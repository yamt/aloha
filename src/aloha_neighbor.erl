% Copyright (c)2013 YAMAMOTO Takashi,
% All rights reserved.
%
% Redistribution and use in source and binary forms, with or without
% modification, are permitted provided that the following conditions
% are met:
% 1. Redistributions of source code must retain the above copyright
%    notice, this list of conditions and the following disclaimer.
% 2. Redistributions in binary form must reproduce the above copyright
%    notice, this list of conditions and the following disclaimer in the
%    documentation and/or other materials provided with the distribution.
%
% THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
% ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
% IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
% ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
% FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
% DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
% OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
% HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
% OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
% SUCH DAMAGE.

-module(aloha_neighbor).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).
-export([start_link/0]).
-export([send_packet/3]).
-export([notify/2]).

-include_lib("aloha_packet/include/aloha_packet.hrl").

-behaviour(gen_server).

-record(state, {addrs = dict:new(), used = dict:new(), q = [], timer}).

-define(CACHE_EXPIRE, 10000).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init(_Opts) ->
    false = process_flag(trap_exit, true),
    ets:new(?MODULE, [set, named_table]),
    Tref = erlang:start_timer(?CACHE_EXPIRE, self(), cache_expire),
    {ok, #state{timer = Tref}}.

handle_call(_Req, _From, State) ->
    {noreply, State}.

handle_cast({resolve, Req},
            #state{addrs = Addrs, used = Used, q = Q} = State) ->
    {Q2, Used2} = process_requests(Addrs, [Req], Used),
    lists:foreach(fun({Pkt, _NS, Backend}) ->
        lager:info("sending discovery packet"),
        send_discover(Pkt, Backend)
    end, Q2),
    State2 = State#state{q = Q ++ Q2, used = Used2},
    {noreply, State2};
handle_cast({resolved, Key, Value},
            #state{addrs = Addrs, used = Used, q = Q} = State) ->
    Addrs2 = dict:store(Key, Value, Addrs),
    {Q2, Used2} = process_requests(Addrs2, Q, Used),
    State2 = State#state{addrs = Addrs2, used = Used2, q = Q2},
    {noreply, State2}.

handle_info({timeout, Tref, cache_expire},
            #state{timer = Tref, addrs = Addrs, used = Used} = State) ->
    lager:info("neighbor cache expire ~p -> ~p",
               [dict:size(Addrs), dict:size(Used)]),
    ets:delete_all_objects(?MODULE),
    Tref2 = erlang:start_timer(?CACHE_EXPIRE, self(), cache_expire),
    State2 = State#state{addrs = Used, used = dict:new(), timer = Tref2},
    {noreply, State2};
handle_info(Info, State) ->
    lager:info("handle_info: ~p", [Info]),
    {noreply, State}.

terminate(Reason, _State) ->
    lager:info("aloha_neighbor terminate for ~p", [Reason]),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

process_requests(Dict, Q, Used) ->
    {Q2, Used2} = lists:foldl(fun(Req, {Acc, Used2}) ->
        send_or_acc(fun(Key, Used3) ->
            Used3 = Used2,
            case dict:find(Key, Dict) of
                error ->
                    {error, Used3};
                {ok, Value} = Ret ->
                    lager:info("neigh sending a pending packet for ~p", [Key]),
                    {Ret, dict:store(Key, Value, Used3)}
            end
        end, Used2, Req, Acc)
    end, {[], dict:new()}, Q),
    lager:info("neigh resolved ~p -> ~p", [length(Q), length(Q2)]),
    % we have finished sending pending packets for this key.
    % now update the ets table for fast-path.
    % this way the chance of packet reordering should be small enough.
    true = dict:fold(fun(Key, Value, true) ->
        ets:insert(?MODULE, {Key, Value})
    end, true, Used2),
    {Q2, dict:merge(fun(_Key, _Value1, Value2) -> Value2 end, Used, Used2)}.

send_packet(Pkt, NS, Backend) ->
    {List, ?MODULE} =
        send_or_acc(fun lookup_cache/2, ?MODULE, {Pkt, NS, Backend}, []),
    lists:foreach(fun(X) ->
        gen_server:cast(?MODULE, {resolve, X}) end,
    List).

lookup_cache(Key, Dict) ->
    case catch ets:lookup_element(Dict, Key, 2) of
        {'EXIT', _} ->
            {error, Dict};  % compat with dict:find/2
        LLAddr ->
            {{ok, LLAddr}, Dict}
    end.

send_or_acc(LookupFun, LookupArg,
            {[#ether{}, L2|_] = Pkt, NS, Backend} = Req,
            %{[#ether{dst = <<0,0,0,0,0,0>>}, L2|_] = Pkt, NS, Backend} = Req,
            Acc) ->
    Key = key(L2, NS),
    {Result, LookupArg2} = LookupFun(Key, LookupArg),
    {case Result of
        error ->
            lager:debug("neighbor not found for key ~p", [Key]),
            [Req|Acc];
        {ok, LLAddr} ->
            send_packet_to(Pkt, LLAddr, Backend),
            Acc
    end, LookupArg2};
send_or_acc(_LookupFun, LookupArg, {Pkt, _NS, Backend}, Acc) ->
    aloha_nic:send_packet(Pkt, Backend),
    {Acc, LookupArg}.

send_packet_to([Ether|Rest] = Pkt, LLAddr, Backend) ->
    lager:debug("neighbor send to ~p ~p",
               [LLAddr, aloha_utils:pr(Pkt, ?MODULE)]),
    aloha_nic:send_packet([Ether#ether{dst = LLAddr}|Rest], Backend).

notify(Key, Value) ->
    lager:debug("neighbor key ~p value ~p", [Key, Value]),
    gen_server:cast(?MODULE, {resolved, Key, Value}).

discover_module(ip) -> aloha_arp;
discover_module(ipv6) -> aloha_icmpv6.

key(L2, NS) ->
    {Proto, Dst, _Src} = extract_l2(L2),
    {NS, Proto, Dst}.

extract_l2(#ip{dst = Dst, src = Src}) -> {ip, Dst, Src};
extract_l2(#ipv6{dst = Dst, src = Src}) -> {ipv6, Dst, Src}.

send_discover([#ether{src = L1Src}, L2|_], Backend) ->
    {Protocol, Dst, Src} = extract_l2(L2),
    Mod = discover_module(Protocol),
    Pkt = Mod:discovery_packet(Dst, Src, L1Src),
    lager:debug("discovery pkt ~p", [aloha_utils:pr(Pkt, ?MODULE)]),
    aloha_nic:send_packet(Pkt, Backend).
