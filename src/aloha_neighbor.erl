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

-record(state, {addrs = dict:new(), used = dict:new(),
                q = dict:new(), oldq = dict:new(), timer}).

-define(CACHE_EXPIRE, 2000).

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
            #state{addrs = Addrs, used = Used, q = Q, oldq = OldQ} = State) ->
    Key = req_key(Req),
    {L, Used2} = process_requests(Key, [Req], Addrs, Used),
    Q2 = case {L, dict:find(Key, Q), dict:find(Key, OldQ)} of
        {[{Pkt, _NS, Backend}], error, error} ->
            lager:info("sending discovery packet for ~p", [Key]),
            send_discover(Pkt, Backend),
            dict:append_list(Key, L, Q);
        _ ->
            Q
    end,
    State2 = State#state{q = Q2, used = Used2},
    {noreply, State2};
handle_cast({resolved, Key, Value},
            #state{addrs = Addrs, used = Used, q = Q, oldq = OldQ} = State) ->
    Addrs2 = dict:store(Key, Value, Addrs),
    {[], Used2} = process_requests(Key, fetch_list(Key, Q), Addrs2, Used),
    {[], Used3} = process_requests(Key, fetch_list(Key, OldQ), Addrs2, Used2),
    State2 = State#state{addrs = Addrs2, used = Used3,
                         q = dict:erase(Key, Q), oldq = dict:erase(Key, OldQ)},
    {noreply, State2}.

handle_info({timeout, Tref, cache_expire},
            #state{timer = Tref, addrs = Addrs, used = Used,
                   q = Q, oldq = OldQ} = State) ->
    lager:info("neighbor cache expire ~p -> ~p",
               [dict:size(Addrs), dict:size(Used)]),
    lager:info("neighbor discovery timeout for ~p", [dict:to_list(OldQ)]),
    ets:delete_all_objects(?MODULE),
    Tref2 = erlang:start_timer(?CACHE_EXPIRE, self(), cache_expire),
    State2 = State#state{addrs = Used, used = dict:new(),
                         q = dict:new(), oldq = Q, timer = Tref2},
    {noreply, State2};
handle_info(Info, State) ->
    lager:info("handle_info: ~p", [Info]),
    {noreply, State}.

terminate(Reason, _State) ->
    lager:info("aloha_neighbor terminate for ~p", [Reason]),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

fetch_list(Key, Dict) ->
    case dict:find(Key, Dict) of
        error -> [];
        {ok, List} -> List
    end.

process_requests(Key, List, Db, Used) ->
    case dict:find(Key, Db) of
        error ->
            {List, Used};
        {ok, LLAddr} ->
            lists:foreach(fun(Req) ->
                send_packet_to(Req, LLAddr)
            end, List),
            % we have finished sending pending packets for this key.
            % now update the ets table for fast-path.
            % this way the chance of packet reordering should be small enough.
            ets:insert(?MODULE, {Key, LLAddr}),
            {[], dict:store(Key, LLAddr, Used)}
    end.

send_packet(Pkt, NS, Backend) ->
    Req = {Pkt, NS, Backend},
    Key = req_key(Req),
    case catch ets:lookup_element(?MODULE, Key, 2) of
        {'EXIT', _} ->
            lager:debug("neighbor not found for key ~p", [Key]),
            gen_server:cast(?MODULE, {resolve, Req});
        LLAddr ->
            send_packet_to(Req, LLAddr)
    end.

send_packet_to({[Ether|Rest] = Pkt, _NS, Backend}, LLAddr) ->
    lager:debug("neighbor send to ~p ~p",
                [LLAddr, aloha_utils:pr(Pkt, ?MODULE)]),
    aloha_nic:send_packet([Ether#ether{dst = LLAddr}|Rest], Backend).

req_key({[#ether{}, L2|_], NS, _Backend}) ->
    key(L2, NS).

key(L2, NS) ->
    {Proto, Dst, _Src} = extract_l2(L2),
    {NS, Proto, Dst}.

extract_l2(#ip{dst = Dst, src = Src}) -> {ip, Dst, Src};
extract_l2(#ipv6{dst = Dst, src = Src}) -> {ipv6, Dst, Src}.

notify(Key, Value) ->
    lager:debug("neighbor key ~p value ~p", [Key, Value]),
    gen_server:cast(?MODULE, {resolved, Key, Value}).

discover_module(ip) -> aloha_arp;
discover_module(ipv6) -> aloha_icmpv6.

send_discover([#ether{src = L1Src}, L2|_], Backend) ->
    {Protocol, Dst, Src} = extract_l2(L2),
    Mod = discover_module(Protocol),
    Pkt = Mod:discovery_packet(Dst, Src, L1Src),
    lager:debug("discovery pkt ~p", [aloha_utils:pr(Pkt, ?MODULE)]),
    aloha_nic:send_packet(Pkt, Backend).
