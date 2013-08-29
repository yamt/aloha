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

-record(state, {q = []}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init(_Opts) ->
    false = process_flag(trap_exit, true),
    ets:new(?MODULE, [set, named_table]),
    {ok, #state{}}.

handle_call(_Req, _From, State) ->
    {noreply, State}.

handle_cast({resolve, Req}, State) ->
    State2 = add_request(Req, State),
    State3 = process_requests(State2),
    {noreply, State3};
handle_cast({resolved, Key, Value}, State) ->
    ets:insert(?MODULE, {Key, Value}),
    State2 = process_requests(State),
    {noreply, State2}.

handle_info(Info, State) ->
    lager:info("handle_info: ~p", [Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

add_request(Req, #state{q = Q} = State) ->
    State#state{q = Q ++ [Req]}.

process_requests(#state{q = Q} = State) ->
    Q2 = lists:foldl(fun send_or_acc/2, [], Q),
    State#state{q = Q2}.

send_packet(Pkt, NS, Backend) ->
    List = send_or_acc({Pkt, NS, Backend}, []),
    lists:foreach(fun(X) ->
        {Pkt, _NS, Backend} = X,
        send_discover(Pkt, Backend),
        gen_server:cast(?MODULE, {resolve, X}) end,
    List).

send_or_acc({[#ether{dst = <<0,0,0,0,0,0>>}, L2|_] = Pkt, NS, Backend} = Req,
            Acc) ->
    Key = key(L2, NS),
    case catch lookup(Key) of
        {'EXIT', _} ->
            [Req|Acc];
        LLAddr ->
            send_packet_to(Pkt, LLAddr, Backend),
            Acc
    end;
send_or_acc({Pkt, _NS, Backend}, Acc) ->
    aloha_nic:send_packet(Pkt, Backend),
    Acc.

lookup(Key) ->
    ets:lookup_element(?MODULE, Key, 2).

send_packet_to([Ether|Rest], LLAddr, Backend) ->
    aloha_nic:send_packet([Ether#ether{dst = LLAddr}|Rest], Backend).

notify(Key, Value) ->
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
    lager:info("discovery pkt ~p", [aloha_utils:pr(Pkt, ?MODULE)]),
    aloha_nic:send_packet(Pkt, Backend).
