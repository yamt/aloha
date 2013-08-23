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

-module(aloha_nic).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).
-export([send_packet/1, send_packet/2, enqueue/1]).

-include_lib("aloha_packet/include/aloha_packet.hrl").

-behaviour(gen_server).

-record(state, {opts}).

init(Opts) ->
    Key = proplists:get_value(key, Opts),
    true = ets:insert_new(?MODULE, {Key, self()}),
    {ok, #state{opts=Opts}}.

handle_call(_Req, _From, State) ->
    {noreply, State}.

handle_cast({packet, Pkt}, State) ->
    aloha_ether:handle(Pkt, [], State#state.opts),
    {noreply, State};
handle_cast({Type, Pkt, Stack}, State) ->
    Mod = ethertype_mod(Type),
    Mod:handle(Pkt, Stack, State#state.opts),
    {noreply, State};
handle_cast({send_packet, BinPkt}, #state{opts = Opts} = State) ->
    Backend = proplists:get_value(backend, Opts),
    send_packet(BinPkt, Backend),
    {noreply, State};
handle_cast({setopts, Opts}, #state{opts = L}=State) ->
    L2 = aloha_utils:merge_opts(L, Opts),
    {noreply, State#state{opts=L2}};
handle_cast(M, State) ->
    lager:info("unknown msg ~w~n", [M]),
    {noreply, State}.

handle_info(Info, State) ->
    lager:info("handle_info: ~w~n", [Info]),
    {noreply, State}.

terminate(_Reason, #state{opts = Opts}) ->
    Key = proplists:get_value(key, Opts),
    true = ets:delete(?MODULE, Key),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

ethertype_mod(arp) -> aloha_arp;
ethertype_mod(ip) -> aloha_ip;
ethertype_mod(ipv6) -> aloha_ipv6;
ethertype_mod(icmp) -> aloha_icmp;
ethertype_mod(icmpv6) -> aloha_icmpv6;
ethertype_mod(tcp) -> aloha_tcp.

enqueue(Msg) ->
    gen_server:cast(self(), Msg).

send_packet(BinPkt) ->
    gen_server:cast(self(), {send_packet, BinPkt}).

send_packet(BinPkt, Backend) ->
    {M, F, A} = Backend,
    apply(M, F, [BinPkt|A]).
