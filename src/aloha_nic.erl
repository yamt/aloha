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
-export([send_packet/1, enqueue_cond/2]).

-include_lib("aloha_packet/include/aloha_packet.hrl").

-behaviour(gen_server).

-record(state, {addr, prop, backend}).

init(Opts) ->
    Addr = proplists:get_value(addr, Opts),
    Backend = proplists:get_value(backend, Opts),
    {ok, #state{addr=Addr, prop=Opts, backend=Backend}}.

handle_call(_Req, _From, State) ->
    {noreply, State}.

enqueue_cond(_Msg, false) ->
    ok;
enqueue_cond(Msg, true) ->
    gen_server:cast(self(), Msg).

handle_cast({packet, Pkt}, #state{addr=Addr}=State) ->
    lager:debug("nic receive packet ~w~n", [Pkt]),
    {Ether, Next, Rest} = aloha_packet:decode(ether, Pkt),
    lager:debug("nic receive packet ~w ~w ~w~n", [Ether, Next, Rest]),
    Dst = Ether#ether.dst,
    BroadcastAddr = <<-1:(6*8)>>,
    Ours = case Dst of
        Addr -> true;
        BroadcastAddr -> true;
        _ ->
            lager:info("not ours ~w~n", [Dst]),
            false
    end,
    enqueue_cond({Next, Rest, [Ether]}, Ours),
    {noreply, State};
handle_cast({Type, Pkt, Stack}, State) ->
    Mod = ethertype_mod(Type),
    %lager:info("mod ~w pkt ~w opts ~w~n", [Mod, Pkt, State#state.prop]),
    Mod:handle(Pkt, Stack, [{backend, State#state.backend} | State#state.prop]),
    {noreply, State};
handle_cast({send_packet, BinPkt}, #state{backend=Backend} = State) ->
    {Dp, Port} = Backend,
    aloha_datapath:packet_out(Dp, Port, BinPkt),
    {noreply, State};
handle_cast({set_backend, Backend}, State) ->
    {noreply, State#state{backend=Backend}};
handle_cast({set_prop, Prop}, #state{prop=L}=State) ->
    L2 = [Prop|L],
    {noreply, State#state{prop=L2}};
handle_cast(M, State) ->
    lager:info("unknown msg ~w~n", [M]),
    {noreply, State}.

handle_info(Info, State) ->
    lager:info("handle_info: ~w~n", [Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

ethertype_mod(arp) -> aloha_arp;
ethertype_mod(ip) -> aloha_ip;
ethertype_mod(icmp) -> aloha_icmp;
ethertype_mod(tcp) -> aloha_tcp.

send_packet(BinPkt) ->
    gen_server:cast(self(), {send_packet, BinPkt}).
