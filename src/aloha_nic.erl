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
-export([send_packet/1, send_packet/2, next_protocol/2]).

-include_lib("aloha_packet/include/aloha_packet.hrl").

-behaviour(gen_server).

-record(state, {opts}).

init(Opts) ->
    false = process_flag(trap_exit, true),
    Key = proplists:get_value(key, Opts),
    true = ets:insert_new(?MODULE, {Key, self()}),
    {ok, #state{opts=Opts}}.

handle_call(getopts, _From, #state{opts = Opts} = State) ->
    {reply, {ok, Opts}, State};
handle_call({setopts, Opts}, _From, #state{opts = OldOpts} = State) ->
    NewOpts = aloha_utils:merge_opts(Opts, OldOpts),
    {reply, ok, State#state{opts = NewOpts}};
handle_call(Req, _From, State) ->
    lager:info("unknown call ~p", [Req]),
    {noreply, State}.

handle_cast({packet, Pkt}, State) ->
    aloha_ether:handle(ether, Pkt, [], State#state.opts),
    {noreply, State};
handle_cast({Type, Pkt, Stack}, State) ->
    Mod = ethertype_mod(Type),
    Mod:handle(Type, Pkt, Stack, State#state.opts),
    {noreply, State};
handle_cast({send_packet, Pkt}, #state{opts = Opts} = State) ->
    Backend = proplists:get_value(backend, Opts),
    send_packet(Pkt, Backend),
    {noreply, State};
handle_cast(M, State) ->
    lager:info("unknown msg ~p", [M]),
    {noreply, State}.

handle_info(Info, State) ->
    lager:info("handle_info: ~p", [Info]),
    {noreply, State}.

terminate(Reason, #state{opts = Opts}) ->
    lager:info("terminate with reason ~p", [Reason]),
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
ethertype_mod(tcp) -> aloha_tcp;
ethertype_mod(_) -> aloha_default.

next_protocol(Msg, _Opts) ->
    gen_server:cast(self(), Msg).

send_packet(Pkt) ->
    send_packet(Pkt, self()).

send_packet(Pkt, Pid) when is_pid(Pid) ->
    gen_server:cast(Pid, {send_packet, Pkt});
send_packet(BinPkt, Backend) when is_binary(BinPkt) ->
    {M, F, A} = Backend,
    apply(M, F, [BinPkt|A]);
send_packet(Pkt, Backend) ->
    EncOpts = [{lookup_key, {aloha_keydb, lookup_key, []}}],
    BinPkt = try aloha_packet:encode_packet(Pkt, EncOpts)
    catch
        error:Error ->
            lager:error("failed to encode packet ~p with ~p",
                        [aloha_utils:pr(Pkt, ?MODULE), Error]),
            <<>>
    end,
    send_packet(BinPkt, Backend).
