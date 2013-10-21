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

-module(aloha_tcp_listener).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).

-export([start_link/2]).

-include_lib("aloha_packet/include/aloha_packet.hrl").

-behaviour(gen_server).

-record(listen_state, {accept_q = [], waiters = [], key, opts}).

start_link(Key, Opts) ->
    gen_server:start_link(?MODULE, {Key, Opts}, []).

init({Key, Opts}) ->
    false = process_flag(trap_exit, true),
    true = ets:insert_new(?MODULE, {Key, self()}),
    DefOpts = [{active, true}],
    Opts2 = lists:keydelete(reuseaddr, 1, Opts),
    Opts3 = lists:keydelete(port, 1, Opts2),
    Opts4 = aloha_utils:merge_opts(Opts3, DefOpts),
    State = #listen_state{key = Key, opts = Opts4},
    {ok, State}.

handle_call(sockname, _From,
            #listen_state{key = {_NS, {Addr, Port}}} = State) ->
    {reply, {ok, {aloha_addr:to_ip(Addr), Port}}, State};
handle_call(sockname, _From, #listen_state{key = {_NS, Port}} = State) ->
    {reply, {ok, {{0, 0, 0, 0}, Port}}, State};
handle_call({setopts, NewOpts}, _From, #listen_state{opts = Opts} = State) ->
    State2 = State#listen_state{opts = aloha_utils:merge_opts(NewOpts, Opts)},
    {ok, State2};
handle_call({getopts, OptKeys}, _From, #listen_state{opts = Opts} = State) ->
    {reply, {ok, aloha_utils:acc_opts(OptKeys, Opts, [])}, State};
handle_call(accept, From, State) ->
    lager:debug("user accept ~p", [From]),
    State2 = add_waiter(From, State),
    {noreply, State2}.

handle_cast(M, State) ->
    lager:info("unknown msg ~p", [M]),
    {noreply, State}.

handle_info({aloha_tcp_connected, {aloha_socket, Sock}}, State) ->
    lager:info("ready to accept ~p", [Sock]),
    State2 = add_socket(Sock, State),
    {noreply, process_accept(State2)};
handle_info({tcp_error, Sock, econnreset}, State) ->
    aloha_socket:close(Sock),
    {noreply, State};
handle_info(Info, State) ->
    lager:info("handle_info: ~p", [Info]),
    {noreply, State}.

terminate(_Reason, #listen_state{key = Key}) ->
    true = ets:delete(?MODULE, Key),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

add_waiter(From, #listen_state{waiters = Waiters} = State) ->
    State2 = State#listen_state{waiters = Waiters ++ [From]},
    process_accept(State2).

add_socket(Sock, #listen_state{accept_q = Q} = State) ->
    State2 = State#listen_state{accept_q = Q ++ [Sock]},
    process_accept(State2).

process_accept(#listen_state{accept_q = []} = State) ->
    State;
process_accept(#listen_state{waiters = []} = State) ->
    State;
process_accept(#listen_state{accept_q = [SockPid|Q],
                             waiters = [{Pid, _} = From|Waiters],
                             opts = Opts} = State) ->
    lager:info("user accepted ~p ~p ~p", [From, SockPid, Opts]),
    Sock = {aloha_socket, SockPid},
    ok = aloha_socket:controlling_process(Sock, Pid),
    ok = aloha_socket:setopts(Sock, Opts),  % XXX handle error
    gen_server:reply(From, {ok, Sock}),
    State#listen_state{accept_q = Q, waiters = Waiters}.
