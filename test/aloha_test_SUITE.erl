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

-module(aloha_test_SUITE).

-compile([{parse_transform, lager_transform}]).

-include_lib("common_test/include/ct.hrl").

-export([suite/0, all/0, init_per_suite/1, end_per_suite/1]).
-export([groups/0, init_per_group/2, end_per_group/2]).

-export([tcp_ipv4_self_connect_test/1]).
-export([tcp_ipv6_self_connect_test/1]).
-export([tcp_ipv4_echo_test/1]).
-export([tcp_ipv6_echo_test/1]).

-define(ECHO_PORT, 7).
-define(LOCAL_PORT, 8888).
-define(SELF_PORT, 7777).

suite() ->
    [{timetrap, 5000}].

all() ->
    [{group, loopback}].

groups() ->
    [{loopback, [parallel], [
        tcp_ipv4_self_connect_test,
        tcp_ipv6_self_connect_test,
        tcp_ipv4_echo_test,
        tcp_ipv6_echo_test
    ]}].

init_per_suite(Config) ->
    %lager:start(),
    %application:start(sasl),
    Owner = proc_lib:spawn(fun() ->
        aloha_tcp:init_tables(),
        receive
            _M -> ok
        end
    end),
    {ok, Pid} = aloha_neighbor:start_link(),
    unlink(Pid),
    [{owner, Owner}, {neighbor, Pid}|Config].

end_per_suite(Config) ->
    Owner = ?config(neighbor, Config),
    Pid = ?config(neighbor, Config),
    kill_and_wait([Owner, Pid]),
    aloha_tcp:fini_tables(),
    ok.

init_per_group(loopback, Config) ->
    HwAddr = <<16#0003478ca1b3:48>>,  % taken from my unused machine
    {ok, Pid} = aloha_nic_loopback:create(?MODULE, HwAddr),
    ok = gen_server:call(Pid, {setopts, [{ip, <<127,0,0,1>>},
                                         {ipv6, <<1:128>>}]}),
    Server = proc_lib:spawn(fun() -> echo_server(?MODULE) end),
    [{loopback, Pid}, {server, Server}|Config].

end_per_group(loopback, Config) ->
    Pid = ?config(loopback, Config),
    Server = ?config(server, Config),
    kill_and_wait([Pid, Server]).

tcp_ipv4_self_connect_test(Config) ->
    tcp_send_and_recv(ip, <<127,0,0,1>>, ?SELF_PORT,
                          <<127,0,0,1>>, ?SELF_PORT, Config).

tcp_ipv6_self_connect_test(Config) ->
    tcp_send_and_recv(ipv6, <<1:128>>, ?SELF_PORT,
                            <<1:128>>, ?SELF_PORT, Config).

tcp_ipv4_echo_test(Config) ->
    tcp_send_and_recv(ip, <<127,0,0,1>>, ?ECHO_PORT,
                          <<127,0,0,1>>, ?LOCAL_PORT, Config).

tcp_ipv6_echo_test(Config) ->
    tcp_send_and_recv(ipv6, <<1:128>>, ?ECHO_PORT,
                            <<1:128>>, ?LOCAL_PORT, Config).

make_data() ->
    iolist_to_binary(lists:map(fun(_) -> <<"hello!">> end,
                     lists:seq(1, 3000))).

tcp_send_and_recv(_Proto, RemoteIPAddr, RemotePort, LocalIPAddr, LocalPort,
                  Config) ->
    Nic = ?config(loopback, Config),
    {ok, Opts} = gen_server:call(Nic, getopts),
    Addr = proplists:get_value(addr, Opts),
    Mtu = proplists:get_value(mtu, Opts),
    Backend = proplists:get_value(backend, Opts),
    Msg = make_data(),
    MsgSize = byte_size(Msg),
    {ok, Sock} = aloha_tcp:connect(?MODULE, RemoteIPAddr, RemotePort, Addr,
                                   Backend,
                                   [{ip, LocalIPAddr}, {port, LocalPort},
                                    {mtu, Mtu}, {rcv_buf, MsgSize}]),
    aloha_socket:send(Sock, Msg),
    aloha_socket:shutdown(Sock, write),
    {ok, Msg} = aloha_socket:recv(Sock, MsgSize),
    aloha_socket:close(Sock),
    lager:info("cleaning up ..."),
    % don't bother to wait for 2MSL
    {aloha_socket, SockPid} = Sock,
    kill_and_wait(SockPid).

kill_and_wait(Pid) when is_pid(Pid) ->
    kill_and_wait([Pid]);
kill_and_wait(List) ->
    lists:foreach(fun(Pid) ->
        monitor(process, Pid),
        exit(Pid, kill)
    end, List),
    lists:foreach(fun(Pid) ->
        receive
            {'DOWN', _, process, Pid, _} -> ok
        end
    end, List).

echo_server(NS) ->
    {ok, Sock} = aloha_socket:listen({NS, ?ECHO_PORT},
                                     [binary, {packet, raw}, {reuseaddr, true},
                                      {nodelay, true}, {active, false}]),
    accept_loop(Sock, fun echo_loop/1).

echo_loop(Sock) ->
    case aloha_socket:recv(Sock, 0) of
        {ok, Data} ->
            ok = aloha_socket:send(Sock, Data),
            echo_loop(Sock);
        {error, closed} ->
            ok = aloha_socket:close(Sock)
    end.

accept_loop(LSock, Fun) ->
    {ok, Sock} = aloha_socket:accept(LSock),
    Pid = proc_lib:spawn_link(fun() -> Fun(Sock) end),
    ok = aloha_socket:controlling_process(Sock, Pid),
    accept_loop(LSock, Fun).