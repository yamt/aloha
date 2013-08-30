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

suite() ->
    [{timetrap, 5000}].

all() ->
    [{group, loopback}].

groups() ->
    [{loopback, [parallel], [
        tcp_ipv4_self_connect_test,
        tcp_ipv6_self_connect_test
    ]}].

init_per_suite(Config) ->
    lager:start(),
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
    [{loopback, Pid}|Config].

end_per_group(loopback, Config) ->
    Pid = ?config(loopback, Config),
    kill_and_wait(Pid).

tcp_ipv4_self_connect_test(Config) ->
    tcp_self_connect_test_common(ip, <<127,0,0,1>>, 7777, Config).

tcp_ipv6_self_connect_test(Config) ->
    tcp_self_connect_test_common(ipv6, <<1:128>>, 7777, Config).

tcp_self_connect_test_common(Proto, IPAddr, Port, Config) ->
    Nic = ?config(loopback, Config),
    {ok, Opts} = gen_server:call(Nic, getopts),
    Addr = proplists:get_value(addr, Opts),
    Mtu = proplists:get_value(mtu, Opts),
    Backend = proplists:get_value(backend, Opts),
    Msg = iolist_to_binary(lists:map(fun(_) -> <<"hello!">> end,
                           lists:seq(1, 3000))),
    MsgSize = byte_size(Msg),
    {ok, Sock} = aloha_tcp:connect(?MODULE, IPAddr, Port, Addr,
                                   Backend,
                                   [{ip, IPAddr}, {port, Port}, {mtu, Mtu},
                                    {rcv_buf, MsgSize}]),
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
