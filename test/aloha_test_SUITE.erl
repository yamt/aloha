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

-export([tcp_self_connect/1]).
-export([tcp_echo/1]).
-export([tcp_bulk_transfer/1]).
-export([tcp_unlisten/1]).
-export([tcp_recv_timeout/1]).
-export([tcp_close/1]).

% server ports
-define(ECHO_PORT, 7).
-define(DISCARD_PORT, 9).
-define(UNLISTEN_PORT, 4000).
-define(CLOSE_PORT, 5000).

% client ports
-define(LOCAL_PORT, 8888).
-define(SELF_PORT, 7777).

-define(NREPEAT, 16).

suite() ->
    [{timetrap, timetrap()}].

timetrap() ->
    case os:getenv("TRAVIS") of
        false -> 5000;
        _ -> 1800000
    end.

all() ->
    [{group, loopback}].

groups() ->
    Tests = [
        tcp_self_connect,
        tcp_echo,
        tcp_bulk_transfer,
        tcp_unlisten,
        tcp_recv_timeout,
        tcp_close
    ],
    Protocols = [
        {group, ipv4},
        {group, ipv6}
    ],
    [{loopback, [], [
        {group, async},
        {group, sync}
     ]},
     {async, [parallel], Protocols},
     {sync,  [parallel], Protocols},
     {ipv4, [parallel, {repeat_until_any_fail, ?NREPEAT}], Tests},
     {ipv6, [parallel, {repeat_until_any_fail, ?NREPEAT}], Tests}].

init_per_suite(Config) ->
    lager:start(),
    lager:set_loglevel(lager_file_backend, "console.log", warning),
    application:start(sasl),
    ok = aloha:start(),
    Config.

end_per_suite(Config) ->
    ok = application:stop(aloha),
    ok.

init_per_group(loopback, Config) ->
    HwAddr = <<16#0003478ca1b3:48>>,  % taken from my unused machine
    {ok, Pid} = aloha_nic_loopback:create(?MODULE, HwAddr),
    ok = gen_server:call(Pid, {setopts, [{ip, <<127,0,0,1>>},
                                         {ipv6, <<1:128>>}]}),
    [{loopback, Pid}|Config];
init_per_group(async, Config) ->
    Config2 = [{mode, async}|Config],
    Servers = start_servers(Config2),
    [{servers, Servers}|Config2];
init_per_group(sync, Config) ->
    Config2 = [{mode, sync}|Config],
    Servers = start_servers(Config2),
    [{servers, Servers}|Config2];
init_per_group(ipv4, Config) ->
    [{proto, ipv4}, {ip, <<127,0,0,1>>}|Config];
init_per_group(ipv6, Config) ->
    [{proto, ipv6}, {ip, <<1:128>>}|Config].

start_servers(Config) ->
    lists:map(fun({Port, Fun}) ->
        proc_lib:spawn(fun() -> tcp_server(?MODULE, Port, Fun, Config) end)
    end, [
        {?ECHO_PORT, fun echo_loop/2},
        {?DISCARD_PORT, fun discard_loop/2},
        {?CLOSE_PORT, fun closer/2}
    ]).

end_per_group(loopback, Config) ->
    Pid = ?config(loopback, Config),
    kill_and_wait([Pid]);
end_per_group(async, Config) ->
    Servers = ?config(servers, Config),
    kill_and_wait(Servers);
end_per_group(sync, Config) ->
    Servers = ?config(servers, Config),
    kill_and_wait(Servers);
end_per_group(ipv4, _Config) ->
    ok;
end_per_group(ipv6, _Config) ->
    ok.

tcp_self_connect(Config) ->
    IP = ?config(ip, Config),
    tcp_send_and_recv(IP, ?SELF_PORT, IP, ?SELF_PORT, Config).

tcp_echo(Config) ->
    IP = ?config(ip, Config),
    tcp_send_and_recv(IP, ?ECHO_PORT, IP, ?LOCAL_PORT, Config).

tcp_bulk_transfer(Config) ->
    IP = ?config(ip, Config),
    tcp_send(IP, ?DISCARD_PORT, IP, ?LOCAL_PORT, Config).

tcp_unlisten(Config) ->
    IP = ?config(ip, Config),
    try
        tcp_send_and_recv(IP, ?UNLISTEN_PORT, IP, ?LOCAL_PORT, Config)
    catch
        error:{badmatch, {error, econnrefused}} = E ->
            ct:pal("expected exception ~p", [E]),
            ok
    end.

tcp_recv_timeout(Config) ->
    IP = ?config(ip, Config),
    Msg = <<"hi!">>,
    MsgSize = byte_size(Msg),
    Sock = tcp_prepare(IP, ?ECHO_PORT, IP, ?LOCAL_PORT + 1, 3000, Config),
    ok = aloha_socket:send(Sock, Msg),
    Timeout = 200,
    {ok, Msg} = case recv(Sock, MsgSize * 2, Timeout, Config) of
        {ok, Msg} = Ret -> Ret;
        {error, timeout} ->
            ct:pal("trying longer timeout"),
            recv(Sock, MsgSize * 2, Timeout * 5, Config)
    end,
    {error, timeout} = recv(Sock, MsgSize * 2, Timeout, Config),
    ok = aloha_socket:shutdown(Sock, write),
    {error, closed} = recv(Sock, MsgSize, Timeout, Config),
    ok = aloha_socket:close(Sock),
    tcp_cleanup(Sock).

tcp_close(Config) ->
    IP = ?config(ip, Config),
    try
        tcp_send_and_recv(IP, ?CLOSE_PORT, IP, ?LOCAL_PORT, Config)
    catch
        error:{badmatch, {error, econnreset}} = E ->
            Trace = erlang:get_stacktrace(),
            false = lists:keyfind(tcp_prepare, 2, Trace),
            ct:pal("expected exception ~p", [E]),
            ok;
        error:{badmatch, {error, econnrefused}} = E ->
            Trace = erlang:get_stacktrace(),
            case lists:keyfind(tcp_prepare, 2, Trace) of
                {?MODULE, tcp_prepare, 6, _} -> ok;  % R15 and later
                {?MODULE, tcp_prepare, 6} -> ok  % R14
            end,
            ct:pal("expected exception ~p", [E]),
            ok
    end.

make_data() ->
    iolist_to_binary(lists:map(fun(_) -> <<"hello!">> end,
                     lists:seq(1, 3000))).

tcp_prepare(RemoteIPAddr, RemotePort, LocalIPAddr, LocalPort, MsgSize,
            Config) ->
    Nic = ?config(loopback, Config),
    ActiveOpts = active_opts(Config),
    {ok, Opts} = gen_server:call(Nic, getopts),
    Addr = proplists:get_value(addr, Opts),
    Mtu = proplists:get_value(mtu, Opts),
    Backend = proplists:get_value(backend, Opts),
    ct:pal("connecting"),
    {ok, Sock} = aloha_tcp:connect(?MODULE, RemoteIPAddr, RemotePort, Addr,
                                   Backend,
                                   [{ip, LocalIPAddr}, {port, LocalPort},
                                    {mtu, Mtu}, {rcv_buf, MsgSize}|ActiveOpts]),
    PeerName = {aloha_addr:to_ip(RemoteIPAddr), RemotePort},
    {ok, PeerName} = aloha_socket:peername(Sock),
    SockName = {aloha_addr:to_ip(LocalIPAddr), LocalPort},
    {ok, SockName} = aloha_socket:sockname(Sock),
    ct:pal("peername ~p sockname ~p", [PeerName, SockName]),
    Sock.

tcp_cleanup(Sock) ->
    ct:pal("cleaning up ..."),
    % don't bother to wait for 2MSL
    case aloha_socket:force_close(Sock) of
        ok -> ok;
        {error, closed} -> ok
    end,
    {aloha_socket, SockPid} = Sock,
    wait(SockPid).

recv(Sock, MsgSize, Config) ->
    recv(Sock, MsgSize, infinity, Config).

recv(Sock, MsgSize, Timeout, Config) ->
    case ?config(mode, Config) of
        async -> async_recv(Sock, MsgSize, Timeout);
        sync -> aloha_socket:recv(Sock, MsgSize, Timeout)
    end.

async_recv(Sock, MsgSize, Timeout) ->
    %aloha_socket:setopts(Sock, [{active, true}]),
    ct:pal("async_recv on ~p for ~p bytes", [Sock, MsgSize]),
    async_recv(Sock, MsgSize, Timeout, true, <<>>).

async_recv(_Sock, Left, _Timeout, false, Acc) when Left =< 0 ->
    {ok, Acc};
async_recv(Sock, MsgSize, Timeout, _, Acc) ->
    receive
        {tcp, Sock, Data} ->
            Left = MsgSize - byte_size(Data),
            ct:pal("~p bytes received (~p bytes left)",
                   [byte_size(Data), Left]),
            % XXX reduce Timeout
            async_recv(Sock, Left, Timeout, false, <<Acc/bytes, Data/bytes>>);
        {tcp_closed, Sock} ->
            case Acc of
                <<>> -> {error, closed};
                _ -> {ok, Acc}
            end;
        Other ->
            ct:pal("got a unexpected msg ~p", [Other]),
            {error, {unknown_msg, Other}}
        after Timeout ->
            case Acc of
                <<>> -> {error, timeout};
                _ -> {ok, Acc}
            end
    end.

tcp_send_and_recv(RemoteIPAddr, RemotePort, LocalIPAddr, LocalPort, Config) ->
    Msg = make_data(),
    MsgSize = byte_size(Msg),
    Sock = tcp_prepare(RemoteIPAddr, RemotePort, LocalIPAddr, LocalPort,
                       MsgSize, Config),
    MsgSize = byte_size(Msg),
    ct:pal("send"),
    ok = aloha_socket:send(Sock, Msg),
    ct:pal("shutdown"),
    ok = aloha_socket:shutdown(Sock, write),
    ct:pal("recv"),
    {ok, Msg} = recv(Sock, MsgSize, Config),
    ct:pal("recv fin"),
    {error, closed} = recv(Sock, MsgSize, Config),
    ct:pal("close"),
    ok = aloha_socket:close(Sock),
    tcp_cleanup(Sock).

tcp_send(RemoteIPAddr, RemotePort, LocalIPAddr, LocalPort, Config) ->
    Msg = make_data(),
    MsgSize = byte_size(Msg),
    Sock = tcp_prepare(RemoteIPAddr, RemotePort, LocalIPAddr, LocalPort,
                       MsgSize, Config),
    MsgSize = byte_size(Msg),
    ct:pal("send"),
    ok = aloha_socket:send(Sock, Msg),
    ct:pal("shutdown"),
    ok = aloha_socket:shutdown(Sock, write),
    ct:pal("recv fin"),
    {error, closed} = recv(Sock, MsgSize, Config),
    ct:pal("close"),
    ok = aloha_socket:close(Sock),
    tcp_cleanup(Sock).

kill_and_wait(Pid) when is_pid(Pid) ->
    kill_and_wait([Pid]);
kill_and_wait(List) ->
    lists:foreach(fun(Pid) ->
        % XXX this leaves an entry in ets
        exit(Pid, kill)
    end, List),
    wait(List).

wait(Pid) when is_pid(Pid) ->
    wait([Pid]);
wait(List) ->
    lists:foreach(fun(Pid) ->
        monitor(process, Pid)
    end, List),
    lists:foreach(fun(Pid) ->
        receive
            {'DOWN', _, process, Pid, _} -> ok
        end
    end, List).

active_opts(Config) ->
    case ?config(mode, Config) of
        async -> [];
        sync -> [{active, false}]
    end.

tcp_server(NS, Port, Fun, Config) ->
    ActiveOpts = active_opts(Config),
    {ok, Sock} = aloha_socket:listen({NS, Port},
                                     [binary, {packet, raw}, {reuseaddr, true},
                                      {nodelay, true}|ActiveOpts]),
    accept_loop(Sock, Fun, Config).

accept_loop(LSock, Fun, Config) ->
    {ok, Sock} = aloha_socket:accept(LSock),
    Pid = proc_lib:spawn_link(fun() -> Fun(Sock, Config) end),
    ok = aloha_socket:controlling_process(Sock, Pid),
    accept_loop(LSock, Fun, Config).

echo_loop(Sock, Config) ->
    case recv(Sock, 0, Config) of
        {ok, Data} ->
            ok = aloha_socket:send(Sock, Data),
            echo_loop(Sock, Config);
        {error, closed} ->
            ok = aloha_socket:close(Sock);
        {error, Reason} ->
            ct:pal("echo_loop got error ~p", [Reason]),
            ok = aloha_socket:close(Sock)
    end.

discard_loop(Sock, Config) ->
    case recv(Sock, 0, Config) of
        {ok, _Data} ->
            discard_loop(Sock, Config);
        {error, closed} ->
            ok = aloha_socket:close(Sock);
        {error, Reason} ->
            ct:pal("discard_loop got error ~p", [Reason]),
            ok = aloha_socket:close(Sock)
    end.

closer(Sock, _Config) ->
    aloha_socket:close(Sock).
