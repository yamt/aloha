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
-export([tcp_eaddrinuse/1]).

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
        false -> 20000;
        _ -> 1800000
    end.

all() ->
    [{group, all}].

groups() ->
    Tests = [
        tcp_self_connect,
        tcp_echo,
        tcp_bulk_transfer,
        tcp_unlisten,
        tcp_recv_timeout,
        tcp_close,
        tcp_eaddrinuse
    ],
    Protocols = [
        {group, ip},
        {group, ipv6}
    ],
    SyncModes = [
        {group, async},
        {group, sync}
    ],
    LoopbackModes = [
        {group, loopback},
        {group, lossyloopback}
    ],
    Md5SigModes = [
        {group, md5sig},
        {group, nomd5sig}
    ],
    [{all, [], Md5SigModes},
     {md5sig, [parallel], LoopbackModes},
     {nomd5sig, [parallel], LoopbackModes},
     {loopback, [parallel], SyncModes},
     {lossyloopback, [parallel], SyncModes},
     {async, [parallel], Protocols},
     {sync,  [parallel], Protocols},
     {ip, [parallel, {repeat_until_any_fail, ?NREPEAT}], Tests},
     {ipv6, [parallel, {repeat_until_any_fail, ?NREPEAT}], Tests}].

init_per_suite(Config) ->
    application:load(lager),
    application:set_env(lager, handlers,
        [{lager_console_backend, [
            info, 
            {lager_default_formatter,
             [date, " ", time, " [", severity, "] ", pid, " ", message, "\n"]}
        ]}]),
    lager:start(),
    lager:set_loglevel(lager_file_backend, "console.log", warning),
    application:start(sasl),
    ok = aloha:start(),
    proc_lib:spawn(fun neighbor_flusher/0),
    Config.

end_per_suite(_Config) ->
    ok = application:stop(aloha),
    ok.

init_per_group(all, Config) ->
    Config;
init_per_group(md5sig, Config) ->
    [{md5sig, [md5sig]}|Config];
init_per_group(nomd5sig, Config) ->
    [{md5sig, []}|Config];
init_per_group(loopback, Config) ->
    [{loopback_mod, aloha_nic_loopback}, {namespace, loopback}|Config];
init_per_group(lossyloopback, Config) ->
    [{loopback_mod, aloha_nic_lossyloopback},
     {namespace, lossyloopback}|Config];
init_per_group(async, Config) ->
    NS = ?config(namespace, Config),
    NS2 = {NS, async, make_ref()},
    Mod = ?config(loopback_mod, Config),
    Pid = start_loopback(NS2, Mod),
    Config2 = [{mode, async}, {namespace, NS2}|Config],
    Servers = start_servers(Config2),
    [{servers, Servers}, {loopback, Pid}|Config2];
init_per_group(sync, Config) ->
    NS = ?config(namespace, Config),
    NS2 = {NS, sync, make_ref()},
    Mod = ?config(loopback_mod, Config),
    Pid = start_loopback(NS2, Mod),
    Config2 = [{mode, sync}, {namespace, NS2}|Config],
    Servers = start_servers(Config2),
    [{servers, Servers}, {loopback, Pid}|Config2];
init_per_group(ip, Config) ->
    [{proto, ip}, {ip, <<127,0,0,1>>}|Config];
init_per_group(ipv6, Config) ->
    [{proto, ipv6}, {ip, <<1:128>>}|Config].

start_loopback(NS, Mod) ->
    HwAddr = <<16#0003478ca1b3:48>>,  % taken from my unused machine
    {ok, Pid} = Mod:create(NS, HwAddr),
    ok = gen_server:call(Pid, {setopts, [{ip, <<127,0,0,1>>},
                                         {ipv6, <<1:128>>}]}),
    Pid.

start_servers(Config) ->
    NS = ?config(namespace, Config),
    lists:map(fun({Port, Fun}) ->
        proc_lib:spawn(fun() -> tcp_server(NS, Port, Fun, Config) end)
    end, [
        {?ECHO_PORT, fun echo_loop/2},
        {?DISCARD_PORT, fun discard_loop/2},
        {?CLOSE_PORT, fun closer/2}
    ]).

end_per_group(all, _Config) ->
    ok;
end_per_group(md5sig, _Config) ->
    ok;
end_per_group(nomd5sig, _Config) ->
    ok;
end_per_group(loopback, _Config) ->
    ok;
end_per_group(lossyloopback, _Config) ->
    ok;
end_per_group(async, Config) ->
    Pid = ?config(loopback, Config),
    Servers = ?config(servers, Config),
    kill_and_wait([Pid|Servers]);
end_per_group(sync, Config) ->
    Pid = ?config(loopback, Config),
    Servers = ?config(servers, Config),
    kill_and_wait([Pid|Servers]);
end_per_group(ip, _Config) ->
    ok;
end_per_group(ipv6, _Config) ->
    ok.

tcp_self_connect(Config) ->
    ct:pal("self ~p", [self()]),
    IP = ?config(ip, Config),
    tcp_send_and_recv(IP, ?SELF_PORT, IP, ?SELF_PORT, Config).

tcp_echo(Config) ->
    ct:pal("self ~p", [self()]),
    IP = ?config(ip, Config),
    tcp_send_and_recv(IP, ?ECHO_PORT, IP, auto, Config).

tcp_bulk_transfer(Config) ->
    ct:pal("self ~p", [self()]),
    IP = ?config(ip, Config),
    tcp_send(IP, ?DISCARD_PORT, IP, auto, Config).

tcp_unlisten(Config) ->
    ct:pal("self ~p", [self()]),
    IP = ?config(ip, Config),
    try
        tcp_send_and_recv(IP, ?UNLISTEN_PORT, IP, auto, Config)
    catch
        error:{badmatch, {error, econnrefused}} = E ->
            ct:pal("expected exception ~p", [E]),
            ok
    end.
    % XXX tcp_cleanup

tcp_recv_timeout(Config) ->
    ct:pal("self ~p", [self()]),
    IP = ?config(ip, Config),
    Msg = <<"hi!">>,
    MsgSize = byte_size(Msg),
    {ok, Sock} = tcp_prepare(IP, ?ECHO_PORT, IP, auto, 3000, Config),
    ok = aloha_socket:send(Sock, Msg),
    Timeout = 200,
    Timeout2 = Timeout + case ?config(loopback_mod, Config) of
        aloha_nic_lossyloopback -> 4000;  % chosen to deal with two loss
        _ -> 0
    end,
    ct:pal("wait for short result"),
    {ok, Msg} = case recv(Sock, MsgSize * 2, Timeout2, Config) of
        {ok, _} = Ret -> Ret;
        {error, timeout} ->
            ct:pal("trying longer timeout"),
            recv(Sock, MsgSize * 2, Timeout2 * 5, Config)
    end,
    ct:pal("wait for timeout"),
    {error, timeout} = recv(Sock, MsgSize * 2, Timeout, Config),
    ct:pal("wait for fin"),
    ok = aloha_socket:shutdown(Sock, write),
    {error, closed} = recv(Sock, MsgSize, Timeout2, Config),
    ct:pal("close the socket"),
    ok = aloha_socket:close(Sock),
    tcp_cleanup(Sock).

tcp_close(Config) ->
    ct:pal("self ~p", [self()]),
    IP = ?config(ip, Config),
    try
        tcp_send_and_recv(IP, ?CLOSE_PORT, IP, auto, Config)
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
    % XXX tcp_cleanup

tcp_eaddrinuse(Config) ->
    ct:pal("self ~p", [self()]),
    IP = ?config(ip, Config),
    Port = choose_local_port(Config),
    {ok, Sock} = tcp_prepare(IP, Port, IP, Port, 100, Config),
    {error, eaddrinuse} = tcp_prepare(IP, Port, IP, Port, 100, Config),
    tcp_cleanup(Sock).

make_data() ->
    iolist_to_binary(lists:map(fun(X) -> io_lib:format("~9..0w|", [X]) end,
                     lists:seq(1, 1800))).

tcp_prepare(RemoteIPAddr, RemotePort, LocalIPAddr, LocalPort, MsgSize,
            Config) ->
    NS = ?config(namespace, Config),
    Nic = ?config(loopback, Config),
    ActiveOpts = active_opts(Config),
    Md5SigOpts = md5sig_opts(Config),
    {ok, Opts} = gen_server:call(Nic, getopts),
    Addr = proplists:get_value(addr, Opts),
    Mtu = proplists:get_value(mtu, Opts),
    Backend = proplists:get_value(backend, Opts),
    ct:pal("connecting"),
    LocalPort2 = case LocalPort of
        auto -> choose_local_port(Config);
        Port -> Port
    end,
    Proto = ?config(proto, Config),
    aloha_keydb:register_peer_key(Proto, LocalIPAddr, <<"test_key">>),
    aloha_keydb:register_peer_key(Proto, RemoteIPAddr, <<"test_key">>),
    case aloha_tcp:connect(NS, RemoteIPAddr, RemotePort, Addr, Backend,
                           [{ip, LocalIPAddr}, {port, LocalPort2},
                            {mtu, Mtu}, {rcv_buf, MsgSize}]
                           ++ ActiveOpts ++ Md5SigOpts) of
        {ok, Sock} ->
            PeerName = {aloha_addr:to_ip(RemoteIPAddr), RemotePort},
            {ok, PeerName} = aloha_socket:peername(Sock),
            SockName = {aloha_addr:to_ip(LocalIPAddr), LocalPort2},
            {ok, SockName} = aloha_socket:sockname(Sock),
            ct:pal("sock ~p peername ~p sockname ~p",
                   [Sock, PeerName, SockName]),
            {ok, Sock};
        {error, eaddrinuse} = Error ->
            case LocalPort of
                auto ->
                    % retry
                    tcp_prepare(RemoteIPAddr, RemotePort, LocalIPAddr,
                        LocalPort, MsgSize, Config);
                _ ->
                    Error
            end;
        Error ->
            Error
    end.

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
    %ct:pal("async_recv on ~p for ~p bytes", [Sock, MsgSize]),
    async_recv(Sock, MsgSize, Timeout, true, <<>>).

async_recv(_Sock, Left, _Timeout, false, Acc) when Left =< 0 ->
    {ok, Acc};
async_recv(Sock, MsgSize, Timeout, _, Acc) ->
    receive
        {tcp, Sock, Data} ->
            Left = MsgSize - byte_size(Data),
            %ct:pal("~p bytes received (~p bytes left)",
            %       [byte_size(Data), Left]),
            % XXX reduce Timeout
            async_recv(Sock, Left, Timeout, false, <<Acc/bytes, Data/bytes>>);
        {tcp_closed, Sock} ->
            case Acc of
                <<>> -> {error, closed};
                _ -> {ok, Acc}
            end;
        Other ->
            %ct:pal("got a unexpected msg ~p", [Other]),
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
    {ok, Sock} = tcp_prepare(RemoteIPAddr, RemotePort, LocalIPAddr, LocalPort,
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
    {ok, Sock} = tcp_prepare(RemoteIPAddr, RemotePort, LocalIPAddr, LocalPort,
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

choose_local_port(_Config) ->
    ?LOCAL_PORT + crypto:rand_uniform(0, 10000).

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

md5sig_opts(Config) ->
    ?config(md5sig, Config).

tcp_server(NS, Port, Fun, Config) ->
    ActiveOpts = active_opts(Config),
    Md5SigOpts = md5sig_opts(Config),
    {ok, Sock} = aloha_socket:listen({NS, Port},
                                     [binary, {packet, raw}, {reuseaddr, true},
                                      {nodelay, true}]
                                      ++ ActiveOpts ++ Md5SigOpts),
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
        {error, _Reason} ->
            ok = aloha_socket:close(Sock)
    end.

discard_loop(Sock, Config) ->
    case recv(Sock, 0, Config) of
        {ok, _Data} ->
            discard_loop(Sock, Config);
        {error, closed} ->
            ok = aloha_socket:close(Sock);
        {error, _Reason} ->
            %ct:pal("discard_loop got error ~p", [Reason]),
            ok = aloha_socket:close(Sock)
    end.

closer(Sock, _Config) ->
    aloha_socket:close(Sock).

neighbor_flusher() ->
    aloha_neighbor:clear(),
    timer:sleep(5000),
    neighbor_flusher().
