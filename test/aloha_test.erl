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

-module(aloha_test).

-include_lib("eunit/include/eunit.hrl").

tcp_self_connect_test_common(Proto, IPAddr) ->
    {ok, Pid} = aloha_neighbor:start_link(),
    aloha_tcp:init_tables(),
    HwAddr = <<16#0003478ca1b3:48>>,  % taken from my unused machine
    {ok, Nic} = aloha_nic_loopback:create(?MODULE, HwAddr),
    ok = gen_server:call(Nic, {setopts, [{Proto, IPAddr}]}),
    {ok, Opts} = gen_server:call(Nic, getopts),
    Addr = proplists:get_value(addr, Opts),
    Mtu = proplists:get_value(mtu, Opts),
    Backend = proplists:get_value(backend, Opts),
    Msg = iolist_to_binary(lists:map(fun(_) -> <<"hello!">> end,
                           lists:seq(1, 3000))),
    MsgSize = byte_size(Msg),
    {ok, Sock} = aloha_tcp:connect(?MODULE, IPAddr, 7777, Addr,
                                   Backend,
                                   [{ip, IPAddr}, {port, 7777}, {mtu, Mtu},
                                    {rcv_buf, MsgSize}]),
    aloha_socket:send(Sock, Msg),
    aloha_socket:shutdown(Sock, write),
    {ok, Msg} = aloha_socket:recv(Sock, MsgSize),
    aloha_socket:close(Sock),
    lager:info("cleaning up ..."),
    % don't bother to wait for 2MSL
    {aloha_socket, SockPid} = Sock,
    exit(SockPid, kill),
    unlink(Pid),
    exit(Pid, kill),
    exit(Nic, kill),
    lists:foreach(fun(P) ->
        monitor(process, P),
        receive
            {'DOWN', _, process, P, _} -> ok
        end
    end, [Pid, Nic, SockPid]),
    aloha_tcp:fini_tables().

tcp_ipv4_self_connect_test() ->
    tcp_self_connect_test_common(ip, <<127,0,0,1>>).

tcp_ipv6_self_connect_test() ->
    tcp_self_connect_test_common(ipv6, <<0:128>>).
