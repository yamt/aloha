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

self_connect_test() ->
    {ok, Pid} = aloha_neighbor:start_link(),
    aloha_tcp:init_tables(),
    HwAddr = <<16#0003478ca1b3:48>>,  % taken from my unused machine
    IPAddr = <<127,0,0,1>>,
    {ok, Nic} = aloha_nic_loopback:create(?MODULE, HwAddr),
    ok = gen_server:call(Nic, {setopts, [{ip, IPAddr}]}),
    {ok, Opts} = gen_server:call(Nic, getopts),
    Addr = proplists:get_value(addr, Opts),
    Mtu = proplists:get_value(mtu, Opts),
    Ip = proplists:get_value(ip, Opts),
    Backend = proplists:get_value(backend, Opts),
    {ok, Sock} = aloha_tcp:connect(?MODULE, IPAddr, 7777, Addr,
                                   Backend,
                                   [{ip, Ip}, {port, 7777}, {mtu, Mtu}]),
    Msg = <<"hello!">>,
    aloha_socket:send(Sock, Msg),
    {ok, Msg} = aloha_socket:recv(Sock, 0),
    aloha_socket:close(Sock),
    lager:info("cleaning up ..."),
    % don't bother to wait for 2MSL
    {aloha_socket, SockPid} = Sock,
    exit(SockPid, kill),
    unlink(Pid),
    exit(Pid, kill).
