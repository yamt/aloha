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

-module(aloha_icmp).
-export([handle/3]).

-include_lib("aloha_packet/include/aloha_packet.hrl").

handle(Pkt, Stack, Opts) ->
    {Icmp, _Next, <<>>} = aloha_packet:decode(icmp, Pkt, Stack),
    handle_icmp(Icmp, Stack, Opts).

handle_icmp(#icmp{checksum = bad} = Icmp, _Stack, _Opts) ->
    lager:info("ICMP bad checksum ~p", [Icmp]);
handle_icmp(#icmp{type = echo_request} = Icmp, Stack, Opts) ->
    [Ip, Ether] = Stack,
    Addr = proplists:get_value(addr, Opts),
    IpAddr = proplists:get_value(ip_addr, Opts),
    Rep = [Ether#ether{dst = Ether#ether.src, src = Addr},
           Ip#ip{src = IpAddr, dst = Ip#ip.src},
           Icmp#icmp{type = echo_reply}],
    lager:info("icmp ~p", [aloha_utils:pr(Rep, ?MODULE)]),
    aloha_nic:send_packet(Rep);
handle_icmp(_Icmp, _Stack, _Opts) ->
    ok.
