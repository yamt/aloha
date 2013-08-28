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

-module(aloha_icmpv6).
-export([handle/3]).

-include_lib("aloha_packet/include/aloha_packet.hrl").

handle(Pkt, Stack, Opts) ->
    {Icmp, _Next, <<>>} = aloha_packet:decode(icmpv6, Pkt, Stack),
    Addr = proplists:get_value(ipv6_addr, Opts),
    handle_icmpv6(Icmp, Stack, Addr, Opts).

handle_icmpv6(#icmpv6{checksum = bad} = Icmp, _Stack, _Addr, _Opts) ->
    lager:info("ICMP bad checksum ~p", [Icmp]);
handle_icmpv6(#icmpv6{type = echo_request} = Icmp, Stack, _Addr, Opts) ->
    [Ip, Ether] = Stack,
    Addr = proplists:get_value(addr, Opts),
    IpAddr = proplists:get_value(ipv6_addr, Opts),
    Rep = [Ether#ether{dst = Ether#ether.src, src = Addr},
           Ip#ipv6{src = IpAddr, dst = Ip#ipv6.src},
           Icmp#icmpv6{type = echo_reply}],
    aloha_nic:send_packet(Rep);
handle_icmpv6(#icmpv6{type = neighbor_solicitation,
                      data = #neighbor_solicitation{
                          target_address = Addr,
                          options = _Options}} = Icmp,
              Stack, Addr, Opts) ->
    [Ip, Ether] = Stack,
    lager:info("icmpv6 neighbor sol who-has ~w tell ~w", [Addr, Ip#ipv6.src]),
    LLAddr = proplists:get_value(addr, Opts),
    Rep = [Ether#ether{dst = Ether#ether.src, src = Addr},
           Ip#ipv6{src = Addr, dst = Ip#ipv6.src},
           Icmp#icmpv6{type = neighbor_advertisement,
                       data = #neighbor_advertisement{
                           router = 0,
                           solicited = 1,
                           override = 1,
                           target_address = Addr,
                           options = [{target_link_layer_address, LLAddr}]}}],
    aloha_nic:send_packet(Rep);
handle_icmpv6(#icmpv6{type = neighbor_advertisement,
                      data = #neighbor_advertisement{
                          target_address = TargetAddress,
                          options = Options}},
              _Stack, _Addr, _Opts) ->
    LLAddr = proplists:get_value(target_link_layer_address, Options),
    lager:info("icmpv6 neighbor adv ~w has ~w", [LLAddr, TargetAddress]);
handle_icmpv6(Icmp, _Stack, _Addr, _Opts) ->
    lager:info("icmpv6 unhandled ~p", [aloha_utils:pr(Icmp, ?MODULE)]),
    ok.
