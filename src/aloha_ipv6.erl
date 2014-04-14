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

-module(aloha_ipv6).
-export([handle/4]).
-export([solicited_node_multicast/1]).
-export([multicast_ether/1]).

-behaviour(aloha_protocol).

-include_lib("aloha_packet/include/aloha_packet.hrl").

handle(ipv6, Pkt, Stack, Opts) ->
    {Ip, Next, Rest} = aloha_packet:decode(ipv6, Pkt, Stack),
    IpAddr = proplists:get_value(ipv6, Opts, none),
    Mcast = solicited_node_multicast(IpAddr),
    handle_ipv6(Ip, Next, Rest, IpAddr, Mcast, Stack, Opts).

handle_ipv6(#ipv6{dst = IpAddr} = Ip, Next, Rest, IpAddr, _Mcast, Stack,
            Opts) ->
    aloha_protocol:dispatch({Next, Rest, [Ip|Stack]}, Opts);
handle_ipv6(#ipv6{dst = Mcast} = Ip, Next, Rest, _IpAddr, Mcast, Stack, Opts) ->
    aloha_protocol:dispatch({Next, Rest, [Ip|Stack]}, Opts);
handle_ipv6(Ip, _Next, _Rest, _IpAddr, _Mcast, _Stack, _Opts) ->
    lager:info("not ours ~p", [aloha_utils:pr(Ip, ?MODULE)]).

% compute solicited-node multicast address (RFC 4291 2.7.1.)
solicited_node_multicast(Addr) ->
    <<_:104, Tail:24>> = Addr,
    <<16#ff02:16, 0:16, 0:16, 0:16, 0:16, 1:16, 16#ff:8, Tail:24>>.

% RFC 2464 7.
multicast_ether(<<_:(12*8), A, B, C, D>>) ->
    <<16#33, 16#33, A, B, C, D>>.
