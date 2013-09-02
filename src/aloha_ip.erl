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

-module(aloha_ip).
-export([handle/3]).

-behaviour(aloha_protocol).

-include_lib("aloha_packet/include/aloha_packet.hrl").

handle(Pkt, Stack, Opts) ->
    {Ip, Next, Rest} = aloha_packet:decode(ip, Pkt, Stack),
    IpAddr = proplists:get_value(ip, Opts),
    Mask = proplists:get_value(ip_mask, Opts, <<255,255,255,0>>),
    Bcast = aloha_utils:bin_or(IpAddr, aloha_utils:bin_not(Mask)),
    handle_ip(Ip, Next, Rest, IpAddr, Bcast, Stack, Opts).

handle_ip(#ip{checksum = bad} = Ip, _Next, _Rest, _IpAddr, _Bcast, _Stack,
          _Opts) ->
    lager:info("IP bad checksum ~p", [Ip]);
handle_ip(#ip{dst = IpAddr} = Ip, Next, Rest, IpAddr, _Bcast, Stack, Opts) ->
    aloha_protocol:dispatch({Next, Rest, [Ip|Stack]}, Opts);
handle_ip(#ip{dst = Bcast} = Ip, Next, Rest, _IpAddr, Bcast, Stack, Opts) ->
    aloha_protocol:dispatch({Next, Rest, [Ip|Stack]}, Opts);
handle_ip(Ip, _Next, _Rest, _IpAddr, _Bcast, _Stack, _Opts) ->
    lager:info("not ours ~p", [aloha_utils:pr(Ip, ?MODULE)]).
