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

-module(aloha_ether).
-export([handle/4]).

-behaviour(aloha_protocol).

-include_lib("aloha_packet/include/aloha_packet.hrl").

-define(BROADCAST, <<16#ffffffffffff:(6*8)>>).

handle(ether, Pkt, [], Opts) ->
    {Ether, Next, Rest} = aloha_packet:decode(ether, Pkt, []),
    handle_ether(Ether, Next, Rest, Opts).

handle_ether(#ether{dst = Dst} = Ether, Next, Rest, Opts) ->
    case is_ours(Dst, Opts) of
        true -> aloha_protocol:dispatch({Next, Rest, [Ether]}, Opts);
        false -> lager:info("ether not ours ~w~n", [Dst])
    end.

is_ours(?BROADCAST, _Opts) ->
    true;
is_ours(<<16#33, 16#33, _/bytes>>, _Opts) ->
    % XXX hardcode
    % ipv6 multicast (RFC 2464 7.)
    true;
is_ours(Addr, Opts) ->
    OurAddr = proplists:get_value(addr, Opts),
    Addrs = [OurAddr|proplists:get_value(auxaddrs, Opts, [])],
    lists:any(fun(X) -> X =:= Addr end, Addrs).
