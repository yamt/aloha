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

-module(aloha_keydb).

-export([lookup_key/2]).
-export([register_peer_key/3]).

-include_lib("aloha_packet/include/aloha_packet.hrl").

-define(TABLE, ?MODULE).

lookup_key(#ip{dst = Dst}, encode) ->
    lookup_peer_key(ip, Dst);
lookup_key(#ip{src = Src}, decode) ->
    lookup_peer_key(ip, Src);
lookup_key(#ipv6{dst = Dst}, encode) ->
    lookup_peer_key(ipv6, Dst);
lookup_key(#ipv6{src = Src}, decode) ->
    lookup_peer_key(ipv6, Src).

lookup_peer_key(Proto, Addr) ->
    try
        ets:lookup_element(?TABLE, {peer, Proto, Addr}, 2)
    catch
        error:badarg ->
            lager:info("NO KEY for ~p ~p", [Proto, Addr]), 
            error(no_key)
    end.

register_peer_key(Proto, Addr, Key) ->
    lager:info("KEY ~p for ~p ~p", [Key, Proto, Addr]), 
    ets:insert(?TABLE, {{peer, Proto, Addr}, Key}).
