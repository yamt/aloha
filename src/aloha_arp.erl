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

-module(aloha_arp).
-export([handle/3]).
-export([discovery_packet/3]).

-include_lib("aloha_packet/include/aloha_packet.hrl").

handle(Pkt, Stack, Opts) ->
    {Arp, _Next, _Rest} = aloha_packet:decode(arp, Pkt, Stack),
    Addr = proplists:get_value(ip_addr, Opts),
    handle_arp(Arp, Addr, Opts).

handle_arp(#arp{op = request, sha = Sha, spa = Spa, tpa = Addr} = Arp, Addr,
           Opts) ->
    LLAddr = proplists:get_value(addr, Opts),
    lager:info("arp request who-has ~w tell ~w (~w)", [Addr, Spa, Sha]),
    Rep = [#ether{dst = Sha, src = LLAddr, type = arp},
           Arp#arp{op = reply, tpa = Spa, tha = Sha, spa = Addr, sha = LLAddr}],
    aloha_nic:send_packet(Rep);
handle_arp(#arp{op = reply, sha = Sha, spa = Spa}, _Addr, _Opts) ->
    lager:info("arp reply ~w has ~w", [Sha, Spa]);
handle_arp(#arp{}, _Addr, _Opts) ->
    ok.

discovery_packet(Target, OurAddr, OurLLAddr) ->
    [#ether{dst = <<255,255,255,255,255,255>>, src = OurLLAddr, type = arp},
     #arp{op = request, sha = OurLLAddr, spa = OurAddr, tha = <<0,0,0,0,0,0>>,
          tpa = Target}].
