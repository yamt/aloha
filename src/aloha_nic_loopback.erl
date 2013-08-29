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

-module(aloha_nic_loopback).
-export([create/2]).
-export([loopback/2]).

% a convenient routine to create loopback interface.
create(NS, Addr) ->
    Id = make_ref(),
    Key = {?MODULE, Id},
    {ok, Pid} = gen_server:start(aloha_nic,
                                 [{namespace, NS},
                                  {addr, Addr},
                                  {key, Key},
                                  {mtu, 2000},  % arbitrary
                                  {backend, {?MODULE, loopback, [Key]}}],
                                 []),
    lager:info("loopback nic ~p created", [Pid]),
    {ok, Pid}.

%% internal

loopback(Pkt, Key) ->
    Nic = ets:lookup_element(aloha_nic, Key, 2),
    % lager:info("loopback pkt ~p", [aloha_utils:pr(Pkt, aloha_tcp)]),
    gen_server:cast(Nic, {packet, Pkt}).
