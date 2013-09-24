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

% references:
% RFC 6298

-module(aloha_tcp_rtt).
-export([init/0, sample/2, rto/1]).

-record(aloha_tcp_rtt, {
    srtt,
    var
}).

-define(K, 4).
-define(G, 1/1000000).  % clock granularity in seconds
-define(BETA, 1/4).
-define(ALPHA, 1/8).
-define(DEFAULT_RTO, 1000000).

% RFC 6298 says 1 sec.
% linux seems to use around 200ms.
% http://www.ee.ucl.ac.uk/~uceeips/minrto.pdf
% http://www.ee.ucl.ac.uk/~uceeips/minrto-networking07-psaras.pdf
% http://www.ietf.org/mail-archive/web/tcpm/current/msg07039.html
-define(MINRTO, 1000000).

init() ->
    #aloha_tcp_rtt{}.

sample(Sample, #aloha_tcp_rtt{srtt = undefined}) ->
    lager:info("RTT sample ~p", [Sample]),
    #aloha_tcp_rtt{srtt = Sample, var = Sample div 2};
sample(Sample, #aloha_tcp_rtt{srtt = SRtt, var = Var}) ->
    Var2 = (1 - ?BETA) * Var + ?BETA * abs(SRtt - Sample),
    SRtt2 = (1 - ?ALPHA) * SRtt + ?ALPHA * Sample,
    lager:info("RTT sample ~p srtt ~p -> ~p var ~p -> ~p",
               [Sample, SRtt, SRtt2, Var, Var2]),
    #aloha_tcp_rtt{srtt = SRtt2, var = Var2}.

rto(#aloha_tcp_rtt{srtt = undefined}) ->
    ?DEFAULT_RTO;
rto(#aloha_tcp_rtt{srtt = SRtt, var = Var}) ->
    RTO = SRtt + max(?G, ?K * Var),
    lager:info("RTO ~p", [RTO]),
    max(round(RTO), ?MINRTO).
