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

-module(aloha_tcp_seq).
-export([trim/6, trim/5]).
-export([accept_check/4]).

-include("aloha_tcp_seq.hrl").

seq(S) -> S band 16#ffffffff.

seq_between(S1, S2, S3) ->
    ?SEQ_LTE(S1, S2) andalso ?SEQ_LT(S2, S3).

% trim out of window part of the segment
% it's assumed that the segment is at least partially in a valid window.
% (except the case for tcp_output)
trim(1, Data, Fin, Seq, WinStart, WinEnd) when ?SEQ_LT(Seq, WinStart) ->
    trim(0, Data, Fin, Seq+1, WinStart, WinEnd);
trim(0, <<>>, 1, Seq, WinStart, WinEnd) when ?SEQ_LT(Seq, WinStart) ->
    % for tcp_output, it's normal that snd_nxt is immediately after fin
    trim(0, <<>>, 0, Seq + 1, WinStart, WinEnd);
trim(0, Data, Fin, Seq, WinStart, WinEnd) when ?SEQ_LT(Seq, WinStart) ->
    Size = byte_size(Data),
    % for tcp_output, it's normal that snd_nxt is immediately after fin
    SkipSize = min(Size, seq(WinStart - Seq)),
    true = (Size + Fin >= seq(WinStart - Seq)),  % assert
    <<_:SkipSize/bytes, Data2/bytes>> = Data,
    trim(0, Data2, Fin, Seq + SkipSize, WinStart, WinEnd);
trim(Syn, Data, 1, Seq, WinStart, WinEnd)
    % the following guard is less obvious than it might look like.
    % it seems that this varies among implementations.
    % on the receive side:
    %   rfc 793 is saying to trim an out-of-window fin.  (Page 69-70)
    %   netbsd accepts a fin if it's immediately after the right edge of
    %   the window.  linux drops a fin if window is closed.
    % on the transmit side:
    %   netbsd only counts data portion of a segment.  so it happily sends
    %   an out-of-window fin if it's immediately after the right edge of
    %   the peer's window.
    %   linux honours the window and keeps sending window probes without fin.
    % (netbsd-6 and linux-2.6.32)
        when ?SEQ_LT(WinEnd, Seq + Syn + byte_size(Data) + 1) ->
    trim(Syn, Data, 0, Seq, WinStart, WinEnd);
trim(Syn, Data, 0, Seq, WinStart, WinEnd)
        when ?SEQ_LT(WinEnd, Seq + Syn + byte_size(Data)) ->
    Size = byte_size(Data),
    TakeSize = Size - seq(Seq + Syn + Size - WinEnd),
    <<Data2:TakeSize/bytes, _/bytes>> = Data,
    trim(Syn, Data2, 0, Seq, WinStart, WinEnd);
trim(Syn, Data, Fin, Seq, _WinStart, _WinEnd) ->
    {Syn, Data, Fin, seq(Seq)}.

trim(Syn, Data, Fin, Seq, WinStart) ->
    trim(Syn, Data, Fin, Seq, WinStart, WinStart + 999999).  % XXX

accept_check(_, 1, undefined, _) ->  % accept syn
    true;
accept_check(Seq, 0, RcvNxt, 0) ->
    Seq =:= RcvNxt;
accept_check(Seq, 0, RcvNxt, RcvWnd) ->
    seq_between(RcvNxt, Seq, RcvNxt + RcvWnd);
accept_check(_, _, _, 0) ->
    false;
accept_check(Seq, SegLen, RcvNxt, RcvWnd) ->
    seq_between(RcvNxt, Seq, RcvNxt + RcvWnd) orelse
    seq_between(RcvNxt, Seq + SegLen + 1, RcvNxt + RcvWnd).

%% debug

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

trim_test() ->
    ?assertEqual({1, <<"hoge">>, 1, 100},
                 trim(1, <<"hoge">>, 1, 100, 100, 106)),
    ?assertEqual({0, <<"hoge">>, 1, 101},
                 trim(1, <<"hoge">>, 1, 100, 101, 106)),
    ?assertEqual({0, <<"oge">>, 1, 102},
                 trim(1, <<"hoge">>, 1, 100, 102, 106)),
    ?assertEqual({1, <<"hoge">>, 0, 100},
                 trim(1, <<"hoge">>, 1, 100, 100, 105)),
    ?assertEqual({1, <<"hog">>, 0, 100},
                 trim(1, <<"hoge">>, 1, 100, 100, 104)),
    ?assertEqual({0, <<"og">>, 0, 102},
                 trim(1, <<"hoge">>, 1, 100, 102, 104)),
    ?assertEqual({0, <<>>, 1, 105},
                 trim(1, <<"hoge">>, 1, 100, 105, 106)),
    ?assertEqual({0, <<>>, 0, 106},
                 trim(1, <<"hoge">>, 1, 100, 106, 106)),
    ?assertEqual({0, <<"oge">>, 1, 1},
                 trim(1, <<"hoge">>, 1, 16#ffffffff, 1, 5)).

-endif.
