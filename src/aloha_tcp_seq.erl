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

% S1 <= S2 < S3
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

% RFC 793 Page 26
%
% Segment Receive  Test
% Length  Window
% ------- -------  -------------------------------------------
%
%    0       0     SEG.SEQ = RCV.NXT
%
%    0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
%
%   >0       0     not acceptable
%
%   >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
%               or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
%
% NetBSD accepts a segement after window if data portion of the segment
% (ie. excluding fin) does not beyond the window.
% this implementation rejects such a segment.  Linux seems to reject, too.
%
% seg_len = 0 on the right edge of the window case is also different.
% consider: rcv_nxt = 1000, rcv_win = 500, seg_seq = 1500, seg_len = 0
% this implementation rejects such a segment as it's out of window per rfc.
% NetBSD accepts it.
% Linux seems to accept it too.  (tcp_validate_incoming@tcp_input.c)
%
% http://www.ietf.org/proceedings/86/slides/slides-86-tcpm-4
accept_check(_, 1, undefined, _) ->  % special case: accept syn
    true;
accept_check(_, 0, undefined, _) ->  % special case: or rst
    true;
accept_check(Seq, 0, RcvNxt, 0) ->
    Seq =:= RcvNxt;
accept_check(Seq, 0, RcvNxt, RcvWnd) ->
    seq_between(RcvNxt, Seq, RcvNxt + RcvWnd);
accept_check(_, _, _, 0) ->
    false;
accept_check(Seq, SegLen, RcvNxt, RcvWnd) ->
    seq_between(RcvNxt, Seq, RcvNxt + RcvWnd) orelse
    seq_between(RcvNxt, Seq + SegLen - 1, RcvNxt + RcvWnd).

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

accept_check_test() ->
    % accept_check(Seq, SegLen, RcvNxt, RcvWnd) -> true|false

    % RFC 793 Page 26  (and Page 69)
    %
    % Segment Receive  Test
    % Length  Window
    % ------- -------  -------------------------------------------
    %
    %    0       0     SEG.SEQ = RCV.NXT

    ?assertEqual(false, accept_check(1999, 0, 2000, 0)),
    ?assertEqual(true,  accept_check(2000, 0, 2000, 0)),
    ?assertEqual(false, accept_check(2001, 0, 2000, 0)),

    %    0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND

    ?assertEqual(false, accept_check(1999, 0, 2000, 1000)),
    ?assertEqual(true,  accept_check(2000, 0, 2000, 1000)),
    ?assertEqual(true,  accept_check(2999, 0, 2000, 1000)),
    ?assertEqual(false, accept_check(3000, 0, 2000, 1000)),

    %   >0       0     not acceptable

    ?assertEqual(false, accept_check(1999, 1, 2000, 0)),
    ?assertEqual(false, accept_check(2000, 1, 2000, 0)),
    ?assertEqual(false, accept_check(2001, 1, 2000, 0)),

    %   >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
    %               or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND

    ?assertEqual(false, accept_check(1999, 1, 2000, 1000)),
    ?assertEqual(true,  accept_check(1999, 2, 2000, 1000)),
    ?assertEqual(true,  accept_check(2000, 1, 2000, 1000)),
    ?assertEqual(true,  accept_check(2000, 2, 2000, 1000)),
    ?assertEqual(true,  accept_check(2999, 1, 2000, 1000)),
    ?assertEqual(true,  accept_check(2999, 2, 2000, 1000)),
    ?assertEqual(false, accept_check(3000, 1, 2000, 1000)),
    ?assertEqual(false, accept_check(3000, 2, 2000, 1000)),

    ?assertEqual(true,  accept_check(2000,  999, 2000, 1000)),
    ?assertEqual(true,  accept_check(2000, 1000, 2000, 1000)),
    ?assertEqual(true,  accept_check(2000, 1001, 2000, 1000)),

    ?assertEqual(true,  accept_check(1999,  999, 2000, 1000)),
    ?assertEqual(true,  accept_check(1999, 1000, 2000, 1000)),
    ?assertEqual(true,  accept_check(1999, 1001, 2000, 1000)),
    ?assertEqual(false, accept_check(1999, 1002, 2000, 1000)).

-endif.
