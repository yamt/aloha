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

-module(aloha_utils).

-export([merge_opts/2, normalize_opts/1, acc_opts/3]).
-export([pr/2]).
-export([bin_not/1, bin_and/2, bin_or/2]).

% normalize Opts1++Opts2
merge_opts(Opts1, Opts2) ->
    normalize_opts(Opts1 ++ Opts2).

normalize_opts(Opts) ->
    lists:ukeysort(1, proplists:unfold(Opts)).

% find options listed in List in Opts1 and prepend Opts2 with them
acc_opts(List, Opts1, Opts2) ->
    lists:foldl(fun(X, Acc) -> lookup_and_acc(X, Opts1, Acc) end, Opts2, List).

lookup_and_acc(Name, Opts, Acc) ->
    case proplists:lookup(Name, Opts) of
        none -> Acc;
        T -> [T|Acc]
    end.

% lager:pr/2 wrapper to pretty print records recursively
pr(V, Mod) ->
    recur_apply(fun(X) -> lager:pr(X, Mod) end, V).

recur_apply(F, V) when is_list(V) ->
    lists:map(fun(X) -> recur_apply(F, X) end, V);
recur_apply(F, V) when is_tuple(V) andalso is_atom(element(1, V)) ->
    [H|T] = tuple_to_list(V),
    F(list_to_tuple([H|recur_apply(F, T)]));
recur_apply(F, V) ->
    F(V).

bin_not(Bin) ->
    Size = byte_size(Bin),
    <<Int:Size/unit:8>> = Bin,
    <<(bnot Int):Size/unit:8>>.

bin_and(Bin1, Bin2) ->
    Size = byte_size(Bin1),
    Size = byte_size(Bin2),
    <<Int1:Size/unit:8>> = Bin1,
    <<Int2:Size/unit:8>> = Bin2,
    <<(Int1 band Int2):Size/unit:8>>.

bin_or(Bin1, Bin2) ->
    Size = byte_size(Bin1),
    Size = byte_size(Bin2),
    <<Int1:Size/unit:8>> = Bin1,
    <<Int2:Size/unit:8>> = Bin2,
    <<(Int1 bor Int2):Size/unit:8>>.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

normalize_opts_test() ->
    ?assertEqual([], normalize_opts([])),
    ?assertEqual([{a,true}], normalize_opts([a])),
    ?assertEqual([{b,1}], normalize_opts([{b,1}])),
    ?assertEqual([{a,true},{b,true},{c,9},{d,true}],
                 normalize_opts([a,b,{c,9},b,d,a])),
    ?assertEqual([{a,true},{b,true},{c,9},{d,true}],
                 normalize_opts([b,b,d,{c,9},a,a])).

acc_opts_test() ->
    ?assertEqual([], acc_opts([hoge], [], [])),
    ?assertEqual([fuga], acc_opts([hoge], [], [fuga])),
    ?assertEqual([{hoge,1}], acc_opts([hoge], [{hoge,1}], [])),
    ?assertEqual([{hoge,1},fuga], acc_opts([hoge], [{hoge,1}], [fuga])),
    ?assertEqual([{hoge,true},fuga], acc_opts([hoge], [a,hoge,c], [fuga])),
    ?assertEqual([{hoge,true}], acc_opts([hoge], [a,{hoge,true},c], [])).

-endif.
