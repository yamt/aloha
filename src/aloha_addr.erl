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

-module(aloha_addr).
-export([to_ip/1]).
-export([to_bin/1]).

% convert to an erlang inet:ip_address() style tuple
to_ip(Tuple) when is_tuple(Tuple) ->
    Tuple;
to_ip(Bin) when byte_size(Bin) =:= 4 ->
    bin_to_ipv4(Bin);
to_ip(Bin) when byte_size(Bin) =:= 16 ->
    bin_to_ipv6(Bin).

bin_to_ipv4(<<A, B, C, D>>) ->
    {A, B, C, D}.

bin_to_ipv6(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    {A, B, C, D, E, F, G, H}.

% convert to on-wire binary
to_bin(Ip) when is_binary(Ip) ->
    Ip;
to_bin(Ip) when tuple_size(Ip) =:= 4 ->
    ipv4_to_bin(Ip);
to_bin(Ip) when tuple_size(Ip) =:= 8 ->
    ipv6_to_bin(Ip).

ipv4_to_bin({A, B, C, D}) ->
    <<A, B, C, D>>.

ipv6_to_bin({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

ipv4_to_ip_test() ->
    ?assertEqual({16#aa,16#bb,16#cc,16#dd},
                 to_ip({16#aa,16#bb,16#cc,16#dd})),
    ?assertEqual({16#aa,16#bb,16#cc,16#dd},
                 to_ip(<<16#aabbccdd:32>>)).

ipv6_to_ip_test() ->
    ?assertEqual({16#1122,16#3344,16#5566,16#7788,
                  16#99aa,16#bbcc,16#ddee,16#ff00},
                 to_ip({16#1122,16#3344,16#5566,16#7788,
                        16#99aa,16#bbcc,16#ddee,16#ff00})),
    ?assertEqual({16#1122,16#3344,16#5566,16#7788,
                  16#99aa,16#bbcc,16#ddee,16#ff00},
                 to_ip(<<16#112233445566778899aabbccddeeff00:128>>)).

ipv4_to_bin_test() ->
    ?assertEqual(<<16#aabbccdd:32>>,
                 to_bin({16#aa,16#bb,16#cc,16#dd})),
    ?assertEqual(<<16#aabbccdd:32>>,
                 to_bin(<<16#aabbccdd:32>>)).

ipv6_to_bin_test() ->
    ?assertEqual(<<16#112233445566778899aabbccddeeff00:128>>,
                 to_bin({16#1122,16#3344,16#5566,16#7788,
                         16#99aa,16#bbcc,16#ddee,16#ff00})),
    ?assertEqual(<<16#112233445566778899aabbccddeeff00:128>>,
                 to_bin(<<16#112233445566778899aabbccddeeff00:128>>)).

-endif.
