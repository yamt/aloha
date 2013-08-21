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

-module(aloha_tcp).
-export([start/0, handle/3]).
-export([listen/2]).
-export([send_packet/2]).

-include_lib("aloha_packet/include/aloha_packet.hrl").

pp(Rec) ->
    io_lib_pretty:print(Rec, fun pp/2).

pp(tcp, _N) ->
    record_info(fields, tcp).

start() ->
    ets:new(aloha_tcp_conn, [set, named_table, public]),
    ets:new(aloha_tcp_listener, [set, named_table, public]).

handle(Pkt, Stack, Opts) ->
    [Ip, _Ether] = Stack,
    {Tcp, bin, Data} = aloha_packet:decode(tcp, Pkt, Stack),
    lager:debug("TCP ~s ~w from ~w~n", [pp(Tcp), Data, Ip#ip.src]),
    handle_tcp(Tcp, Stack, Data, Opts).

% Key is either of Port or {IP, Port}
listen(Key, Opts) ->
    {ok, Pid} = aloha_tcp_listener:start_link(Key, Opts),
    {ok, {aloha_socket, Pid}}.

listener_key({_SrcIp, DstIp, _SrcPort, DstPort}) ->
    {DstIp, DstPort}.

listener_port_key({_SrcIp, _DstIp, _SrcPort, DstPort}) ->
    DstPort.

lookup_listener(Key) ->
    Spec = [{{listener_key(Key),     '$1'}, [], ['$1']},
            {{listener_port_key(Key),'$1'}, [], ['$1']}],
    ets:select(aloha_tcp_listener, Spec).

make_reply_template(Tcp, Stack) ->
    [Ip, Ether] = Stack,
    % swap dst and src
    [Ether#ether{dst = Ether#ether.src, src = Ether#ether.dst},
     Ip#ip{src = Ip#ip.dst, dst = Ip#ip.src, options = <<>>},
     #tcp{dst_port = Tcp#tcp.src_port, src_port = Tcp#tcp.dst_port}].

new_connection(#tcp{syn = 0}, _, _, _) ->
    none;
new_connection(Tcp, Stack, Key, Opts) ->
    case lookup_listener(Key) of
        [Listener] ->
            new_connection(Tcp, Stack, Key, Opts, Listener);
        [] ->
            lager:info("no listener for ~p", [Key]),
            none
    end.

new_connection(Tcp, Stack, Key, Opts, Listener) ->
    % create new connection process
    Opts2 = [{template, make_reply_template(Tcp, Stack)},
             {owner, Listener}, {key, Key} | Opts],
    {ok, NewPid} = gen_server:start(aloha_tcp_conn, Opts2, []),
    NewPid.

handle_tcp(#tcp{checksum=good} = Tcp, Stack, Data, Opts) ->
    lager:info("RECV ~s", [tcp_summary(Tcp, Data)]),
    [Ip|_] = Stack,
    Key = {Ip#ip.src, Ip#ip.dst, Tcp#tcp.src_port, Tcp#tcp.dst_port},
    Pid = try ets:lookup_element(aloha_tcp_conn, Key, 2)
    catch
        error:badarg ->
            new_connection(Tcp, Stack, Key, Opts)
    end,
    case Pid of
        none ->
            reply_rst(Tcp, Stack, Data, proplists:get_value(backend, Opts));
        _ ->
            gen_server:cast(Pid, {Tcp, Data})
    end;
handle_tcp(Tcp, _Stack, _Data, _Opts) ->
    lager:info("TCP bad checksum ~w", [Tcp]).

% cf. RFC 1122 4.2.2.20 (b)
make_rst(Rep, #tcp{ack = 0} = Tcp, Data) ->
    Rep#tcp{seqno = 0, ackno = aloha_tcp_conn:calc_next_seq(Tcp, Data),
            rst = 1, ack = 1};
make_rst(Rep, Tcp, _Data) ->
    Rep#tcp{seqno = Tcp#tcp.ackno, rst = 1}.

reply_rst(Tcp, Stack, Data, Backend) ->
    [Ether, Ip, Tcp2] = make_reply_template(Tcp, Stack),
    Tcp3 = make_rst(Tcp2, Tcp, Data),
    send_packet([Ether, Ip, Tcp3, <<>>], Backend).

send_packet(Pkt, Backend) ->
    [_, _, Tcp, Data] = Pkt,
    lager:info("SEND ~s", [tcp_summary(Tcp, Data)]),
    BinPkt = aloha_packet:encode_packet(Pkt),
%   [aloha_nic:send_packet(BinPkt, Backend) ||
%    random:uniform() > 0.5],  % drop packets for testing
    aloha_nic:send_packet(BinPkt, Backend).

flag(1, C) ->
    C;
flag(0, _) ->
    ".".

tcp_summary(#tcp{dst_port = Dst, src_port = Src, syn = Syn, ack = Ack,
                 rst = Rst, psh = Psh, fin = Fin, window = Win,
                 seqno = Seq, ackno = Ackno} = Tcp,
            Data) ->
    [integer_to_list(Src), "->", integer_to_list(Dst), " ",
     flag(Syn, "S"), flag(Ack, "A"), flag(Rst, "R"), flag(Psh, "P"),
     flag(Fin, "F"), " ",
     "seq ", integer_to_list(Seq),
     " len ", integer_to_list(aloha_tcp_conn:seg_len(Tcp, Data)),
     " ack ", integer_to_list(Ackno),
     " win ", integer_to_list(Win)].
