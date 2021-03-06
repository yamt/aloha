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
-export([handle/4]).
-export([send_packet/3]).

-export([listen/2]).
-export([connect/6]).

-behaviour(aloha_protocol).

-include_lib("aloha_packet/include/aloha_packet.hrl").
-include("aloha_tcp_seq.hrl").

handle(tcp, Pkt, Stack, Opts) ->
    [_Ip, _Ether] = Stack,
    EncOpts = [{lookup_key, {aloha_keydb, lookup_key, []}}],
    {Tcp, bin, Data} = aloha_packet:decode(tcp, Pkt, Stack, EncOpts),
    case proplists:get_value(md5, Tcp#tcp.options) of
        undefined ->
            handle_tcp(Tcp, Stack, Data, Opts);
        good ->
            handle_tcp(Tcp, Stack, Data, Opts);
        Error ->
            lager:info("TCP bad md5 sig ~p ~w", [Error, Tcp])
    end.

% Key is either of Port or {IP, Port}
listen(Key, Opts) ->
    {ok, Pid} = aloha_tcp_listener:start_link(Key, Opts),
    lager:info("listen ~p key ~p Opts ~p", [Pid, Key, Opts]),
    {ok, {aloha_socket, Pid}}.

listener_key({NS, {_SrcIp, DstIp, _SrcPort, DstPort}}) ->
    {NS, {DstIp, DstPort}}.

listener_port_key({NS, {_SrcIp, _DstIp, _SrcPort, DstPort}}) ->
    {NS, DstPort}.

lookup_listener(Key) ->
    Spec = [{{listener_key(Key),     '$1'}, [], ['$1']},
            {{listener_port_key(Key),'$1'}, [], ['$1']}],
    ets:select(aloha_tcp_listener, Spec).

make_reply_template(#ip{src = Src, dst = Dst} = Ip) ->
    Ip#ip{src = Dst, dst = Src, options = <<>>};
make_reply_template(#ipv6{src = Src, dst = Dst} = Ip) ->
    Ip#ipv6{src = Dst, dst = Src}.

make_reply_template(Tcp, Stack) ->
    [Ip, Ether] = Stack,
    % swap dst and src
    [Ether#ether{dst = Ether#ether.src, src = Ether#ether.dst},
     make_reply_template(Ip),
     #tcp{dst_port = Tcp#tcp.src_port, src_port = Tcp#tcp.dst_port,
          options = aloha_utils:acc_opts([md5], Tcp#tcp.options, [])}].

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
    {ok, Opts3} = aloha_socket:getopts({aloha_socket, Listener}, [md5sig]),
    Opts4 = Opts2 ++ Opts3,
    {ok, NewPid} = aloha_tcp_conn:start(Opts4),
    lager:info("new conn ~p opts ~p", [NewPid, Opts4]),
    NewPid.

handle_tcp(#tcp{checksum=good} = Tcp, Stack, Data, Opts) ->
    lager:info("RECV ~s", [tcp_summary(Tcp, Data)]),
    NS = proplists:get_value(namespace, Opts),
    [Ip|_] = Stack,
    Key = case Ip of
        #ip{src = Src, dst = Dst} ->
            {NS, {Src, Dst, Tcp#tcp.src_port, Tcp#tcp.dst_port}};
        #ipv6{src = Src, dst = Dst} ->
            {NS, {Src, Dst, Tcp#tcp.src_port, Tcp#tcp.dst_port}}
    end,
    Pid = try ets:lookup_element(aloha_tcp_conn, Key, 2)
    catch
        error:badarg ->
            new_connection(Tcp, Stack, Key, Opts)
    end,
    case Pid of
        none ->
            reply_rst(Tcp, Stack, Data, Opts);
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
    Rep#tcp{seqno = Tcp#tcp.ackno, rst = 1, ack = 0, psh = 0}.

reply_rst(#tcp{rst = 1}, _, _, _) ->
    ok;
reply_rst(Tcp, Stack, Data, Opts) ->
    Backend = proplists:get_value(backend, Opts),
    NS = proplists:get_value(namespace, Opts),
    [Ether, Ip, Tcp2] = make_reply_template(Tcp, Stack),
    Tcp3 = make_rst(Tcp2, Tcp, Data),
    send_packet([Ether, Ip, Tcp3, <<>>], NS, Backend).

send_packet(Pkt, NS, Backend) ->
    [_, _, Tcp, Data] = Pkt,
    lager:info("SEND ~s", [tcp_summary(Tcp, Data)]),
    aloha_neighbor:send_packet(Pkt, NS, Backend).

flag(1, C) ->
    C;
flag(0, _) ->
    ".".

connect(NS, RAddr0, RPort, L1Src, Backend, Opts) ->
    RAddr = aloha_addr:to_bin(RAddr0),
    LAddr = aloha_addr:to_bin(proplists:get_value(ip, Opts)),
    LPort = proplists:get_value(port, Opts, choose_port()),
    Mtu = proplists:get_value(mtu, Opts, 1500),
    Proto = case byte_size(LAddr) of
        16 -> ipv6;
        4 -> ip
    end,
    Key = {NS, {RAddr, LAddr, RPort, LPort}},
    TcpOptions = case proplists:get_value(md5sig, Opts, false) of
        true ->
            [{md5, dummy}];
        false ->
            []
    end,
    Opts2 = [{owner, self()},
             {addr, L1Src},
             {mtu, Mtu},
             {Proto, LAddr},
             {backend, Backend},
             {key, Key},
             {template,
                 make_template(Proto, RAddr, RPort, LAddr, LPort, L1Src,
                               TcpOptions)},
             {namespace, NS}],
    Opts3 = aloha_utils:acc_opts([rcv_buf, snd_buf, md5sig], Opts, Opts2),
    case aloha_tcp_conn:start(Opts3) of
        {ok, Pid} ->
            connect(Pid, Opts);
        Error ->
            Error
    end.

connect(Pid, Opts) ->
    ok = gen_server:call(Pid, connect),
    Sock = {aloha_socket, Pid},
    case connect_wait(Sock) of
        {ok, Sock} ->
            DefOpts = [{active, true}],
            Opts2 = aloha_utils:acc_opts([active], Opts, DefOpts),
            aloha_socket:setopts(Sock, Opts2),
            {ok, Sock};
        Error ->
            Error
    end.

connect_wait(Sock) ->
    lager:info("waiting active connect completion", []),
    receive
        {aloha_tcp_connected, Sock} -> {ok, Sock};
        {tcp_error, Sock, econnreset} -> {error, econnrefused};
        {tcp_error, Sock, Reason} -> {error, Reason}
    end.

make_template(Proto, Dst, DstPort, Src, SrcPort, L1Src, TcpOptions) ->
    [#ether{dst = <<0,0,0,0,0,0>>, src = L1Src, type = Proto},
     make_l2_template(Proto, Dst, Src),
     #tcp{src_port = SrcPort, dst_port = DstPort,
          options = TcpOptions}].

make_l2_template(ip, Dst, Src) ->
    #ip{dst = Dst, src = Src, protocol = tcp};
make_l2_template(ipv6, Dst, Src) ->
    #ipv6{dst = Dst, src = Src, next_header = tcp}.

choose_port() ->
    crypto:rand_uniform(1000, 65000).  % XXX

tcp_summary(#tcp{dst_port = Dst, src_port = Src, syn = Syn, ack = Ack,
                 rst = Rst, psh = Psh, fin = Fin, window = Win,
                 seqno = Seq, ackno = Ackno} = Tcp,
            Data) ->
    SegLen = aloha_tcp_conn:seg_len(Tcp, Data),
    [integer_to_list(Src), "->", integer_to_list(Dst), " ",
     flag(Syn, "S"), flag(Ack, "A"), flag(Rst, "R"), flag(Psh, "P"),
     flag(Fin, "F"), " ",
     "seq ", integer_to_list(Seq), ":", integer_to_list(?SEQ(Seq + SegLen)),
     " len ", integer_to_list(SegLen),
     " ack ", integer_to_list(Ackno),
     " win ", integer_to_list(Win)].
