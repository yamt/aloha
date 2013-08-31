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

-module(aloha_tcp_conn).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).
-export([start/1]).

-export([calc_next_seq/2, seg_len/2]).

-export([controlling_process/2]).

-include_lib("aloha_packet/include/aloha_packet.hrl").
-include("aloha_tcp_seq.hrl").

-behaviour(gen_server).

-record(tcp_state, {snd_una, snd_nxt, snd_wnd,
                    snd_buf, snd_buf_size,
                    snd_mss,
                    snd_syn = 0,
                    snd_fin = 0, rexmit_timer, delack_timer,
                    rcv_nxt,
                    rcv_adv,  % the right edge of advertised window
                    rcv_buf, rcv_buf_size,
                    rcv_mss,
                    backend, template,
                    state, owner, active = false, suppress = false,
                    pending_ctl = [],
                    key,
                    writers = [], reader = none,
                    namespace}).

-define(MSL, (30 * 1000)).

-define(REXMIT_TIMEOUT, 1000).
-define(PERSIST_TIMEOUT, 3000).
-define(DELACK_TIMEOUT, 500).
-define(TIME_WAIT_TIMEOUT, (2 * ?MSL)).

-define(DEFAULT_MSS, (576 - 20 - 20)).  % as per RFC 879 and RFC 1122

start(Opts) ->
    gen_server:start(?MODULE, Opts, []).

init(Opts) ->
    false = process_flag(trap_exit, true),
    Backend = proplists:get_value(backend, Opts),
    Key = proplists:get_value(key, Opts),
    MTU = proplists:get_value(mtu, Opts, 1500),
    MSS = MTU - 20 - 20,
    Owner = proplists:get_value(owner, Opts),
    NS = proplists:get_value(namespace, Opts),
    ISS = 0, %16#ffff0000,
    State = #tcp_state{backend = Backend,
                       template = proplists:get_value(template, Opts),
                       snd_nxt = ISS,
                       snd_una = ISS,
                       snd_buf = <<>>,
                       snd_buf_size = proplists:get_value(snd_buf, Opts, 3000),
                       snd_mss = MSS,
                       snd_wnd = 1,  % for initial syn
                       rexmit_timer = make_ref(),
                       rcv_buf = <<>>,
                       rcv_buf_size = proplists:get_value(rcv_buf, Opts, 3000),
                       rcv_mss = MSS,
                       state = closed,
                       owner = Owner,
                       key = Key,
                       namespace = NS},
    true = ets:insert_new(?MODULE, {Key, self()}),
    link(Owner),
    {ok, State}.

reply(Reply, State) ->
    reply(should_exit(State), should_hibernate(State), Reply, State).

reply(true, _, Reply, State) ->
    {stop, normal, Reply, State};
reply(false, true, Reply, State) ->
    {reply, Reply, State, hibernate};
reply(false, false, Reply, State) ->
    {reply, Reply, State}.

noreply(State) ->
    noreply(should_exit(State), should_hibernate(State), State).

noreply(true, _, State) ->
    {stop, normal, State};
noreply(false, true, State) ->
    {noreply, State, hibernate};
noreply(false, false, State) ->
    {noreply, State}.

handle_call(connect, _From, #tcp_state{state = closed} = State) ->
    State2 = State#tcp_state{snd_syn = 1},
    State3 = set_state(syn_sent, State2),
    State4 = tcp_output(State3),
    reply(ok, State4);
handle_call({send, Data}, From, State) ->
    lager:info("TCP user write datalen ~p", [byte_size(Data)]),
    State2 = add_writer({From, Data}, State),
    State3 = process_writers(State2),
    State4 = tcp_output(State3),
    noreply(State4);
handle_call({recv, _, _}, _From,
            #tcp_state{active = Active} = State) when Active =/= false ->
    % gen_tcp compat behaviour
    reply({error, einval}, State);
handle_call({recv, _, _}, _From,
            #tcp_state{reader = Reader} = State) when Reader =/= none ->
    % gen_tcp compat behaviour
    lager:info("recv ealready"),
    reply({error, ealready}, State);
handle_call({recv, Len, Timeout}, From,
            #tcp_state{reader = none, active = false} = State) ->
    lager:info("TCP user read request datalen ~p", [Len]),
    TRef = setup_reader_timeout(Timeout),
    State2 = State#tcp_state{reader = {TRef, From, Len, <<>>}},
    State3 = process_readers(State2),
    State4 = tcp_output(State3),
    noreply(State4);
handle_call(peername, _From, #tcp_state{template = Tmpl} = State) ->
    {Addr, Port} = case Tmpl of
        [_, #ip{dst = A}, #tcp{dst_port = P}] -> {A, P};
        [_, #ipv6{dst = A}, #tcp{dst_port = P}] -> {A, P}
    end,
    reply({ok, {aloha_addr:to_ip(Addr), Port}}, State);
handle_call(sockname, _From, #tcp_state{template = Tmpl} = State) ->
    {Addr, Port} = case Tmpl of
        [_, #ip{src = A}, #tcp{src_port = P}] -> {A, P};
        [_, #ipv6{src = A}, #tcp{src_port = P}] -> {A, P}
    end,
    reply({ok, {aloha_addr:to_ip(Addr), Port}}, State);
handle_call({controlling_process, NewOwner}, _From,
            #tcp_state{owner = OldOwner} = State) ->
    true = State#tcp_state.suppress,  % assert.  see controlling_process/1
    State2 = State#tcp_state{owner = NewOwner},
    unlink(OldOwner),
    link(NewOwner),
    reply(ok, State2);
handle_call(close, {Pid, _}, #tcp_state{owner = Pid} = State) ->
    lager:info("TCP user close ~p", [self()]),
    reply(ok, close(State));
handle_call({setopts, Opts}, _From, State) ->
    {Ret, State2} = setopts(proplists:unfold(Opts), State),
    State3 = deliver_to_app(State2),
    reply(Ret, State3);
handle_call({set_suppress, Mode}, _From,
            #tcp_state{suppress = OldMode} = State) ->
    State2 = State#tcp_state{suppress = Mode},
    State3 = deliver_to_app(State2),
    reply({ok, OldMode}, State3);
handle_call({test_and_set_active, OldMode, NewMode}, _From,
            #tcp_state{active = OldMode} = State) ->
    State2 = State#tcp_state{active = NewMode},
    State3 = deliver_to_app(State2),
    reply(ok, State3);
handle_call(get_owner_info, _From,
            #tcp_state{owner = Owner, active = Active} = State) ->
    reply({Owner, Active}, State).

handle_cast({#tcp{}, _} = Msg, State) ->
    segment_arrival(Msg, State);
handle_cast({shutdown, read}, State) ->
    lager:info("TCP user shutdown read ~p", [self()]),
    State2 = shutdown_receiver(State),
    noreply(State2);
handle_cast({shutdown, write}, State) ->
    lager:info("TCP user shutdown write ~p", [self()]),
    State2 = shutdown_sender(State),
    noreply(State2);
handle_cast(M, State) ->
    lager:info("unknown msg ~w", [M]),
    noreply(State).

handle_info({timeout, TRef, reader_timeout},
            #tcp_state{rcv_buf = RcvBuf,
                       reader = {TRef, From, _, Data}} = State) ->
    gen_server:reply(From, {error, timeout}),
    % XXX XXX this shrinks window advertised to the peer
    RcvBuf2 = <<Data/bytes, RcvBuf/bytes>>,
    noreply(State#tcp_state{rcv_buf = RcvBuf2, reader = none});
handle_info({timeout, TRef, time_wait_timer},
            #tcp_state{rexmit_timer = TRef, state = time_wait} = State) ->
    lager:debug("2msl timer expired"),
    State2 = set_state(closed, State),
    noreply(State2);
handle_info({timeout, TRef, Name},
            #tcp_state{snd_una = Una, rexmit_timer = TRef} = State) ->
    lager:debug("~p expired", [Name]),
    State2 = State#tcp_state{snd_nxt = Una},
    State3 = tcp_output(true, false, State2),
    noreply(State3);
handle_info({timeout, TRef, delack_timeout},
            #tcp_state{delack_timer = TRef} = State) ->
    lager:info("delack timer expired"),
    State2 = tcp_output(true, State),
    noreply(State2);
handle_info({'EXIT', Pid, Reason}, #tcp_state{owner = Pid} = State) ->
    lager:info("owner ~p exited with reason ~p", [Pid, Reason]),
    noreply(close(State));
handle_info(Info, State) ->
    lager:info("handle_info: ~p", [Info]),
    noreply(State).

terminate(Reason, #tcp_state{key = Key}) ->
    lager:info("conn process terminate ~p", [Reason]),
    true = ets:delete(?MODULE, Key),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

trim(Tcp, Data, #tcp_state{rcv_nxt = undefined}) ->
    {Tcp, Data};
trim(#tcp{syn = Syn, fin = Fin, seqno = Seq} = Tcp, Data,
     #tcp_state{rcv_nxt = RcvNxt} = State) ->
    {Syn2, Data2, Fin2, Seq2} =
        aloha_tcp_seq:trim(Syn, Data, Fin, Seq,
                           RcvNxt, RcvNxt + rcv_wnd(State)),
    {Tcp#tcp{syn = Syn2, fin = Fin2, seqno = Seq2}, Data2}.

seg_len(#tcp{syn = Syn, fin = Fin}, Data) ->
    Syn + byte_size(Data) + Fin.

calc_next_seq(#tcp{seqno = Seq} = Tcp, Data) ->
    ?SEQ(Seq + seg_len(Tcp, Data)).

% advance SND.UNA and truncate send buffer
% SND.UNA < SEG.ACK =< SND.NXT
process_ack(#tcp{ack = 1, ackno = Ack, window = Wnd},
            #tcp_state{snd_una = Una, snd_nxt = Nxt,
                       snd_syn = Syn, snd_buf = SndBuf,
                       snd_fin = Fin} = State) when
            ?SEQ_LT(Una, Ack) andalso ?SEQ_LTE(Ack, Nxt) ->
    lager:info("TCP ACKed ~p-~p", [Una, Ack]),
    {Syn2, SndBuf2, Fin2, Ack} = aloha_tcp_seq:trim(Syn, SndBuf, Fin, Una, Ack),
    State2 = update_state_on_ack(Syn2 =/= Syn, Fin2 =/= Fin, State),
    State3 = State2#tcp_state{snd_una = Ack, snd_syn = Syn2, snd_buf = SndBuf2,
                              snd_fin = Fin2, snd_wnd = Wnd},
    State4 = process_writers(State3),
    tcp_output(State4);
process_ack(#tcp{ack = 0}, State) ->
    State;  % rst, (retransmitted) syn
process_ack(#tcp{ackno = Ack, window = Wnd} = Tcp,
            #tcp_state{snd_una = Ack, snd_wnd = Wnd} = State) ->
    lager:debug("dup ack ~p ~p", [pp(Tcp), pp(State)]),
    State;
process_ack(#tcp{ackno = Ack, window = Wnd} = Tcp,
            #tcp_state{snd_una = Ack} = State) ->
    lager:debug("pure window update ~p ~p", [pp(Tcp), pp(State)]),
    State#tcp_state{snd_wnd = Wnd};
process_ack(Tcp, State) ->
    lager:info("out of range ack ~p ~p", [pp(Tcp), pp(State)]),
    State.

update_mss(#tcp{syn = 0}, State) ->
    State;
update_mss(#tcp{options = Options}, #tcp_state{snd_mss = OldMSS} = State) ->
    MSS = proplists:get_value(mss, Options, ?DEFAULT_MSS),
    State#tcp_state{snd_mss = min(OldMSS, MSS)}.

update_sender(Tcp, State) ->
    State2 = process_ack(Tcp, State),
    update_mss(Tcp, State2).

established(#tcp_state{owner = Owner} = State) ->
    lager:info("connected ~p owner ~p", [self(), Owner]),
    % notify the listener socket process or connecting process
    Owner ! {aloha_tcp_connected, self_socket()},
    set_state(established, State).

set_state(New, State) ->
    lager:info("TCP ~p State ~p -> ~p", [self(), State#tcp_state.state, New]),
    State#tcp_state{state = New}.

% incoming ack
update_state_on_ack(true, _, #tcp_state{state = syn_received} = State) ->
    established(State);
update_state_on_ack(true, _, #tcp_state{state = syn_sent} = State) ->
    established(State);
update_state_on_ack(_, true, #tcp_state{state = fin_wait_1} = State) ->
    set_state(fin_wait_2, State);
update_state_on_ack(_, true, #tcp_state{state = closing} = State) ->
    set_state(time_wait, State);
update_state_on_ack(_, true, #tcp_state{state = last_ack} = State) ->
    set_state(closed, State);
update_state_on_ack(_, _, State) ->
    State.

% user close
update_state_on_close(State) ->
    set_state(next_state_on_close(State#tcp_state.state), State).

% incoming rst/syn/fin
update_state_on_flags(#tcp{rst = 1}, #tcp_state{} = State) ->
    lager:debug("closed on rst"),
    set_state(closed, State);
update_state_on_flags(#tcp{syn = 1, fin = 0},
                      #tcp_state{state = syn_sent} = State) ->
    set_state(syn_received, State);
update_state_on_flags(#tcp{syn = 1, fin = 0},
                      #tcp_state{state = closed} = State) ->
    set_state(syn_received, State#tcp_state{snd_syn = 1});
update_state_on_flags(#tcp{syn = 0, fin = 1},
                      #tcp_state{state = established} = State) ->
    State2 = set_state(close_wait, State),
    deliver_to_app({tcp_closed, self_socket()}, State2);
update_state_on_flags(#tcp{syn = 0, fin = 1},
                      #tcp_state{state = fin_wait_1} = State) ->
    State2 = set_state(closing, State),
    deliver_to_app({tcp_closed, self_socket()}, State2);
update_state_on_flags(#tcp{syn = 0, fin = 1},
                      #tcp_state{state = fin_wait_2} = State) ->
    State2 = set_state(time_wait, State),
    deliver_to_app({tcp_closed, self_socket()}, State2);
update_state_on_flags(_, State) ->
    State.

% in-window check  RFC 793 3.3. (p.26)
accept_check(#tcp{syn = 0}, _, #tcp_state{rcv_nxt = undefined}) ->
    false;
accept_check(#tcp{seqno = Seq} = Tcp, Data,
             #tcp_state{rcv_nxt = RcvNxt} = State) ->
    aloha_tcp_seq:accept_check(Seq, seg_len(Tcp, Data), RcvNxt, rcv_wnd(State)).

process_input(#tcp{} = Tcp, Data, State) ->
    case accept_check(Tcp, Data, State) of
        true ->
            {Tcp2, Data2} = trim(Tcp, Data, State),
            State2 = update_sender(Tcp2, State),
            State3 = update_state_on_flags(Tcp2, State2),
            update_receiver(Tcp2, Data2, State3);
        false ->
            lager:info("drop out of window segment ~p seg_len ~p state ~p",
                       [pp(Tcp), seg_len(Tcp, Data), pp(State)]),
            {true, State}
    end.

setup_ack(Nxt, #tcp_state{rcv_nxt = Nxt} = State) ->
    {false, State};
setup_ack(_Nxt, #tcp_state{delack_timer = undefined} = State) ->
    TRef = erlang:start_timer(?DELACK_TIMEOUT, self(), delack_timeout),
    State2 = State#tcp_state{delack_timer = TRef},
    {false, State2};
setup_ack(_Nxt, State) ->
    {true, cancel_delack(State)}.

cancel_delack(#tcp_state{delack_timer = undefined} = State) ->
    State;
cancel_delack(#tcp_state{delack_timer = TRef} = State) ->
    erlang:cancel_timer(TRef),
    State#tcp_state{delack_timer = undefined}.

update_receiver(#tcp{syn = 1, seqno = Seq}, <<>>,
                #tcp_state{rcv_nxt = undefined, state = TcpState} = State) ->
    true = TcpState =:= established orelse TcpState =:= syn_received,
    {true, State#tcp_state{rcv_nxt = Seq + 1}};
update_receiver(#tcp{seqno = Seq} = Tcp, Data,
                #tcp_state{rcv_nxt = Seq} = State) ->
    lager:debug("appending ~p bytes to rcv_buf ~p", [byte_size(Data), Data]),
    RcvBuf = <<(State#tcp_state.rcv_buf)/bytes, Data/bytes>>,
    Nxt = calc_next_seq(Tcp, Data),
    {AckNow, State2} = setup_ack(Nxt, State),
    State3 = State2#tcp_state{rcv_nxt = Nxt, rcv_buf = RcvBuf},
    {AckNow, State3};
update_receiver(_, _, State) ->
    % drop out of order segment
    {true, State}.

segment_arrival({#tcp{ack = 0, syn = 1} = Tcp, Data}, State)
        when Data =/= <<>> ->
    segment_arrival({Tcp, <<>>}, State);  % drop data on syn segment
segment_arrival({#tcp{ack = Ack, rst = Rst, syn = Syn} = Tcp, Data}, State) when
        Ack + Syn =/= 0 orelse Rst =:= 1 ->
    {AckNow, State2} = process_input(Tcp, Data, State),
    State3 = deliver_to_app(State2),
    State4 = process_readers(State3),
    State5 = tcp_output(AckNow, State4),
    noreply(State5);
segment_arrival({#tcp{} = Tcp, Data}, State) ->
    lager:info("TCP unimplemented datalen ~p~n~s", [byte_size(Data), pp(Tcp)]),
    noreply(State).

next_state_on_close(established) -> fin_wait_1;
next_state_on_close(syn_received) -> fin_wait_1;
next_state_on_close(syn_sent) -> closed;
next_state_on_close(close_wait) -> last_ack;
next_state_on_close(Other) -> Other.

% enqueue fin except the case of syn_sent -> closed
enqueue_fin(#tcp_state{state = closed} = State) ->
    State;
enqueue_fin(State) ->
    State#tcp_state{snd_fin = 1}.

rcv_buf_space(#tcp_state{rcv_buf_size = BufSize, rcv_buf = Buf}) ->
    max(0, BufSize - byte_size(Buf)).

rcv_wnd(#tcp_state{rcv_adv = undefined} = Tcp) ->
    rcv_buf_space(Tcp);
rcv_wnd(#tcp_state{rcv_nxt = Nxt, rcv_adv = Adv} = Tcp) ->
    max(rcv_buf_space(Tcp), ?SEQ(Adv - Nxt)).

% window size to advertise
% RFC 1122 4.2.3.3 receiver side SWS avoidance
choose_rcv_wnd(#tcp_state{rcv_adv = undefined} = State) ->
    rcv_buf_space(State);
choose_rcv_wnd(#tcp_state{rcv_nxt = Nxt, rcv_adv = Adv} = State) ->
    choose_rcv_wnd(rcv_buf_space(State), ?SEQ(Adv - Nxt), State).

choose_rcv_wnd(NextWnd, AdvWnd,
               #tcp_state{rcv_buf_size = BufSize, rcv_mss = MSS})
        when NextWnd - AdvWnd >= BufSize div 2 orelse
             NextWnd - AdvWnd >= MSS ->
    NextWnd;
choose_rcv_wnd(_, AdvWnd, _) ->
    AdvWnd.

tcp_output(State) ->
    tcp_output(false, State).

tcp_output(AckNow, State) ->
    tcp_output(false, AckNow, State).

to_send(#tcp_state{snd_una = Una, snd_nxt = Nxt, snd_syn = 1}) ->
    {S, D, F, _} = aloha_tcp_seq:trim(1, <<>>, 0, Una, Nxt),
    {S, D, F};
to_send(#tcp_state{snd_una = Una, snd_nxt = Nxt, snd_syn = Syn, snd_fin = Fin,
        snd_buf = Buf}) ->
    {S, D, F, _} = aloha_tcp_seq:trim(Syn, Buf, Fin, Una, Nxt),
    {S, D, F}.

tcp_output(CanProbe,
           AckNow,
           #tcp_state{snd_una = SndUna,
                      snd_nxt = SndNxt,
                      snd_wnd = SndWnd,
                      snd_mss = SMSS} = State) ->
    {Syn, Data, Fin} = to_send(State),
    % probe if
    %   1. window is closed
    %   2. nothing in-flight
    %   3. we have something to send (not idle)
    NeedProbe = CanProbe andalso SndWnd =:= 0 andalso SndUna =:= SndNxt andalso
        (Syn =:= 1 orelse Fin =:= 1 orelse Data =/= <<>>),
    SndWnd2 = case NeedProbe of
        true ->
            1;
        false ->
            min(max(SndUna + SndWnd - SndNxt, 0), SMSS)
    end,
    {Syn2, Data2, Fin2, SndNxt} =
        aloha_tcp_seq:trim(Syn, Data, Fin, SndNxt, SndNxt, SndNxt + SndWnd2),
    case AckNow orelse Syn2 =:= 1 orelse Fin2 =:= 1 orelse Data2 =/= <<>> of
        true ->
            State2 = cancel_delack(State),
            State3 = build_and_send_packet(Syn2, Data2, Fin2, State2),
            State4 = might_renew_timer(true, NeedProbe, State3),
            tcp_output(State4);  % burst transmit
        _ ->
            might_renew_timer(false, NeedProbe, State)
    end.

renew_timer(Timeout, Msg, State) ->
    lager:debug("renew timer ~p", [Msg]),
    erlang:cancel_timer(State#tcp_state.rexmit_timer),
    TRef = erlang:start_timer(Timeout, self(), Msg),
    State#tcp_state{rexmit_timer = TRef}.

might_renew_timer(false, false, State) ->
    State;
might_renew_timer(true, NeedProbe, State) ->
    {Timeout, Msg} = choose_timer(NeedProbe, State#tcp_state.state),
    renew_timer(Timeout, Msg, State).

choose_timer(_, time_wait) ->
    % we have sent ack of fin.
    {?TIME_WAIT_TIMEOUT, time_wait_timer};
choose_timer(true, _) ->
    {?PERSIST_TIMEOUT, persist_timer};
choose_timer(false, _) ->
    {?REXMIT_TIMEOUT, rexmit_timer}.

push(_, _, 1, _) -> 1;
push(1, _, _, _) -> 1;
push(_, Data, _, #tcp_state{snd_una = Una, snd_nxt = Nxt, snd_buf = Buf})
    when ?SEQ(Nxt - Una) + byte_size(Data) =:= byte_size(Buf) -> 1;
push(_, _, _, _) -> 0.

build_and_send_packet(Syn, Data, Fin,
                      #tcp_state{snd_nxt = SndNxt,
                                 rcv_nxt = RcvNxt,
                                 backend = Backend,
                                 rcv_mss = RMSS,
                                 template = [Ether, Ip, TcpTmpl],
                                 namespace = NS} = State) ->
    Win = choose_rcv_wnd(State),
    {Ack, Ackno, Adv} = case RcvNxt of
        undefined -> {0, 0, undefined};
        V ->         {1, V, ?SEQ(V + Win)}
    end,
    Tcp = TcpTmpl#tcp{
        seqno = SndNxt,
        ackno = Ackno,
        syn = Syn,
        fin = Fin,
        ack = Ack,
        psh = push(Syn, Data, Fin, State),
        window = Win,
        options = [{mss, RMSS} || Syn =:= 1]
    },
    lager:debug("TCP send datalen ~p~n~p~n~p",
                [byte_size(Data), pp(Tcp), pp(State)]),
    Pkt = [Ether, Ip, Tcp, Data],
    aloha_tcp:send_packet(Pkt, NS, Backend),
    State#tcp_state{snd_nxt = calc_next_seq(Tcp, Data), rcv_adv = Adv}.

should_exit(#tcp_state{state = closed, owner = none}) ->
    true;
should_exit(_) ->
    false.

should_hibernate(#tcp_state{state = time_wait}) ->
    true;
should_hibernate(_) ->
    false.

%%%%%%%%%%%%%%%%%%%% user interface %%%%%%%%%%%%%%%%%%%%

self_socket() ->
    {aloha_socket, self()}.

%% controlling_process

% why this needs to be this complicate?  to avoid races in the following
% rather common code fragment.
%
%   accept_loop(LSock) ->
%       Sock = accept(LSock),
%       Pid = spawn(?MODULE, child, [Sock]),
%       controlling_process(Sock, Pid),
%       accept_loop(LSock).
%   child(Sock) ->
%       setopts(Sock, [{active, once}]),
%       ...
%
% the problem is, setopts can be executed before controlling_process and
% it makes the socket to send messages to the wrong process.
% i'd call this a bad api, but we need this workaround because it's done
% by gen_tcp, which we want to behave similarly with.
controlling_process({aloha_socket, Pid} = Sock, NewOwner) ->
    {OldOwner, _} = gen_server:call(Pid, get_owner_info),
    controlling_process(Sock, OldOwner, NewOwner).

controlling_process({aloha_socket, Pid} = Sock, OldOwner, NewOwner)
        when OldOwner =:= self() ->
    lager:info("~p change owner ~p -> ~p", [Sock, OldOwner, NewOwner]),
    % temporarily make the socket suppress sending messages
    % to preserve the message ordering.  we don't use ordinary
    % setopt {active, false} because it can interfere with other processes.
    % XXX i don't understand why otp inet.erl can just use {active, false}.
    {ok, false} = gen_server:call(Pid, {set_suppress, true}),
    ok = gen_server:call(Pid, {controlling_process, NewOwner}),
    % at this point all messages previously sent from the socket to us
    % are in our mailbox.  move them to the new owner.
    ok = move_messages(Sock, NewOwner),
    {ok, true} = gen_server:call(Pid, {set_suppress, false}),
    ok;
controlling_process(Sock, OldOwner, NewOwner) ->
    lager:info("not_owner ~p ~p ~p ~p", [self(), Sock, OldOwner, NewOwner]),
    {error, not_owner}.

% transfer already received messages from the old controlling process
% (self()) to the new controlling process.
move_messages(Sock, NewOwner) ->
    receive
        {tcp_closed, Sock} = M -> move_message(M, Sock, NewOwner);
        {tcp, Sock, _} = M -> move_message(M, Sock, NewOwner)
    after 0 ->
        ok
    end.

move_message(M, Sock, NewOwner) ->
    lager:info("moving tcp message ~p to ~p", [M, NewOwner]),
    NewOwner ! M,
    move_messages(Sock, NewOwner).

%% async messages ({active, true} stuff)

deliver_to_app(#tcp_state{active = false} = State) ->
    State;
deliver_to_app(#tcp_state{suppress = true} = State) ->
    State;
deliver_to_app(#tcp_state{rcv_buf = <<>>, owner = Pid,
                          pending_ctl = [Msg|Rest]} = State) ->
    Pid ! Msg,
    deliver_to_app(State#tcp_state{pending_ctl = Rest});
deliver_to_app(#tcp_state{rcv_buf = <<>>} = State) ->
    State;
deliver_to_app(#tcp_state{rcv_buf = RcvBuf, owner = Pid,
                          active = Mode} = State) ->
    % mimic inet {deliver, term}
    Pid ! {tcp, self_socket(), RcvBuf},
    NextMode = case Mode of
        once -> false;
        true -> true
    end,
    deliver_to_app(State#tcp_state{rcv_buf = <<>>, active = NextMode}).

deliver_to_app(Msg, #tcp_state{pending_ctl = Q} = State) ->
    State#tcp_state{pending_ctl = Q ++ [Msg]}.

%% send/recv common

append_data(SndBuf, SndBufSize, Data) when
      byte_size(SndBuf) + byte_size(Data) =< SndBufSize ->
    {<<SndBuf/bytes, Data/bytes>>, <<>>};
append_data(SndBuf, SndBufSize, Data) ->
    Left = SndBufSize - byte_size(SndBuf),
    <<ToAdd:Left/bytes, Rest/bytes>> = Data,
    {<<SndBuf/bytes, ToAdd/bytes>>, Rest}.

process_users(State) ->
    State2 = process_readers(State),
    process_writers(State2).

%% send

add_writer(Writer, #tcp_state{writers = Writers} = State) ->
    State#tcp_state{writers = Writers ++ [Writer]}.

process_writers(#tcp_state{writers = []} = State) ->
    State;
process_writers(#tcp_state{writers = [{From, _}|Rest],
                           state = TcpState} = State) when
        TcpState =:= fin_wait_1 orelse TcpState =:= fin_wait_2 orelse
        TcpState =:= closing orelse TcpState =:= time_wait orelse
        TcpState =:= last_ack orelse TcpState =:= closed ->
    gen_server:reply(From, {error, closed}),
    process_writers(State#tcp_state{writers = Rest});
process_writers(#tcp_state{snd_buf = SndBuf,
                           snd_buf_size = SndBufSize} = State) when
       byte_size(SndBuf) >= SndBufSize ->
    State;
process_writers(#tcp_state{snd_buf = SndBuf,
                           snd_buf_size = SndBufSize,
                           writers = Writers} = State) ->
    [{From, Data}|Rest] = Writers,
    {SndBuf2, Data2} = append_data(SndBuf, SndBufSize, Data),
    case Data2 of
        <<>> ->
            State2 = State#tcp_state{snd_buf = SndBuf2, writers = Rest},
            gen_server:reply(From, ok),
            process_writers(State2);
        _ ->
            State#tcp_state{snd_buf = SndBuf2, writers = [{From, Data2}|Rest]}
    end.

%% recv

process_readers(#tcp_state{reader = none} = State) ->
    State;
process_readers(#tcp_state{rcv_buf = <<>>,
                           reader = {TRef, From, _, Data},
                           state = TcpState} = State) when
       TcpState =:= close_wait orelse TcpState =:= last_ack orelse
       TcpState =:= closing orelse TcpState =:= time_wait orelse
       TcpState =:= closed ->
    case Data of
        <<>> ->
            lager:info("TCP user read result closed"),
            lager:debug("closed ~p", [pp(State)]),
            gen_server:reply(From, {error, closed});
        Partial ->
            reply_data(TRef, From, Partial)
    end,
    State2 = State#tcp_state{reader = none},
    process_readers(State2);
process_readers(#tcp_state{rcv_buf = <<>>} = State) ->
    State;
process_readers(#tcp_state{reader = {TRef, From, 0, Data},
                           rcv_buf = RcvBuf} = State) ->
    Data = <<>>,
    reply_data(TRef, From, RcvBuf),
    State2 = State#tcp_state{rcv_buf = <<>>, reader = none},
    process_readers(State2);
process_readers(#tcp_state{reader = {TRef, From, Len, Data},
                           rcv_buf = RcvBuf} = State) ->
    {Data2, RcvBuf2} = append_data(Data, Len, RcvBuf),
    State2 = State#tcp_state{rcv_buf = RcvBuf2},
    State3 = case byte_size(Data2) =:= Len of
        true ->
            reply_data(TRef, From, Data2),
            State2#tcp_state{reader = none};
        false ->
            State2#tcp_state{reader = {TRef, From, Len, Data2}}
    end,
    process_readers(State3).

reply_data(TRef, From, Data) ->
    lager:info("TCP user read result datalen ~p", [byte_size(Data)]),
    cancel_reader_timeout(TRef),
    gen_server:reply(From, {ok, Data}).

cancel_reader_timeout(none) ->
    none;
cancel_reader_timeout(TRef) ->
    erlang:cancel_timer(TRef).

setup_reader_timeout(infinity) ->
    none;
setup_reader_timeout(Timeout) ->
    erlang:start_timer(Timeout, self(), reader_timeout).

%% shutdown

shutdown_receiver(State) ->
    % just close the receive window.
    % XXX keeping window closed makes us refuse accepting fin.
    % rcv_adv masks the problem in the common cases, though.
    % (it's what linux does.)
    State2 = State#tcp_state{rcv_buf = <<>>, rcv_buf_size = 0},
    tcp_output(State2).

shutdown_sender(State) ->
    State2 = update_state_on_close(State),
    State3 = process_users(State2),
    State4 = enqueue_fin(State3),
    tcp_output(State4).

%% close

close(State) ->
    State2 = shutdown_receiver(State),
    State3 = shutdown_sender(State2),
    unlink(State3#tcp_state.owner),
    State3#tcp_state{owner = none}.

%% setopt

setopt({packet, raw}, State) ->
    State;
setopt({nodelay, true}, State) ->
    State;
setopt({binary, true}, State) ->
    State;
setopt({active, Mode}, State) ->
    State#tcp_state{active = Mode};
setopt(Opt, _State) ->
    lager:info("unsupported setopts ~p", [Opt]),
    {error, einval}.

setopts([], {error, _} = E, Orig) ->
    {E, Orig};
setopts([], State, _Orig) ->
    {ok, State};
setopts([H|Rest], State, Orig) ->
    setopts(Rest, setopt(H, State), Orig).

setopts(Opts, State) ->
    setopts(Opts, State, State).

%% misc

pp(#tcp_state{rcv_buf = RcvBuf, snd_buf = SndBuf,
              writers = Writers, reader = Reader} = State) ->
    aloha_utils:pr(State#tcp_state{rcv_buf = byte_size(RcvBuf),
                                   snd_buf = byte_size(SndBuf),
                                   writers = length(Writers),
                                   reader = Reader =/= none}, ?MODULE);
pp(X) ->
    aloha_utils:pr(X, ?MODULE).
