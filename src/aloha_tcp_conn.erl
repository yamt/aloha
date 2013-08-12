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

% todo
%  active open
%  checksum validation
%  exit_on_close
%  urg
%  delayed ack
%  sws avoidance
%  2msl
%  mss option
%  call process_readers/writers on state change

-module(aloha_tcp_conn).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).

-export([calc_next_seq/2, seg_len/2]).

-export([controlling_process/2]).

-include_lib("aloha_packet/include/aloha_packet.hrl").

-behaviour(gen_server).

-record(tcp_state, {snd_una, snd_nxt, snd_wnd, rcv_nxt, backend, template,
                    rexmit_timer,
                    snd_buf, snd_buf_size,
                    rcv_buf, rcv_buf_size,
                    state, owner, active = false, suppress = false,
                    pending_ctl = [], fin = 0, key,
                    writers = [], reader = none}).

% these are macros so that they can be used in guards.
-define(SEQ(S), ((S) band 16#ffffffff)).
-define(SEQ_LT(S1, S2), (?SEQ((S1) - (S2)) >= 16#80000000)).
-define(SEQ_LTE(S1, S2), (not ?SEQ_LT(S2, S1))).

-define(REXMIT_TIMEOUT, 1000).
-define(PERSIST_TIMEOUT, 3000).

pp(#tcp_state{snd_buf = SndBuf} = State) when is_binary(SndBuf) ->
    % XXX hack to make this less verbose
    pp(State#tcp_state{snd_buf = byte_size(State#tcp_state.snd_buf),
                       rcv_buf = byte_size(State#tcp_state.rcv_buf),
                       template = [], backend = []});
pp(Rec) ->
    io_lib_pretty:print(Rec, fun pp/2).

pp(tcp_state, _N) ->
    record_info(fields, tcp_state);
pp(tcp, _N) ->
    record_info(fields, tcp);
pp(_, _) ->
    no.

init(Opts) ->
    Backend = proplists:get_value(backend, Opts),
    Key = proplists:get_value(key, Opts),
    % XXX link
    State = #tcp_state{backend = Backend,
                       template = proplists:get_value(template, Opts),
                       snd_nxt = 0,  % ISS
                       snd_una = 0,  % ISS
                       rexmit_timer = make_ref(),
                       snd_buf = <<>>, snd_buf_size = 3000,
                       rcv_buf = <<>>, rcv_buf_size = 3000,
                       state = closed,
                       owner = proplists:get_value(owner, Opts),
                       key = Key},
    true = ets:insert_new(aloha_tcp_conn, {Key, self()}),
    lager:debug("init ~s", [pp(State)]),
    {ok, State}.

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

should_exit(#tcp_state{state = closed, owner = none}) ->
    true;
should_exit(_) ->
    false.

reply(Reply, State) ->
    reply(should_exit(State), Reply, State).

reply(true, Reply, State) ->
    {stop, normal, Reply, State};
reply(false, Reply, State) ->
    {reply, Reply, State}.

noreply(State) ->
    noreply(should_exit(State), State).

noreply(true, State) ->
    {stop, normal, State};
noreply(false, State) ->
    {noreply, State}.

handle_call({send, Data}, From, State) ->
    lager:info("TCP user write datalen ~p", [byte_size(Data)]),
    State2 = add_writer({From, Data}, State),
    State3 = process_writers(State2),
    noreply(State3);
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
    lager:info("TCP user read datalen ~p", [Len]),
    TRef = setup_reader_timeout(Timeout),
    State2 = State#tcp_state{reader = {TRef, From, Len, <<>>}},
    State3 = process_readers(State2),
    State4 = tcp_output(State3),
    noreply(State4);
handle_call(peername, _From, #tcp_state{template = Tmpl} = State) ->
    [_, #ip{dst = Addr}, #tcp{dst_port = Port}] = Tmpl,
    reply({ok, {aloha_utils:bytes_to_ip(Addr), Port}}, State);
handle_call(sockname, _From, #tcp_state{template = Tmpl} = State) ->
    [_, #ip{src = Addr}, #tcp{src_port = Port}] = Tmpl,
    reply({ok, {aloha_utils:bytes_to_ip(Addr), Port}}, State);
handle_call({controlling_process, Pid}, _From, State) ->
    true = State#tcp_state.suppress,  % assert.  see controlling_process/1
    State2 = State#tcp_state{owner = Pid},
    % XXX unlink/link here?
    reply(ok, State2);
handle_call(close, {Pid, _}, #tcp_state{owner = Pid} = State) ->
    lager:info("user close ~p", [self()]),
    State2 = State#tcp_state{owner = none},
    reply(ok, State2);
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

seq(S) -> S band 16#ffffffff.

trim(Tcp, Data, #tcp_state{rcv_nxt = undefined}) ->
    {Tcp, Data};
trim(#tcp{syn = Syn, fin = Fin, seqno = Seq} = Tcp, Data,
    #tcp_state{rcv_nxt = RcvNxt} = State) ->
    {Syn2, Data2, Fin2, Seq2} =
        trim(Syn, Data, Fin, Seq, RcvNxt, RcvNxt + rcv_wnd(State)),
    {Tcp#tcp{syn = Syn2, fin = Fin2, seqno = Seq2}, Data2}.

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
        when ?SEQ_LT(WinEnd, Seq + Syn + byte_size(Data) + 1) ->
    trim(Syn, Data, 0, Seq, WinStart, WinEnd);
trim(Syn, Data, 0, Seq, WinStart, WinEnd)
        when ?SEQ_LT(WinEnd, Seq + Syn + byte_size(Data)) ->
    Size = byte_size(Data),
    TakeSize = Size - seq(Seq + Syn + Size - WinEnd),
    <<Data2:TakeSize/bytes, _/bytes>> = Data,
    trim(Syn, Data2, 0, Seq, WinStart, WinEnd);
trim(Syn, Data, Fin, Seq, _WinStart, _WinEnd) ->
    {Syn, Data, Fin, Seq}.

trim(Syn, Data, Fin, Seq, WinStart) ->
    trim(Syn, Data, Fin, Seq, WinStart, WinStart + 999999).  % XXX

seg_len(#tcp{syn = Syn, fin = Fin}, Data) ->
    Syn + byte_size(Data) + Fin.

calc_next_seq(#tcp{seqno = Seq} = Tcp, Data) ->
    seq(Seq + seg_len(Tcp, Data)).

% advance SND.UNA and truncate send buffer
% SND.UNA < SEG.ACK =< SND.NXT
process_ack(#tcp{ack = 1, ackno = Ack},
            #tcp_state{snd_una = Una, snd_nxt = Nxt,
                       snd_buf = SndBuf, fin = Fin} = State) when
            ?SEQ_LT(Una, Ack) andalso ?SEQ_LTE(Ack, Nxt) ->
    lager:info("TCP ACKed ~p-~p", [Una, Ack]),
    Syn = una_syn(State),
    {Syn2, SndBuf2, Fin2, Ack} = trim(Syn, SndBuf, Fin, Una, Ack),
    State2 = update_state_on_ack(Syn2 =/= Syn, Fin2 =/= Fin, State),
    State3 = State2#tcp_state{snd_una = Ack, snd_buf = SndBuf2, fin = Fin2},
    process_writers(State3);
process_ack(#tcp{ack = 0}, State) ->
    State;  % rst, (retransmitted) syn
process_ack(#tcp{ack = 1} = Tcp, State) ->
    lager:debug("out of range ack~n~s~n~s", [pp(Tcp), pp(State)]),
    State.

update_sender(Tcp, State) ->
    State2 = process_ack(Tcp, State),
    State2#tcp_state{snd_wnd = Tcp#tcp.window}.

una_syn(#tcp_state{state = syn_received}) -> 1;
una_syn(#tcp_state{state = syn_sent}) -> 1;
una_syn(_) -> 0.

established(#tcp_state{owner = Owner} = State) ->
    lager:info("connected ~p owner ~p", [self(), Owner]),
    ok = gen_server:cast(Owner, {tcp_connected, self_socket()}),
    State#tcp_state{state = established}.

update_state_on_ack(true, _, #tcp_state{state = syn_received} = State) ->
    established(State);
update_state_on_ack(true, _, #tcp_state{state = syn_sent} = State) ->
    established(State);
update_state_on_ack(_, true, #tcp_state{state = fin_wait_1} = State) ->
    State#tcp_state{state = fin_wait_2};
update_state_on_ack(_, true, #tcp_state{state = closing} = State) ->
    State#tcp_state{state = time_wait};
update_state_on_ack(_, true, #tcp_state{state = last_ack} = State) ->
    State#tcp_state{state = closed};
update_state_on_ack(_, _, State) ->
    State.

update_state_on_close(State) ->
    State#tcp_state{state = next_state_on_close(State#tcp_state.state)}.

update_state(#tcp{rst = 1}, #tcp_state{} = State) ->
    lager:debug("closed on rst"),
    State#tcp_state{state = closed};
update_state(#tcp{syn = 1, fin = 0}, #tcp_state{state = closed} = State) ->
    State#tcp_state{state = syn_received};
update_state(#tcp{syn = 0, fin = 1}, #tcp_state{state = established} = State) ->
    State2 = State#tcp_state{state = close_wait},
    deliver_to_app({tcp_closed, self_socket()}, State2);
update_state(_, State) ->
    State.

seq_between(S1, S2, S3) ->
    ?SEQ_LTE(S1, S2) andalso ?SEQ_LT(S2, S3).

% in-window check  RFC 793 3.3. (p.26)
accept_check(#tcp{seqno = Seq} = Tcp, Data,
             #tcp_state{rcv_nxt = RcvNxt} = State) ->
    accept_check(Seq, seg_len(Tcp, Data), RcvNxt, rcv_wnd(State)).

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

process_input(#tcp{} = Tcp, Data, State) ->
    case accept_check(Tcp, Data, State) of
        true ->
            {Tcp2, Data2} = trim(Tcp, Data, State),
            State2 = update_sender(Tcp2, State),
            State3 = update_state(Tcp2, State2),
            update_receiver(Tcp2, Data2, State3);
        false ->
            % out of window
            {true, State}
    end.

update_receiver(#tcp{syn = 1, seqno = Seq}, <<>>,
                #tcp_state{rcv_nxt = undefined,
                           state = syn_received} = State) ->
    {true, State#tcp_state{rcv_nxt = Seq + 1}};
update_receiver(#tcp{seqno = Seq} = Tcp, Data,
                #tcp_state{rcv_nxt = Seq} = State) ->
    RcvBuf = <<(State#tcp_state.rcv_buf)/bytes, Data/bytes>>,
    Nxt = calc_next_seq(Tcp, Data),
    AckNow = State#tcp_state.rcv_nxt =/= Nxt,
    State2 = State#tcp_state{rcv_nxt = Nxt, rcv_buf = RcvBuf},
    {AckNow, State2};
update_receiver(_, _, State) ->
    % drop out of order segment
    {true, State}.

segment_arrival({#tcp{ack = 0, rst = 0, syn = 1, fin = 0} = Tcp, Data},
                State) when
        Data =/= <<>> ->
    segment_arrival({Tcp, <<>>}, State);  % drop data on syn segment
segment_arrival({#tcp{ack = Ack, rst = Rst, syn = Syn} = Tcp, Data}, State) when
        Ack + Syn =:= 1 orelse Rst =:= 1 ->
    {AckNow, State2} = process_input(Tcp, Data, State),
    State3 = deliver_to_app(State2),
    State4 = process_readers(State3),
    State5 = tcp_output(AckNow, State4),
    noreply(State5);
segment_arrival({#tcp{} = Tcp, Data}, State) ->
    lager:info("TCP unimplemented datalen ~p~n~s", [byte_size(Data), pp(Tcp)]),
    noreply(State).

next_state_on_close(established) -> true, fin_wait_1;
next_state_on_close(syn_received) -> fin_wait_1;
next_state_on_close(syn_sent) -> closed;
next_state_on_close(close_wait) -> last_ack.

% enqueue fin except the case of syn_sent -> closed
enqueue_fin(closed, State) ->
    State;
enqueue_fin(_, State) ->
    State#tcp_state{fin = 1}.

handle_cast({#tcp{}, _} = Msg, State) ->
    segment_arrival(Msg, State);
handle_cast({shutdown, read}, State) ->
    State2 = shutdown_receiver(State),
    noreply(State2);
handle_cast({shutdown, write}, State) ->
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
handle_info({timeout, TRef, Name},
            #tcp_state{snd_una = Una, rexmit_timer = TRef} = State) ->
    lager:info("timer expired ~p", [Name]),
    State2 = State#tcp_state{snd_nxt = Una},
    State3 = tcp_output(true, false, State2),
    noreply(State3);
handle_info(Info, State) ->
    lager:info("handle_info: ~w", [Info]),
    noreply(State).

terminate(Reason, #tcp_state{key = Key} = State) ->
    lager:debug("conn process terminate ~p~n~s", [Reason, pp(State)]),
    true = ets:delete(aloha_tcp_conn, Key),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

self_socket() ->
    {aloha_socket, self()}.

rcv_wnd(#tcp_state{rcv_buf_size = RcvBufSize, rcv_buf = RcvBuf}) ->
    max(0, RcvBufSize - byte_size(RcvBuf)).

renew_timer(Timeout, Msg, State) ->
    erlang:cancel_timer(State#tcp_state.rexmit_timer),
    TRef = erlang:start_timer(Timeout, self(), Msg),
    State#tcp_state{rexmit_timer = TRef}.

tcp_output(State) ->
    tcp_output(false, State).

tcp_output(AckNow, State) ->
    tcp_output(false, AckNow, State).

tcp_output(CanProbe,
           AckNow,
           #tcp_state{snd_una = SndUna,
                      snd_nxt = SndNxt,
                     snd_wnd = SndWnd,
                     rcv_nxt = RcvNxt,
                     backend = Backend,
                     template = [Ether, Ip, TcpTmpl],
                     snd_buf = SndBuf} = State) ->
    {Syn, Data, Fin} = case State#tcp_state.state of
        closed ->
            {0, <<>>, 0};
        syn_received when SndUna =:= SndNxt ->
            {1, <<>>, 0};
        syn_received ->
            {0, <<>>, 0};
        _ ->
            {S, D, F, _} = trim(0, SndBuf, State#tcp_state.fin, SndUna, SndNxt),
            {S, D, F}
    end,
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
            MSS = 576 - 20 - 20,  % default MSS as per RFC 879 and RFC 1122
            min(SndWnd, MSS)
    end,
    {Syn2, Data2, Fin2, SndNxt} =
        trim(Syn, Data, Fin, SndNxt, SndNxt, SndNxt + SndWnd2),
    case AckNow orelse Syn2 =:= 1 orelse Fin2 =:= 1 orelse Data2 =/= <<>> of
        true ->
            Psh = 0, % XXX
            Tcp = TcpTmpl#tcp{
                seqno = SndNxt,
                ackno = RcvNxt,
                syn = Syn2,
                fin = Fin2,
                ack = 1,
                psh = Psh,
                window = rcv_wnd(State),
                options = <<>>
            },
            Pkt = [
                Ether,
                Ip,
                Tcp,
                Data2
            ],
            lager:debug("TCP send datalen ~p~n~s~n~s",
                       [byte_size(Data2), pp(Tcp), pp(State)]),
            aloha_tcp:send_packet(Pkt, Backend),
            State2 = case NeedProbe of
                true ->
                    renew_timer(?PERSIST_TIMEOUT, persist_timer, State);
                false ->
                    renew_timer(?REXMIT_TIMEOUT, rexmit_timer, State)
            end,
            State3 = State2#tcp_state{snd_nxt = calc_next_seq(Tcp, Data2)},
            tcp_output(State3);  % burst transmit
        _ ->
            case NeedProbe of
                true ->
                    renew_timer(?PERSIST_TIMEOUT, persist_timer, State);
                false ->
                    State
            end
    end.

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
                          active = once} = State) ->
    % mimic inet {deliver, term}
    Pid ! {tcp, self_socket(), RcvBuf},
    deliver_to_app(State#tcp_state{rcv_buf = <<>>, active = false}).

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
    gen_server:reply(From, {ok, closed}),
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
            State3 = tcp_output(State2),
            gen_server:reply(From, ok),
            process_writers(State3);
        _ ->
            State#tcp_state{snd_buf = SndBuf2, writers = [{From, Data2}|Rest]}
    end.

%% recv

process_readers(#tcp_state{reader = none} = State) ->
    State;
process_readers(#tcp_state{reader = {_, From, _, _},
                           state = TcpState} = State) when
       TcpState =:= close_wait orelse TcpState =:= last_ack orelse
       TcpState =:= closing orelse TcpState =:= time_wait orelse
       TcpState =:= closed ->
    gen_server:reply(From, {error, closed}),
    State2 = State#tcp_state{reader = none},
    process_readers(State2);
process_readers(#tcp_state{rcv_buf = <<>>} = State) ->
    State;
process_readers(#tcp_state{reader = {_, From, 0, Data},
                           rcv_buf = RcvBuf} = State) when RcvBuf =/= <<>> ->
    Data = <<>>,
    lager:debug("process_reader ~p ~p ~p", [From, Data, RcvBuf]),
    gen_server:reply(From, {ok, RcvBuf}),
    State2 = State#tcp_state{rcv_buf = <<>>, reader = none},
    process_readers(State2);
process_readers(#tcp_state{reader = {TRef, From, Len, Data},
                           rcv_buf = RcvBuf} = State) ->
    {Data2, RcvBuf2} = append_data(Data, Len, RcvBuf),
    State2 = State#tcp_state{rcv_buf = RcvBuf2},
    State3 = case byte_size(Data2) =:= Len of
        true ->
            gen_server:reply(From, {ok, Data2}),
            State2#tcp_state{reader = none};
        false ->
            State2#tcp_state{reader = {TRef, From, Len, Data2}}
    end,
    process_readers(State3).

setup_reader_timeout(infinity) ->
    none;
setup_reader_timeout(Timeout) ->
    erlang:start_timer(Timeout, self(), reader_timeout).

%% shutdown

shutdown_receiver(State) ->
    State2 = State#tcp_state{rcv_buf = <<>>, rcv_buf_size = 0},
    tcp_output(State2).

shutdown_sender(State) ->
    State2 = update_state_on_close(State),
    State3 = enqueue_fin(State2#tcp_state.state, State2),
    tcp_output(State3).

%% debug

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

simple_test() ->
    {1, <<"hoge">>, 1, 100} = trim(1, <<"hoge">>, 1, 100, 100, 106),
    {0, <<"hoge">>, 1, 101} = trim(1, <<"hoge">>, 1, 100, 101, 106),
    {0, <<"oge">>, 1, 102} = trim(1, <<"hoge">>, 1, 100, 102, 106),
    {1, <<"hoge">>, 0, 100} = trim(1, <<"hoge">>, 1, 100, 100, 105),
    {1, <<"hog">>, 0, 100} = trim(1, <<"hoge">>, 1, 100, 100, 104),
    {0, <<"og">>, 0, 102} = trim(1, <<"hoge">>, 1, 100, 102, 104),
    {0, <<>>, 1, 105} = trim(1, <<"hoge">>, 1, 100, 105, 106),
    {0, <<>>, 0, 106} = trim(1, <<"hoge">>, 1, 100, 106, 106).

-endif.
