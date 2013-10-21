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

-module(aloha_socket).

-export([listen/2, accept/1]).
-export([controlling_process/2, setopts/2, getopts/2,
         send/2, recv/2, recv/3, close/1,
         shutdown/2, peername/1, sockname/1]).
-export([force_close/1]).

listen(Port, Opts) ->
    lager:debug("aloha_socket:listen ~p ~p", [Port, Opts]),
    aloha_tcp:listen(Port, Opts).

accept({aloha_socket, SockPid}) ->
    call(SockPid, accept);
accept(Sock) ->
    gen_tcp:accept(Sock).

controlling_process({aloha_socket, _SockPid} = Sock, Pid) ->
    aloha_tcp_conn:controlling_process(Sock, Pid);
controlling_process(Sock, Pid) ->
    gen_tcp:controlling_process(Sock, Pid).

setopts({aloha_socket, SockPid}, Opts) ->
    call(SockPid, {setopts, Opts});
setopts(Sock, Opts) ->
    inet:setopts(Sock, Opts).

getopts({aloha_socket, SockPid}, Opts) ->
    call(SockPid, {getopts, Opts});
getopts(Sock, Opts) ->
    inet:getopts(Sock, Opts).

send({aloha_socket, SockPid}, Data) ->
    call(SockPid, {send, iolist_to_binary(Data)});
send(Sock, Data) ->
    gen_tcp:send(Sock, Data).

recv({aloha_socket, SockPid}, Len) ->
    call(SockPid, {recv, Len, infinity});
recv(Sock, Len) ->
    gen_tcp:recv(Sock, Len).

recv({aloha_socket, SockPid}, Len, Timeout) ->
    call(SockPid, {recv, Len, Timeout});
recv(Sock, Len, Timeout) ->
    gen_tcp:recv(Sock, Len, Timeout).

close({aloha_socket, SockPid}) ->
    call(SockPid, close);
close(Sock) ->
    gen_tcp:close(Sock).

shutdown({aloha_socket, SockPid}, write) ->
    gen_server:cast(SockPid, {shutdown, write});
shutdown({aloha_socket, SockPid}, read) ->
    gen_server:cast(SockPid, {shutdown, read});
shutdown({aloha_socket, _} = Sock, read_write) ->
    shutdown(Sock, read),
    shutdown(Sock, write);
shutdown(Sock, How) ->
    gen_tcp:shutdown(Sock, How).

peername({aloha_socket, SockPid}) ->
    call(SockPid, peername);
peername(Sock) ->
    inet:peername(Sock).

sockname({aloha_socket, SockPid}) ->
    call(SockPid, sockname);
sockname(Sock) ->
    inet:sockname(Sock).

force_close({aloha_socket, SockPid}) ->
    call(SockPid, force_close).

call(Pid, Req) ->
    try
        gen_server:call(Pid, Req, infinity)
    catch
        exit:{noproc, Reason} ->
            lager:info("~p exit noproc reason ~p", [Pid, Reason]),
            {error, closed};
        exit:{normal, Reason} ->
            lager:info("~p exit normal reason ~p", [Pid, Reason]),
            {error, closed};
        exit:Reason ->
            lager:info("~p exit reason ~p", [Pid, Reason]),
            {error, closed}
    end.
