aloha
=====

TCP/IP written in Erlang.

[![Build Status](https://travis-ci.org/yamt/aloha.png?branch=master)](https://travis-ci.org/yamt/aloha)

Goals
-----

- Provide connectivity
- Simplicity

Non goals
---------

- Performance

API
---

aloha provides an API similar to gen_tcp/inet.
See [aloha_demo](https://github.com/yamt/aloha_demo) for an example
to run cowboy/ranch on aloha.

TODO
----

- active open
- exit_on_close
- urg
- sws avoidance
- 2msl
- mss option
- ip/port namespace
- ip fragment
- timeout
- use gproc instead of raw ets tables?
