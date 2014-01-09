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

Implemented features
--------------------
- Basic gen_tcp/inet-like API
- TCP
    - Active and Passive connections
    - Retransmit
    - Delayed ACK
    - RTT estimate
    - MD5 signature
- IP
    - ARP
    - ICMP
- IPv6
    - NDP
    - ICMPv6
- Virtual NIC

TODO
----

- user timeout
- rto backoff
- exit_on_close
- urg
- sender sws avoidance
- ip fragment
- use gproc instead of raw ets tables?
- handle exiting processes in accept/read/write queues
- wscale option
- out of order segment queueing
- make aloha_nic a separate app
- send_timeout
- workaround ct_run failure on travis-ci
- ctlinput
- pmtu discovery
- udp
