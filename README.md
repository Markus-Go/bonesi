BoNeSi
======

**BoNeSi**, the DDoS Botnet Simulator is a Tool to simulate Botnet Traffic in a testbed environment on the wire. It is designed to study the effect of DDoS attacks.

_What traffic can be generated?_  
**BoNeSi** generates ICMP, UDP and TCP (HTTP) flooding attacks from a defined botnet size (different IP addresses). **BoNeSi** is highly configurable and rates, data volume, source IP addresses, URLs and other parameters can be configured.

_What makes it different from other tools?_  
There are plenty of other tools out there to spoof IP addresses with UDP and ICMP, but for TCP spoofing, there is no solution. **BoNeSi** is the first tool to simulate HTTP-GET floods from large-scale bot networks. **BoNeSi** also tries to avoid to generate packets with easy identifiable patterns (which can be filtered out easily).

_Where can I run **BoNeSi**?_  
We highly recommend to run **BoNeSi** in a closed testbed environment. However, UDP and ICMP attacks could be run in the internet as well, but you should be carefull. HTTP-Flooding attacks can not be simulated in the internet, because answers from the webserver must be routed back to the host running **BoNeSi**.

_How does TCP Spoofing work?_  
**BoNeSi** sniffs for TCP packets on the network interface and responds to all packets in order to establish TCP connections. For this feature, it is necessary, that all traffic from the target webserver is routed back to the host running **BoNeSi**

_How good is the perfomance of **BoNeSi**?_  
We focused very much on performance in order to simulate big botnets. On an AMD Opteron with 2Ghz we were able to generate up to 150,000 packets per second. On a more recent AMD Phenom II X6 1100T with 3.3Ghz you can generate 300,000 pps (running on 2 cores).

_Are **BoNeSi** attacks successful?_  
Yes, they are very successful. UDP/ ICMP attacks can easily fill the bandwidth and HTTP-Flooding attacks knock out webservers fast. We also tested **BoNeSi** against state-of-the-art commercial DDoS mitigation systems and where able to either crash them or hiding the attack from being detected.

<b>A demo video of BoNeSi in action can be found <a target="_blank" href='http://madm.dfki.de/projects/netcentricsecurity'>here</a>.</b>

Detailed Information
--------------------

BoNeSi is a network traffic generator for different protocol types.
The attributes of the created packets and connections can be controlled by
several parameters like send rate or payload size or they are determined by chance.
It spoofs the source ip addresses even when generating tcp traffic. Therefor it
includes a simple tcp-stack to handle tcp connections in promiscuous mode.
For correct work, one has to ensure that the response packets are routed to the
host at which BoNeSi is running. Therefore BoNeSi cannot used in arbitrary
network infrastructures.
The most advanced kind of traffic that can be generated are http requests.

**TCP/HTTP**
In order to make the http requests more realistic, several things are determined
by chance:
- source port
- ttl: 3..255
- tcp options: out of seven different real life options
               with different lengths and probabilities
- user agent for http header: out of a by file given list
                              (an example file is included, see below)


Copyright 2006-2007 Deutsches Forschungszentrum fuer Kuenstliche Intelligenz
This is free software. Licensed under the Apache License, Version 2.0.
There is NO WARRANTY, to the extent permitted by law.


Installation
------------

    :~$ ./configure
    :~$ make
    :~$ make install


Usage
-----

    :~$ bonesi [OPTION...] <dst_ip:port>
    
     Options:
    
      -i, --ips=FILENAME               filename with ip list
      -p, --protocol=PROTO             udp (default), icmp or tcp
      -r, --send_rate=NUM              packets per second, 0 = infinite (default)
      -s, --payload_size=SIZE          size of the paylod, (default: 32)
      -o, --stats_file=FILENAME        filename for the statistics, (default: 'stats')
      -c, --max_packets=NUM            maximum number of packets (requests at tcp/http), 0 = infinite (default)
          --integer                    IPs are integers in host byte order instead of in dotted notation
      -t, --max_bots=NUM               determine max_bots in the 24bit prefix randomly (1-256)
      -u, --url=URL                    the url (default: '/') (only for tcp/http)
      -l, --url_list=FILENAME          filename with url list (only for tcp/http)
      -b, --useragent_list=FILENAME    filename with useragent list (only for tcp/http)
      -d, --device=DEVICE              network listening device (only for tcp/http, e.g. eth1)
      -m, --mtu=NUM                    set MTU, (default 1500). Currently only when using TCP.
      -f, --frag=NUM                   set fragmentation mode (0=IP, 1=TCP, default: 0). Currently only when using TCP.
      -v, --verbose                    print additional debug messages
      -h, --help                       print help message and exit

  
Additionally Included Example Files
-----------------------------------

50k-bots
* 50,000 ip addresses generated randomly to use with --ips option
    
browserlist.txt
* several browser identifications to use with --useragentlist option
    
urllist.txt
* several urls to use with --urllist option

Copyright/ License/ Credits
---------------------------

Copyright 2006-2007 Deutsches Forschungszentrum fuer Kuenstliche Intelligenz  
Copyright 2008-2015 Markus Goldstein

This is free software. Licensed under the [Apache License, Version 2.0](LICENSE).  
There is NO WARRANTY, to the extent permitted by law.

![http://madm.dfki.de/lib/tpl/dfki/images/logo.jpg](http://madm.dfki.de/lib/tpl/dfki/images/logo.jpg)

