

# list commands

```
>>> lsc()
IPID_count          : Identify IP id values classes in a list of packets
arpcachepoison      : Poison target's cache with (your MAC,victim's IP) couple
arping              : Send ARP who-has requests to determine which hosts are up
arpleak             : Exploit ARP leak flaws, like NetBSD-SA2017-002.
bind_layers         : Bind 2 layers on some specific fields' values.
bridge_and_sniff    : Forward traffic between interfaces if1 and if2, sniff and return
chexdump            : Build a per byte hexadecimal representation
computeNIGroupAddr  : Compute the NI group Address. Can take a FQDN as input parameter
..
..
```


# read pcap file

```
>>> from scapy.all import *
>>> rdpcap("/home/sugo/github/tmrc/network_traffic_analysis/eternalblue.pcap")
<eternalblue.pcap: TCP:1420 UDP:0 ICMP:0 Other:0>
```

or

```
>>> from scapy.all import *
>>> packets = rdpcap("/home/sugo/github/tmrc/network_traffic_analysis/eternalblue.pcap")
>>> packets.summary
<bound method _PacketList.summary of <eternalblue.pcap: TCP:1420 UDP:0 ICMP:0 Other:0>>
```

# print detail of a packet

```
>>> pkts[0].show()
###[ Ethernet ]###
  dst       = 52:54:00:12:35:00
  src       = 08:00:27:2f:03:77
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 84
..
..
```

# print field of a packet

```
>>> pkts[0].load
b'{\xbf\x93b\x00\x00\x00\x00\xadm\x06\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567'
```

# print only icmp packet

```
>>> pkts.summary
<bound method _PacketList.summary of <esercitazione_20230529.pcapng: TCP:1464 UDP:0 ICMP:50 Other:9>>
>>> pkts[ICMP].summary()
Ether / IP / ICMP 10.0.2.8 > 10.0.2.5 echo-request 0 / Raw
Ether / IP / ICMP 10.0.2.5 > 10.0.2.8 echo-reply 0 / Raw
Ether / IP / ICMP 10.0.2.8 > 10.0.2.5 echo-request 0 / Raw
..
..
```

# print only icmp echo request

```
from scapy.all import *

pkts = rdpcap("onlyicmp.pcap")

for p in pkts:
    if p[ICMP].type == 8:
        print(p[ICMP].id)
```


# forge icmp

with root or sudo rights


```python
>>> from scapy.all import *
>>> pingr = IP(dst="46.252.144.172")/ICMP()
>>> sr1(pingr)
```

get response:

```python
>>> resp = sr1(pingr)
Begin emission:
..Finished to send 1 packets.
.*
Received 147 packets, got 1 answers, remaining 0 packets
>>> resp[0].summary()
'IP / ICMP 4.2.2.1 > 172.16.20.40 echo-reply 0 / Padding'
```
