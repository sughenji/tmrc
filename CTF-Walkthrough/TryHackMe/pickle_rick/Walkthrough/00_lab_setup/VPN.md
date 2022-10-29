```
joshua@kaligra:~/Downloads$ sudo openvpn sughenji.ovpn
2022-10-29 11:42:39 DEPRECATED OPTION: --cipher set to 'AES-256-CBC' but missing in --data-ciphers (AES-256-GCM:AES-128-GCM). Future OpenVPN version will ignore --cipher for cipher negotiati
ons. Add 'AES-256-CBC' to --data-ciphers or change --cipher 'AES-256-CBC' to --data-ciphers-fallback 'AES-256-CBC' to silence this warning.
2022-10-29 11:42:39 OpenVPN 2.5.7 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on Jul  5 2022
2022-10-29 11:42:39 library versions: OpenSSL 3.0.5 5 Jul 2022, LZO 2.10
..
2022-10-29 11:42:40 net_addr_v4_add: 10.9.10.198/16 dev tun0
2022-10-29 11:42:40 net_route_v4_add: 10.10.0.0/16 via 10.9.0.1 dev [NULL] table 0 metric 1000
2022-10-29 11:42:40 WARNING: this configuration may cache passwords in memory -- use the auth-nocache option to prevent this
2022-10-29 11:42:40 Initialization Sequence Completed

```

```
joshua@kaligra:~/Documents/thm$ ping -c 3 10.10.104.194
PING 10.10.104.194 (10.10.104.194) 56(84) bytes of data.
64 bytes from 10.10.104.194: icmp_seq=1 ttl=63 time=72.1 ms
64 bytes from 10.10.104.194: icmp_seq=2 ttl=63 time=55.9 ms
64 bytes from 10.10.104.194: icmp_seq=3 ttl=63 time=55.6 ms

--- 10.10.104.194 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2010ms
rtt min/avg/max/mdev = 55.561/61.190/72.092/7.710 ms

```



