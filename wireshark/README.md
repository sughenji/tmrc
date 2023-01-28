# Wireshark cheat sheet

- [List interfaces](#list-interfaces)
- [Capture and ring buffer](#capture-and-ring-buffer)
- [Capture with tshark](#capture-with-tshark)
- [Conversation filter](#conversation-filter)
- [Search for string](#search-for-string)
- [Resolved address](#resolved-address)
- [IP alias](#ip-alias)
- [Delta time](#delta-time)
- [Sample capture](#sample-capture)
- [DNS queries](#dns-queries)
- [SSL](#ssl)

Some useful tips from Chris Greer Masterclass https://www.youtube.com/playlist?list=PLW8bTPfXNGdC5Co0VnBK1yVzAwSSphzpJ and more!



## List interfaces

```
C:\Users\sugo>dumpcap -D
1. \Device\NPF_{771AE0CD-82C9-418D-85F9-C179AA3A2AAB} (Connessione alla rete locale (LAN)* 8)
2. \Device\NPF_{EFCC04D4-BCD4-4B23-BFAE-BA9E4AEE9F9C} (Connessione alla rete locale (LAN)* 7)
3. \Device\NPF_{5E1BA02D-9D6E-4E95-99A5-BFBE4DD7DEB4} (Connessione alla rete locale (LAN)* 6)
4. \Device\NPF_{D44A80DE-25DD-4888-9101-7D94296B8954} (VirtualBox Host-Only Network)
5. \Device\NPF_{974BD271-CC54-456C-8A14-661AD51E3F4F} (Ethernet)
6. \Device\NPF_Loopback (Adapter for loopback traffic capture)
7. \Device\NPF_{B9DC513E-DDB5-4956-82F7-2822A5F69349} (Ethernet 2)
8. \Device\NPF_{BD559BFB-A75F-41DA-BE84-DC44533A7B34} (Connessione alla rete locale (LAN))
```

## Capture and ring buffer

start collecting traffic in some folder, with some ring buffer of specified size:

```
C:\Users\sugo>dumpcap -i 5 -w d:\wireshark_capture\test.pcapng -b filesize:500000 -b files:10
```

## Capture with tshark

```
tshark.exe -b interval:3600 -b files:48 -f "port 53" -i Ethernet0 -w c:\users\sugo\desktop\traffic.pcapng
```


## Conversation filter

conversation filter (between two IPs)

![filter1](https://user-images.githubusercontent.com/42389836/150690077-f47711a5-c127-496b-9630-518ba00417bb.JPG)

or:

```
ip.addr eq 46.252.144.172 and ip.addr eq 192.168.88.14
```

only TCP:

```
(ip.addr eq 46.252.144.172 and ip.addr eq 192.168.88.14) and tcp
```

Port can be one of...:

```
tcp.port in {80 443 8080}
```

## Search for string

This is case sensitive:

```
frame contains Google
```

This is case insensitive:

```
frame matches google
```

## Resolved addresses

Statistics -> resolved addresses -> Host

## IP alias
How to assign a descriptive name to a private address:


![dns1](https://user-images.githubusercontent.com/42389836/150691352-62c1cbb0-ffc9-4353-bf77-bdd1dd9f4d0d.JPG)

## Delta time

View delta time in context (in same TCP stream)

![streamtcp](https://user-images.githubusercontent.com/42389836/151020481-6817afba-c0a6-46a1-b0ec-d1c9aacddfa9.JPG)

## Sample capture

https://gitlab.com/wireshark/wireshark/-/wikis/SampleCaptures

## DNS queries

```
dns.qry.name
```

## SSL

```
ssl.handshake.extensions_server_name
```





