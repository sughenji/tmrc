# Network Traffic Analysis

- [Snort](#snort)
- [Eternalblue](#eternalblue)
- [Emotet](#emotet)
- [Looking for malware activity](#looking-for-malware-activity)
- [General info on host](#general-info-on-host)
- [tshark-fu](#tshark-fu)
- [Capture with pktmon](#capture-with-pktmon)

## snort

**config file is now in .lua extension**

### test configuration file

```bash
$ snort -T -c /etc/snort/snort.lua
--------------------------------------------------
o")~   Snort++ 3.1.82.0
--------------------------------------------------
Loading /etc/snort/snort.lua:
Loading snort_defaults.lua:
Finished snort_defaults.lua:
        ips
        classifications
        references
        appid
..
..
..
Snort successfully validated the configuration (with 0 warnings).
o")~   Snort exiting
```

### dump pcap to console

(`-q` to suppress statistics)  
```bash
$ snort -r test.pcap -L dump
--------------------------------------------------
o")~   Snort++ 3.1.82.0
--------------------------------------------------
--------------------------------------------------
pcap DAQ configured to read-file.
Commencing packet processing
++ [0] test.pcap
pkt:1
eth(DLT):  08:00:27:2F:03:77 -> 78:24:AF:3C:D4:C2  type:0x0800
ipv4(0x0800):  192.168.88.28 -> 192.168.88.14
        Next:0x06 TTL:64 TOS:0x10 ID:51594 IpLen:20 DgmLen:184 DF
..
..
..    
```

### dump live traffic

```bash
$ snort -i eth0 -L dump
--------------------------------------------------
o")~   Snort++ 3.1.82.0
--------------------------------------------------
--------------------------------------------------
pcap DAQ configured to passive.
Commencing packet processing
..
..
```

### read pcap with application data and layer 2 headers

```bash
$ snort -q -r test.pcap -L dump -d -e
```

### a simple test rule

```bash
root@kaligra:/etc/snort/rules# cat local.rules
# $Id: local.rules,v 1.11 2004/07/23 20:15:44 bmc Exp $
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert icmp any any -> any any (msg:"ICMP connection attempt"; sid:1000010; rev:1;)
```

test it with a PCAP file with just 8 ICMP packets

```bash
snort -c /etc/snort/snort.lua  -r /home/joshua/onlyping.pcap --talos |grep -i alert
alert_talos
        alerts
        [1:1000010:1] ICMP connection attempt (alerts: 8) <==============
                   alerts: 8
             total_alerts: 8
..
```

### snort with docker

```bash
joshua@kaligra:~$ docker pull ciscotalos/snort3
Using default tag: latest
latest: Pulling from ciscotalos/snort3
8f0fdd3eaac0: Pull complete
9f2aba7999e8: Pull complete
ea85662ac198: Pull complete
635219aed8b4: Pull complete
b8d9a7384d21: Pull complete
cd49bdf1d940: Pull complete
1e4978604ac1: Pull complete
Digest: sha256:d804a865175503367e6aabd46e2280c38dbb76e25628c76eb31bbec62c200ffb
Status: Downloaded newer image for ciscotalos/snort3:latest
docker.io/ciscotalos/snort3:latest
```

start the container:

```bash
joshua@kaligra:~$ docker run --name snort3 -h snort3 -u snorty -w /home/snorty -d -it ciscotalos/snort3 bash
0aa04e6e100e82a87dcef64c4fdb2a9e5eb8779ac88b854182238542cf38198f
```

attach to container:

```bash
joshua@kaligra:~$ docker exec -it snort3 bash
snorty@snort3:~$
```
## Eternalblue

Consider PCAP from Snort Container:

https://hub.docker.com/r/ciscotalos/snort3

path: /home/snorty/examples/intro/lab2/eternalblue.pcap

```
snorty@snort3:~$ snort -q  --talos -r examples/intro/lab2/eternalblue.pcap --rule-path ~/snort3/etc/rules/

##### eternalblue.pcap #####
        [1:41978:5] OS-WINDOWS Microsoft Windows SMB remote code execution attempt (alerts: 27)
        [1:42944:2] OS-WINDOWS Microsoft Windows SMB remote code execution attempt (alerts: 3)
#####
```

Let's check rules:

```
snorty@snort3:~$ grep -rl "OS-WINDOWS Microsoft Windows SMB remote code execution attempt" snort3/etc/rules/*
snort3/etc/rules/snort3-community.rules
```

```
alert tcp any any -> $HOME_NET 445 ( msg:"OS-WINDOWS Microsoft Windows SMB remote code execution attempt"; flow:to_server,established; content:"|FF|SMB3|00 00 00 00|",depth 9,offset 4; byte_extract:2,26,TotalDataCount,relative,little; byte_test:2,>,TotalDataCount,20,relative,little; metadata:policy balanced-ips drop,policy connectivity-ips drop,policy max-detect-ips drop,policy security-ips drop,ruleset community; service:netbios-ssn; reference:cve,2017-0144; reference:cve,2017-0146; reference:url,blog.talosintelligence.com/2017/05/wannacry.html; reference:url,isc.sans.edu/forums/diary/ETERNALBLUE+Possible+Window+SMB+Buffer+Overflow+0Day/22304/; reference:url,technet.microsoft.com/en-us/security/bulletin/MS17-010; classtype:attempted-admin; sid:41978; rev:5; )
alert tcp any any -> $HOME_NET 445 ( msg:"OS-WINDOWS Microsoft Windows SMB remote code execution attempt"; flow:to_server,established; content:"|FF|SMB|A0 00 00 00 00|",depth 9,offset 4; content:"|01 00 00 00 00|",within 5,distance 59; byte_test:4,>,0x8150,-33,relative,little; metadata:policy balanced-ips drop,policy connectivity-ips drop,policy max-detect-ips drop,policy security-ips drop,ruleset community; service:netbios-ssn; reference:cve,2017-0144; reference:cve,2017-0146; reference:url,isc.sans.edu/forums/diary/ETERNALBLUE+Possible+Window+SMB+Buffer+Overflow+0Day/22304/; reference:url,technet.microsoft.com/en-us/security/bulletin/MS17-010; classtype:attempted-admin; sid:42944; rev:2; )
```

Pattern: `|FF|SMB3|00 00 00 00|`

Hex: `FF 53 4D 42 33 00 00 00 00`

![filter1](https://user-images.githubusercontent.com/42389836/163867724-1604691d-4bff-46b8-a6df-f76241ee814a.JPG)


![filter2](https://user-images.githubusercontent.com/42389836/163867765-529c8bf4-6a7e-4bca-86ea-598cb189d7b0.JPG)

## Emotet

https://feodotracker.abuse.ch/browse/emotet/

## Looking for malware activity

Look for no user-agent

Look for no recognized vendor in mac address

Look for old TLS version traffic (like 1.0)

## General info on host

Look for DHCP option (12) hostname to get an idea of what kind of device is - filter: dhcp.option.hostname

Look for nbns traffic to see registration (-> hostname)

Look for kerberos traffic (tcp.port==88) to determine username or kerberos.CNameString (will reveal hostname AND user account)

Look for useragent to get an idea of OS

## Tshark-fu

```
tshark -r traffic.pcap -T fields -e ip.src -e dns.qry.name -2R "dns.flags.response eq 0" | awk -F" " '{ print $2 }' | sort -u
tshark -r traffic.pcap -q -z endpoints,tcp
tshark -r traffic.pcap -Y ntlmssp.auth.username -V -x | ack -i 'Response:|user|dns'
```

### dhcp details

hostname, mac address, requested ip

```bash
tshark -r file.pcap -Y "dhcp && dhcp.type == 1 && dhcp.option.dhcp == 3" -T fields -e eth.src  -e bootp.option.hostname -e dhcp.option.requested_ip_address | uniq
```

### dns query

```bash
$ tshark -r file.pcap -Y "dns and udp.dstport==53" -T fields -e ip.src -e dns.qry.name  |head
192.168.122.130 teredo.ipv6.microsoft.com
192.168.122.130 www.msftncsi.com
192.168.122.52  teredo.ipv6.microsoft.com
192.168.122.130 www.bing.com
192.168.122.130 www.bing.com
192.168.122.130 login.live.com
192.168.122.130 az29176.vo.msecnd.net
192.168.122.130 www.bing.com
192.168.122.130 www.bing.com
192.168.122.130 az29176.vo.msecnd.net
```

### export objects in directory

```bash
$ tshark -r file.pcap --export-objects http,objects
```

(all files will be extracted in `/objects` folder)
## Capture with pktmon

```
c:\Users\sugo\Desktop>pktmon start --capture

Parametri registratore:
    Nome registratore:        PktMon
    Modalità di registrazione:       Circolare
    File di log:           c:\Users\sugo\Desktop\PktMon.etl
    Dimensioni massime file:      512 MB
    Memoria utilizzata:        256 MB

Dati raccolti:
    Contatori pacchetti, acquisizione pacchetti

Tipo cattura:
    Tutti i pacchetti

Componenti monitorati:
    Tutto

Filtri pacchetti:
    Nessuno
```

```
c:\Users\sugo\Desktop>pktmon stop --capture
Scaricamento log in corso...
Unione dei metadati in...
File di log: c:\Users\sugo\Desktop\PktMon.etl (nessun evento perduto)
```

```
c:\Users\sugo\Desktop>pktmon etl2pcap PktMon.etl
Elaborazione in corso...

Pacchetti totali:       4198
Conteggio mancata elaborazione pacchetti:   0
Pacchetti formattati:   4198
File formattato:      PktMon.pcapng

c:\Users\sugo\Desktop>
```

