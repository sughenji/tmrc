# Forensic

- [Collect memory](#collect-memory)
- [Volatility](#volatility)
	- [Useful links](#useful-links)
	- [Instalation](#installation)
	- [Profile](#profile)
	- [Envars](#envars)
	- [Hostname](#hostname)
	- [SIDs](#sids)
      	- [Credentials](#credentials)
	- [Last shutdown](#last-shutdown)
	- [Pslist](#pslist)
	- [Command arguments](#command-arguments)
	- [Offset](#offset)
	- [cmd history](#cmd-history)
	- [Truecrypt](#truecrypt)
	- [DLL list](#dll-list)
	- [Connections](#connections)
- [Event viewer](#event-viewer)
- [Chainsaw](#chainsaw)

## Collect memory

FTK Imager 

LiME

```
apt install lime-forensics-dkms/jammy
cd /lib/modules/5.15.0-43-generic/updates/dkms/
insmod ./lime.ko "path=/tmp/image format=lime"
```

(this will create an image of current RAM in `/tmp/image`)

## Volatility

# useful links

https://github.com/volatilityfoundation/volatility/wiki/Installation

https://github.com/volatilityfoundation/volatility/wiki

https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-examples

https://heisenberk.github.io/Profile-Memory-Dump/

Followed this to install on Kali:

https://seanthegeek.net/1172/how-to-install-volatility-2-and-volatility-3-on-debian-ubuntu-or-kali-linux/

# Installation

```
sudo apt install -y build-essential git libdistorm3-dev yara libraw1394-11 libcapstone-dev capstone-tool tzdata
sudo apt install -y python2 python2.7-dev libpython2-dev
cd /opt/tools
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
sudo python2 get-pip.py
sudo python2 -m pip install -U setuptools wheel
python2 -m pip install -U distorm3 yara pycrypto pillow openpyxl ujson pytz ipython capstone
sudo python2 -m pip install yara
sudo ln -s /usr/local/lib/python2.7/dist-packages/usr/lib/libyara.so /usr/lib/libyara.so
python2 -m pip install -U git+https://github.com/volatilityfoundation/volatility.git
```

# Profile

```
joshua@kaligra:~/Documents/thm/memoryforensics$ vol.py -f Snapshot6.vmem imageinfo
```

# Envars

```
joshua@kaligra:~/Documents/thm/memoryforensics$ vol.py --profile Win7SP1x64 -f Snapshot14.vmem envars
```

# Hostname

```
joshua@kaligra:~/Documents/thm/memoryforensics$ vol.py --profile Win7SP1x64 -f Snapshot14.vmem envars |grep COMPUTERNAME
Volatility Foundation Volatility Framework 2.6.1
     408 wininit.exe          0x0000000000149660 COMPUTERNAME                   JOHN-PC
     464 winlogon.exe         0x000000000021def0 COMPUTERNAME                   JOHN-PC
     508 services.exe         0x00000000002b1320 COMPUTERNAME                   JOHN-PC
..
..
```	

# SIDs

```
joshua@kaligra:~/Documents/thm/memoryforensics$ vol.py --profile Win7SP1x64 -f Snapshot14.vmem getsids
Volatility Foundation Volatility Framework 2.6.1
System (4): S-1-5-18 (Local System)
System (4): S-1-5-32-544 (Administrators)
System (4): S-1-1-0 (Everyone)
System (4): S-1-5-11 (Authenticated Users)
System (4): S-1-16-16384 (System Mandatory Level)
smss.exe (264): S-1-5-18 (Local System)
smss.exe (264): S-1-5-32-544 (Administrators)
smss.exe (264): S-1-1-0 (Everyone)
smss.exe (264): S-1-5-11 (Authenticated Users)
smss.exe (264): S-1-16-16384 (System Mandatory Level)
csrss.exe (356): S-1-5-18 (Local System)
csrss.exe (356): S-1-5-32-544 (Administrators)
csrss.exe (356): S-1-1-0 (Everyone)
csrss.exe (356): S-1-5-11 (Authenticated Users)
csrss.exe (356): S-1-16-16384 (System Mandatory Level)
wininit.exe (408): S-1-5-18 (Local System)
wininit.exe (408): S-1-5-32-544 (Administrators)
wininit.exe (408): S-1-1-0 (Everyone)
wininit.exe (408): S-1-5-11 (Authenticated Users)
wininit.exe (408): S-1-16-16384 (System Mandatory Level)
..
..
```


# Credentials

```
joshua@kaligra:~/Documents/thm/memoryforensics$ vol.py --profile Win7SP1x64 -f Snapshot6.vmem hashdump
Volatility Foundation Volatility Framework 2.6.1
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
John:1001:aad3b435b51404eeaad3b435b51404ee:47fbd6536d7868c873d5ea455f2fc0c9:::
HomeGroupUser$:1002:aad3b435b51404eeaad3b435b51404ee:91c34c06b7988e216c3bfeb9530cabfb:::
```

```
joshua@kaligra:~/Documents/thm/memoryforensics$ hashcat -m 1000 '47fbd6536d7868c873d5ea455f2fc0c9' /usr/share/wordlists/rockyou.txt
```

```
joshua@kaligra:~/Documents/thm/memoryforensics$ hashcat -m 1000 '47fbd6536d7868c873d5ea455f2fc0c9' --show
47fbd6536d7868c873d5ea455f2fc0c9:charmander999
```

# Last shutdown

```
joshua@kaligra:~/Documents/thm/memoryforensics$ vol.py --profile Win7SP1x64 -f Snapshot19.vmem shutdowntime
Volatility Foundation Volatility Framework 2.6.1
Registry: SYSTEM
Key Path: ControlSet001\Control\Windows
Key Last updated: 2020-12-27 22:50:12 UTC+0000
Value Name: ShutdownTime
Value: 2020-12-27 22:50:12 UTC+0000
```



# Pslist

Es.

```
joshua@kaligra:~/Documents/thm/volatility$ vol.py  -f cridex.vmem --profile WinXPSP2x86 pslist
Volatility Foundation Volatility Framework 2.6.1
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0x823c89c8 System                    4      0     53      240 ------      0
0x822f1020 smss.exe                368      4      3       19 ------      0 2012-07-22 02:42:31 UTC+0000
0x822a0598 csrss.exe               584    368      9      326      0      0 2012-07-22 02:42:32 UTC+0000
0x82298700 winlogon.exe            608    368     23      519      0      0 2012-07-22 02:42:32 UTC+0000
0x81e2ab28 services.exe            652    608     16      243      0      0 2012-07-22 02:42:32 UTC+0000
0x81e2a3b8 lsass.exe               664    608     24      330      0      0 2012-07-22 02:42:32 UTC+0000
0x82311360 svchost.exe             824    652     20      194      0      0 2012-07-22 02:42:33 UTC+0000
0x81e29ab8 svchost.exe             908    652      9      226      0      0 2012-07-22 02:42:33 UTC+0000
0x823001d0 svchost.exe            1004    652     64     1118      0      0 2012-07-22 02:42:33 UTC+0000
0x821dfda0 svchost.exe            1056    652      5       60      0      0 2012-07-22 02:42:33 UTC+0000
0x82295650 svchost.exe            1220    652     15      197      0      0 2012-07-22 02:42:35 UTC+0000
0x821dea70 explorer.exe           1484   1464     17      415      0      0 2012-07-22 02:42:36 UTC+0000
0x81eb17b8 spoolsv.exe            1512    652     14      113      0      0 2012-07-22 02:42:36 UTC+0000
0x81e7bda0 reader_sl.exe          1640   1484      5       39      0      0 2012-07-22 02:42:36 UTC+0000
0x820e8da0 alg.exe                 788    652      7      104      0      0 2012-07-22 02:43:01 UTC+0000
0x821fcda0 wuauclt.exe            1136   1004      8      173      0      0 2012-07-22 02:43:46 UTC+0000
0x8205bda0 wuauclt.exe            1588   1004      5      132      0      0 2012-07-22 02:44:01 UTC+0000
```

```
joshua@kaligra:~/Documents/thm/memoryforensics$ vol.py --profile Win7SP1x64 -f Snapshot19.vmem pslist
```

# Command arguments

```
joshua@kaligra:~/Documents/thm/memoryforensics$ vol.py --profile Win7SP1x64 -f Snapshot14.vmem cmdline -p 2192
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
SearchIndexer. pid:   2192
Command line : C:\Windows\system32\SearchIndexer.exe /Embedding
```

# Offset

```
joshua@kaligra:~/Documents/thm/memoryforensics$ vol.py --profile Win7SP1x64 -f Snapshot14.vmem pslist -p 1904
Volatility Foundation Volatility Framework 2.6.1
Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
------------------ -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0xfffffa80052c2b30 TrueCrypt.exe          1904   1180     14      268      1      1 2020-12-27 13:39:50 UTC+0000
```

Answer: `0xfffffa80052c2b30`



# CMD history

```
joshua@kaligra:~/Documents/thm/memoryforensics$ vol.py --profile Win7SP1x64 -f Snapshot19.vmem cmdscan
```

# Truecrypt

```
joshua@kaligra:~/Documents/thm/memoryforensics$ vol.py --profile Win7SP1x64 -f Snapshot14.vmem truecryptpassphrase
```

# DLL list

```
joshua@kaligra:~/Documents/thm/memoryforensics$ vol.py --profile Win7SP1x64 -f Snapshot14.vmem dlllist -p 1904
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
TrueCrypt.exe pid:   1904
Command line : "C:\Program Files\TrueCrypt\TrueCrypt.exe"


Base                             Size          LoadCount LoadTime                       Path
------------------ ------------------ ------------------ ------------------------------ ----
0x0000000000400000           0x1a2000             0xffff 1970-01-01 00:00:00 UTC+0000   C:\Program Files\TrueCrypt\TrueCrypt.exe
0x00000000778a0000           0x1a9000             0xffff 1970-01-01 00:00:00 UTC+0000   C:\Windows\SYSTEM32\ntdll.dll
0x00000000752c0000            0x3f000                0x3 2020-12-27 13:39:50 UTC+0000   C:\Windows\SYSTEM32\wow64.dll
0x0000000075260000            0x5c000                0x1 2020-12-27 13:39:50 UTC+0000   C:\Windows\SYSTEM32\wow64win.dll
0x0000000075250000             0x8000                0x1 2020-12-27 13:39:50 UTC+0000   C:\Windows\SYSTEM32\wow64cpu.dll
0x0000000000400000           0x1a2000             0xffff 1970-01-01 00:00:00 UTC+0000   C:\Program Files\TrueCrypt\TrueCrypt.exe
0x0000000077a80000           0x180000             0xffff 1970-01-01 00:00:00 UTC+0000   C:\Windows\SysWOW64\ntdll.dll
0x0000000075910000           0x110000             0xffff 2020-12-27 13:39:50 UTC+0000   C:\Windows\syswow64\kernel32.dll
..
..
```

# Connections

```
$ vol.py --profile Win7SP1x64 -f Snapshot14.vmem netscan
```

# Event viewer

Search for logs about a specific username:

```
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[EventData[Data[@Name='TargetUserName']='sugo']]</Select>
  </Query>
</QueryList>
```

ref. https://www.beaming.co.uk/knowledge-base/techs-how-to-search-the-windows-event-log-for-logins-by-username/


## Chainsaw

https://github.com/WithSecureLabs/chainsaw

```
D:\download\chainsaw_all_platforms+rules+examples\chainsaw>chainsaw_x86_64-pc-windows-msvc.exe hunt d:\share\dc01logs -s sigma/rules --mapping mappings/sigma-event-logs-all.yml --level critical

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By Countercept (@FranticTyping, @AlexKornitzer)

[+] Loading detection rules from: sigma/rules
[+] Loaded 88 detection rules (144 not loaded)
[+] Loading forensic artefacts from: d:\share\dc01logs (extensions: .evtx, .evt)
[+] Loaded 331 forensic artefacts (592.4 MB)
[+] Hunting: [========================================] 331/331 -
[+] Group: Sigma
┌─────────────────────┬────────────────────────────────┬───────┬────────────────────────────────┬──────────┬───────────┬─────────────────────┬────────────────────────────────┐
│      timestamp      │           detections           │ count │     Event.System.Provider      │ Event ID │ Record ID │      Computer       │           Event Data           │
├─────────────────────┼────────────────────────────────┼───────┼────────────────────────────────┼──────────┼───────────┼─────────────────────┼────────────────────────────────┤
│ 2023-05-01 14:08:20 │ + Active Directory Replication │ 1     │ Microsoft-Windows-Security-Aud │ 4662     │ 53362     │ DC01.budapest.local │ AccessList: "%%7688\r          │
│                     │ from Non Machine Account       │       │ iting                          │          │           │                     │ \t\t\t\                        │
│                     │                                │       │                                │          │           │                     │ t"                             │
│                     │                                │       │                                │          │           │                     │ AccessMask: '0x100'            │
│                     │                                │       │                                │          │           │                     │ AdditionalInfo: '-'            │
│                     │                                │       │                                │          │           │                     │ AdditionalInfo2: ''            │
│                     │                                │       │                                │          │           │                     │ HandleId: '0x0'                │
│                     │                                │       │                                │          │           │                     │ ObjectName: '%{06d6aa46-5cc3-4 │
│                     │                                │       │                                │          │           │                     │ 678-974d-e2c2b57910aa}'        │
│                     │                                │       │                                │          │           │                     │ ObjectServer: DS               │
│                     │                                │       │                                │          │           │                     │ ObjectType: '%{19195a5b-6da0-1 │
│                     │                                │       │                                │          │           │                     │ 1d0-afd3-00c04fd930c9}'        │
│                     │                                │       │                                │          │           │                     │ OperationType: Object Access   │
│                     │                                │       │                                │          │           │                     │ Properties: "%%7688\r          │
│                     │                                │       │                                │          │           │                     │ \t\t{11                        │
│                     │                                │       │                                │          │           │                     │ 31f6aa-9c07-11d1-f79f-00c04fc2 │
│                     │                                │       │                                │          │           │                     │ dcd2}\r                        │
│                     │                                │       │                                │          │           │                     │ \t{19195a5b-6da0-11d0          │
│                     │                                │       │                                │          │           │                     │ -afd3-00c04fd930c9}\r          │
│                     │                                │       │                                │          │           │                     │ "                              │
│                     │                                │       │                                │          │           │                     │ SubjectDomainName: BUDAPEST    │
│                     │                                │       │                                │          │           │                     │ SubjectLogonId: '0x650f73'     │
│                     │                                │       │                                │          │           │                     │ SubjectUserName: Administrator │
│                     │                                │       │                                │          │           │                     │ SubjectUserSid: S-1-5-21-12754 │
│                     │                                │       │                                │          │           │                     │ 03054-872536965-1404416288-500 │
├─────────────────────┼────────────────────────────────┼───────┼────────────────────────────────┼──────────┼───────────┼─────────────────────┼────────────────────────────────┤
```


