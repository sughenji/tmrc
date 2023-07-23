# TakeOver

URL: https://tryhackme.com/room/takeover

Level: Easy

Date: 23 Jul 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [HTTP](#http)
	- [Feroxbuster](#feroxbuster)
	- [Subdomain enumeration](#subdomain-enumeration)
	- [Rabbit Hole](#rabbit-hole)
	- [SSL Certificate](#ssl-certificate)






## Reconnaissance

First, we add `futurevera.thm` to our `/etc/hosts` file.

### nmap

```bash
$ sudo nmap -T4 -p- -n 10.10.54.122 -oA nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-23 09:57 CEST
Nmap scan report for 10.10.54.122
Host is up (0.059s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 38.68 seconds
```

### http


![](Pasted%20image%2020230723100320.png)

### feroxbuster

```bash
$ feroxbuster --silent -k -u https://futurevera.thm -n -t 200 -L 1 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt -o feroxbuster.txt
https://futurevera.thm/
https://futurevera.thm/assets => https://futurevera.thm/assets/
https://futurevera.thm/css => https://futurevera.thm/css/
https://futurevera.thm/js => https://futurevera.thm/js/
```

Nothing interesting.

### subdomain enumeration

```bash
$ ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u https://10.10.111.78 -H "Host: FUZZ.futurevera.thm" -fs 4605

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : https://10.10.111.78
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.futurevera.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 4605
________________________________________________

support                 [Status: 200, Size: 1522, Words: 367, Lines: 34, Duration: 75ms]
blog                    [Status: 200, Size: 3838, Words: 1326, Lines: 81, Duration: 74ms]
:: Progress: [114441/114441] :: Job [1/1] :: 410 req/sec :: Duration: [0:03:37] :: Errors: 0 ::
```



We found two subdomain:

`blog.futurevera.thm`

![](Pasted%20image%2020230723114151.png)


`support.futurevera.htm`

![](Pasted%20image%2020230723114230.png)


Let's enum again with `feroxbuster`:

```bash
joshua@kaligra:~/Documents/thm/takeover$ feroxbuster --silent -k -u https://blog.futurevera.thm -n -t 200 -L 1 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt -o blog.futurevera.thm
https://blog.futurevera.thm/
https://blog.futurevera.thm/assets => https://blog.futurevera.thm/assets/
https://blog.futurevera.thm/css => https://blog.futurevera.thm/css/
https://blog.futurevera.thm/js => https://blog.futurevera.thm/js/



joshua@kaligra:~/Documents/thm/takeover$ feroxbuster --silent -k -u https://support.futurevera.thm -n -t 200 -L 1 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt -o support.futurevera.thm
https://support.futurevera.thm/
https://support.futurevera.thm/assets => https://support.futurevera.thm/assets/
https://support.futurevera.thm/css => https://support.futurevera.thm/css/
https://support.futurevera.thm/js => https://support.futurevera.thm/js/
```

### rabbit hole

We spend lot's of time during file enumeration...


```bash
$ gobuster dir -u http://support.futurevera.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,bak,html -o gobuster_support
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://support.futurevera.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php,bak,html
[+] Timeout:                 10s
===============================================================
2023/07/23 15:11:51 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 287]
/.html                (Status: 403) [Size: 287]
/index.php            (Status: 302) [Size: 0] [--> https://futurevera.thm/]
Progress: 57535 / 350660 (16.41%)
..
..
..
```

Or fourth level sudomains:

```bash
ffuf -w /opt/SecLists/Discovery/DNS/fierce-hostlist.txt -u https://10.10.113.72 -H "Host: FUZZ.support.futurevera.thm" -fs 4605
..
..
..
```

### SSL certificate

Since there is port 443 involved (not quite common), let's investigate on SSL certificate:

```bash
$ openssl s_client -connect 10.10.113.72:443 -servername support.futurevera.thm
CONNECTED(00000003)
depth=0 C = US, ST = Oregon, L = Portland, O = Futurevera, OU = Thm, CN = support.futurevera.thm
verify error:num=18:self-signed certificate
verify return:1
depth=0 C = US, ST = Oregon, L = Portland, O = Futurevera, OU = Thm, CN = support.futurevera.thm
verify return:1
---
Certificate chain
 0 s:C = US, ST = Oregon, L = Portland, O = Futurevera, OU = Thm, CN = support.futurevera.thm
   i:C = US, ST = Oregon, L = Portland, O = Futurevera, OU = Thm, CN = support.futurevera.thm
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Mar 13 14:26:24 2022 GMT; NotAfter: Mar 12 14:26:24 2024 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIID1DCCArygAwIBAgIUauW3cx0CzRBzqYjg5HMaPwCIbJIwDQYJKoZIhvcNAQEL
..
..
..
```

```
-----BEGIN CERTIFICATE-----
MIID1DCCArygAwIBAgIUauW3cx0CzRBzqYjg5HMaPwCIbJIwDQYJKoZIhvcNAQEL
BQAwdTELMAkGA1UEBhMCVVMxDzANBgNVBAgMBk9yZWdvbjERMA8GA1UEBwwIUG9y
dGxhbmQxEzARBgNVBAoMCkZ1dHVyZXZlcmExDDAKBgNVBAsMA1RobTEfMB0GA1UE
AwwWc3VwcG9ydC5mdXR1cmV2ZXJhLnRobTAeFw0yMjAzMTMxNDI2MjRaFw0yNDAz
MTIxNDI2MjRaMHUxCzAJBgNVBAYTAlVTMQ8wDQYDVQQIDAZPcmVnb24xETAPBgNV
BAcMCFBvcnRsYW5kMRMwEQYDVQQKDApGdXR1cmV2ZXJhMQwwCgYDVQQLDANUaG0x
HzAdBgNVBAMMFnN1cHBvcnQuZnV0dXJldmVyYS50aG0wggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCam2TIcJoT0V4OyJPrAtr3JW/H14xrPxSQHe3Jjxqw
SH1HcQh13NdJRyZl/hFoNpKJQIur+2EPN32SSHoAI0Fy7x+cJxNMjeRl5TDFsU5a
f+Tf7Pzi8xnF0c82OOC0RDOE8sVhP2OFMx95rS283KxVwjpCGHBzkHsvIVLDjIvh
s3b0Xfnscao+H9PProJSNkMBZc5ZRJ6MYtHm74MPdVdmbWuyIeNkaK+slQ73xKZh
RxlYlUhULhzxursi4qgJS5SpDQdc4fVFd3VFa9TJ0VUBWUsXupibA3DFTmkoGSyD
QRjEwBcOoWcfqF6VWA+BJL/f/OKrP1THuAuQvCHwa7YrAgMBAAGjXDBaMAsGA1Ud
DwQEAwIEMDATBgNVHSUEDDAKBggrBgEFBQcDATA2BgNVHREELzAtgitzZWNyZXRo
ZWxwZGVzazkzNDc1Mi5zdXBwb3J0LmZ1dHVyZXZlcmEudGhtMA0GCSqGSIb3DQEB
CwUAA4IBAQCTUYQLIjsHa42CQDgkqOjmMxlbw+YE3lBfhfzs3kDLTLX0xdq1+JqN
wMVU10PSxSqEG58toZVumHP1y72n3glXUE5EEpjEOqDfWe6V7Qnzr8rRp1ceofLx
3tXGNg7UGCl0wtMv2SQhJfYbGFY+/nWVv3+PxRUaHYDyKNqR9zkhpKYtfco9VHVH
YiAbo4VZwLNM6kuyxKXqDSPrlZQ+lrwYDPVFoIygjInvGv1XqrHJaxzNZflaDMc0
+wBc0SMOD3YHuTnlbI0hqEgr2dT7IcNQeEGrUL7H5thgGwbucRuXIXyqz1HUprNB
HcT1TOoUlF4OYm9VnHzvAX8BcfxY8N5y
-----END CERTIFICATE-----
```

Certificate's detail:

```bash
$ openssl x509 -in ./cert -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            6a:e5:b7:73:1d:02:cd:10:73:a9:88:e0:e4:73:1a:3f:00:88:6c:92
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, ST = Oregon, L = Portland, O = Futurevera, OU = Thm, CN = support.futurevera.thm
        Validity
            Not Before: Mar 13 14:26:24 2022 GMT
            Not After : Mar 12 14:26:24 2024 GMT
        Subject: C = US, ST = Oregon, L = Portland, O = Futurevera, OU = Thm, CN = support.futurevera.thm
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
..
..
..
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 Subject Alternative Name:
                DNS:secrethelpdesk934752.support.futurevera.thm
    Signature Algorithm: sha256WithRSAEncryption
..
..
..
```

We just discovered another subdomain:

`secrethelpdesk934752.support.futurevera.thm`

### flag

Flag is in the `Location` header:

```bash
# curl -v -H "Host: secrethelpdesk934752.support.futurevera.thm" http://10.10.113.72
*   Trying 10.10.113.72:80...
* Connected to 10.10.113.72 (10.10.113.72) port 80 (#0)
> GET / HTTP/1.1
> Host: secrethelpdesk934752.support.futurevera.thm
> User-Agent: curl/7.87.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Found
< Date: Sun, 23 Jul 2023 13:25:32 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Location: http://flag{beea0d6edfcee06a59b83fbXXXXXX}.s3-website-us-west-3.amazonaws.com/
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
<
* Connection #0 to host 10.10.113.72 left intact

```