# Committed

URL: https://tryhackme.com/room/committed

Level: Easy

Date: 3 Aug 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [Split view](#split-view)
	- [Flag](#flag)
	 





## Reconnaissance

### nmap

```bash
joshua@kaligra:~/Documents/thm/committed$ sudo nmap -T4 -p- 10.10.143.130 -oA nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-03 12:11 CEST
Nmap scan report for 10.10.143.130
Host is up (0.13s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 33.60 seconds
```

```bash
joshua@kaligra:~/Documents/thm/committed$ sudo nmap -T4 -p80 -sC -sV  10.10.143.130 -oA nmap2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-03 12:12 CEST
Nmap scan report for 10.10.143.130
Host is up (0.053s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    WebSockify Python/3.8.10
|_http-server-header: WebSockify Python/3.8.10
|_http-title: Error response
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 405 Method Not Allowed
|     Server: WebSockify Python/3.8.10
|     Date: Thu, 03 Aug 2023 10:12:54 GMT
|     Connection: close
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 472
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 405</p>
|     <p>Message: Method Not Allowed.</p>
|     <p>Error code explanation: 405 - Specified method is invalid for this resource.</p>
|     </body>
|     </html>
|   HTTPOptions:
|     HTTP/1.1 501 Unsupported method ('OPTIONS')
|     Server: WebSockify Python/3.8.10
|     Date: Thu, 03 Aug 2023 10:12:54 GMT
|     Connection: close
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 500
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 501</p>
|     <p>Message: Unsupported method ('OPTIONS').</p>
|     <p>Error code explanation: HTTPStatus.NOT_IMPLEMENTED - Server does not support this operation.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.93%I=7%D=8/3%Time=64CB7DA6%P=x86_64-pc-linux-gnu%r(GetRe
SF:quest,291,"HTTP/1\.1\x20405\x20Method\x20Not\x20Allowed\r\nServer:\x20W
SF:ebSockify\x20Python/3\.8\.10\r\nDate:\x20Thu,\x2003\x20Aug\x202023\x201
SF:0:12:54\x20GMT\r\nConnection:\x20close\r\nContent-Type:\x20text/html;ch
SF:arset=utf-8\r\nContent-Length:\x20472\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLI
SF:C\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x20
SF:\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Conte
SF:nt-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\n
SF:\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20re
SF:sponse</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20405</
SF:p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Method\x20Not\x20All
SF:owed\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20explana
SF:tion:\x20405\x20-\x20Specified\x20method\x20is\x20invalid\x20for\x20thi
SF:s\x20resource\.</p>\n\x20\x20\x20\x20</body>\n</html>\n")%r(HTTPOptions
SF:,2B9,"HTTP/1\.1\x20501\x20Unsupported\x20method\x20\('OPTIONS'\)\r\nSer
SF:ver:\x20WebSockify\x20Python/3\.8\.10\r\nDate:\x20Thu,\x2003\x20Aug\x20
SF:2023\x2010:12:54\x20GMT\r\nConnection:\x20close\r\nContent-Type:\x20tex
SF:t/html;charset=utf-8\r\nContent-Length:\x20500\r\n\r\n<!DOCTYPE\x20HTML
SF:\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x2
SF:0\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equi
SF:v=\"Content-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x2
SF:0\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20
SF:</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Er
SF:ror\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:
SF:\x20501</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Unsupported
SF:\x20method\x20\('OPTIONS'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>E
SF:rror\x20code\x20explanation:\x20HTTPStatus\.NOT_IMPLEMENTED\x20-\x20Ser
SF:ver\x20does\x20not\x20support\x20this\x20operation\.</p>\n\x20\x20\x20\
SF:x20</body>\n</html>\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 85.29 seconds

```

### Split view

Honestly, after a few tries with `feroxbuster`, we just use the *Split View* machine and we noticed the `committed.zip` archive.

We spawn a python web server on remote machine and we transfer such archive to our attacker box:

```bash
joshua@kaligra:~/Documents/thm/committed$ wget http://10.10.7.4:8888/commited.zip
--2023-08-04 17:54:24--  http://10.10.7.4:8888/commited.zip
Connecting to 10.10.7.4:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 34993 (34K) [application/zip]
Saving to: ‘commited.zip’

commited.zip                                    100%[=====================================================================================================>]  34.17K  --.-KB/s    in 0.08s

2023-08-04 17:54:25 (448 KB/s) - ‘commited.zip’ saved [34993/34993]

joshua@kaligra:~/Documents/thm/committed$ ls
```

Unzip it:

```bash
joshua@kaligra:~/Documents/thm/committed$ unzip commited.zip
Archive:  commited.zip
   creating: commited/
   creating: commited/.git/
   creating: commited/.git/logs/
   creating: commited/.git/logs/refs/
   creating: commited/.git/logs/refs/heads/
  inflating: commited/.git/logs/refs/heads/dbint
  inflating: commited/.git/logs/refs/heads/master
  inflating: commited/.git/logs/HEAD
   creating: commited/.git/refs/
   creating: commited/.git/refs/tags/
   creating: commited/.git/refs/heads/
 extracting: commited/.git/refs/heads/dbint
 extracting: commited/.git/refs/heads/master
   creating: commited/.git/info/
  inflating: commited/.git/info/exclude
 extracting: commited/.git/COMMIT_EDITMSG
   creating: commited/.git/objects/
   creating: commited/.git/objects/da/
 extracting: commited/.git/objects/da/b5a1b99756122e83df66ea1a86d81257b2ec47
   creating: commited/.git/objects/dc/
 extracting: commited/.git/objects/dc/1ca4ca1d54e7a4ac6757c9b98bd1be0a8ed2f0
   creating: commited/.git/objects/26/
 extracting: commited/.git/objects/26/bcf1aa99094bf2fb4c9685b528a55838698fbe
   creating: commited/.git/objects/69/
 extracting: commited/.git/objects/69/d6211898e43bfe15ab5a4cad1690b9be1115f8
   creating: commited/.git/objects/74/
 extracting: commited/.git/objects/74/2b40ee5d0597b0595f60998305605186ab29db
   creating: commited/.git/objects/9e/
 extracting: commited/.git/objects/9e/cdc566de145f5c13da74673fa3432773692502
   creating: commited/.git/objects/info/
   creating: commited/.git/objects/3a/
 extracting: commited/.git/objects/3a/8cc16f919b8ac43651d68dceacbb28ebb9b625
   creating: commited/.git/objects/b0/
 extracting: commited/.git/objects/b0/eda7db60a1cb0aea86f053816a1bfb7e2d6c67
   creating: commited/.git/objects/94/
 extracting: commited/.git/objects/94/a7ea670b13f698012abd246ab08b76d95643c8
   creating: commited/.git/objects/28/
 extracting: commited/.git/objects/28/c36211be8187d4be04530e340206b856198a84
   creating: commited/.git/objects/c7/
 extracting: commited/.git/objects/c7/18c75179d46ba5a1d21dc351a39c0dfb257d3d
   creating: commited/.git/objects/08/
 extracting: commited/.git/objects/08/178a40f4b3585566b539985399f51bbcc7ae22
   creating: commited/.git/objects/6e/
 extracting: commited/.git/objects/6e/1ea88319ae84175bfe953b7791ec695e1ca004
   creating: commited/.git/objects/0b/
 extracting: commited/.git/objects/0b/8b1d537ea651d504d29c1556d7dcbcf76a5d57
   creating: commited/.git/objects/pack/
   creating: commited/.git/objects/40/
 extracting: commited/.git/objects/40/754840a68f85ad8d963f1556a3f24b51cef4fa
   creating: commited/.git/objects/16/
 extracting: commited/.git/objects/16/1979c948240de867b5c0a4079d7e2c7f6d4e04
   creating: commited/.git/objects/c5/
 extracting: commited/.git/objects/c5/6c470a2a9dfb5cfbd54cd614a9fdb1644412b5
   creating: commited/.git/objects/38/
 extracting: commited/.git/objects/38/0dd9b32cc8429638c09cc857cc0ef2ff8f8e50
   creating: commited/.git/objects/df/
 extracting: commited/.git/objects/df/e24c9e9ae78d8339e44d0c9e32dde9b9efe148
   creating: commited/.git/objects/45/
 extracting: commited/.git/objects/45/b137061d385e2f5c05cccc7fd13873f2ce18b1
   creating: commited/.git/objects/0e/
 extracting: commited/.git/objects/0e/1d395f33767d795f3ff66ceac6c792629d40d2
   creating: commited/.git/objects/b3/
 extracting: commited/.git/objects/b3/7056e8583abc13547fe146c7ee9d905ac8488c
   creating: commited/.git/objects/44/
 extracting: commited/.git/objects/44/f3cb396ce178127b2dca6fa903113152710129
 extracting: commited/.git/objects/44/7ef7f1f03534fbea17f61ef3c2e610fcf23693
 extracting: commited/.git/objects/44/1daaaa600aef8021f273c8c66404d5283ed83e
   creating: commited/.git/objects/54/
 extracting: commited/.git/objects/54/d0271a615735240d22dcd737b4bf26cbe9d43f
   creating: commited/.git/objects/4e/
 extracting: commited/.git/objects/4e/ca752261f327712539fc04f81e7f335a69b429
 extracting: commited/.git/objects/4e/16af9349ed8eaa4a29decd82a7f1f9886a32db
   creating: commited/.git/objects/fd/
 extracting: commited/.git/objects/fd/132b91ad2a752dd39ce22bc1c55c0e5c38ab84
  inflating: commited/.git/index
   creating: commited/.git/hooks/
  inflating: commited/.git/hooks/fsmonitor-watchman.sample
  inflating: commited/.git/hooks/pre-push.sample
  inflating: commited/.git/hooks/pre-merge-commit.sample
  inflating: commited/.git/hooks/pre-rebase.sample
  inflating: commited/.git/hooks/post-update.sample
  inflating: commited/.git/hooks/prepare-commit-msg.sample
  inflating: commited/.git/hooks/update.sample
  inflating: commited/.git/hooks/commit-msg.sample
  inflating: commited/.git/hooks/applypatch-msg.sample
  inflating: commited/.git/hooks/pre-applypatch.sample
  inflating: commited/.git/hooks/pre-commit.sample
  inflating: commited/.git/hooks/pre-receive.sample
  inflating: commited/.git/config
 extracting: commited/.git/HEAD
   creating: commited/.git/branches/
  inflating: commited/.git/description
  inflating: commited/main.py
  inflating: commited/Readme.md
```

We then use `extractor.sh` from this repo:

https://github.com/internetwache/GitTools

```bash
joshua@kaligra:~/Documents/thm/gitandcrumpets$ bash extractor.sh ../committed/commited ../committed/commited2/
###########
# Extractor is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances.
# Only for educational purposes!
###########
[+] Found commit: 6e1ea88319ae84175bfe953b7791ec695e1ca004
[+] Found file: /home/joshua/Documents/thm/gitandcrumpets/../committed/commited2//0-6e1ea88319ae84175bfe953b7791ec695e1ca004/Note
[+] Found file: /home/joshua/Documents/thm/gitandcrumpets/../committed/commited2//0-6e1ea88319ae84175bfe953b7791ec695e1ca004/Readme.md
[+] Found file: /home/joshua/Documents/thm/gitandcrumpets/../committed/commited2//0-6e1ea88319ae84175bfe953b7791ec695e1ca004/main.py
[+] Found commit: 3a8cc16f919b8ac43651d68dceacbb28ebb9b625
..
..
..
```

### flag

```bash
joshua@kaligra:~/Documents/thm/committed/commited2$ grep -r flag *
1-3a8cc16f919b8ac43651d68dceacbb28ebb9b625/main.py:    password="flag{a489a9dbf8eb9d37c6e0cc1a92cda17b}" # Password Goes Here
1-3a8cc16f919b8ac43651d68dceacbb28ebb9b625/main.py:    password="flag{a489a9dbf8eb9d37c6e0cc1a92cda17b}", #password Goes here
1-3a8cc16f919b8ac43651d68dceacbb28ebb9b625/main.py:    password="flag{a489a9dbf8eb9d37c6e0cc1a92cda17b}",
```



