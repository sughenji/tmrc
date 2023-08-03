# Git Happens

URL: https://tryhackme.com/room/githappens

Level: Easy

Date: 3 Aug 2023

## nmap

```bash
joshua@kaligra:~/Documents/thm/githappens$ sudo nmap -T4 -p- -n 10.10.25.68 -oA nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-03 15:59 CEST
Nmap scan report for 10.10.25.68
Host is up (0.072s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 111.43 seconds
```

```bash
joshua@kaligra:~/Documents/thm/githappens$ sudo nmap -T4 -p80 -n -sC -sV 10.10.25.68 -oA nmap2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-03 16:01 CEST
Nmap scan report for 10.10.25.68
Host is up (0.056s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.0 (Ubuntu)
| http-git:
|   10.10.25.68:80/.git/
|     Git repository found!
|_    Repository description: Unnamed repository; edit this file 'description' to name the...
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Super Awesome Site!
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.30 seconds
```

We got `.git` path discovered, we just use `feroxbuster` with a longer wordlist:

## feroxbuster

```bash
joshua@kaligra:~/Documents/thm/githappens$ feroxbuster --silent  -u http://10.10.25.68 -t 200 -L 1 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -o ferox.txt
http://10.10.25.68/
http://10.10.25.68/css => http://10.10.25.68/css/
```

```bash
joshua@kaligra:~/Documents/thm/githappens$ feroxbuster --silent  -u http://10.10.25.68 -t 200 -L 1 -w /opt/SecLists/Discovery/Web-Content/common.txt -o ferox.txt2
http://10.10.25.68/
http://10.10.25.68/.git/logs/
http://10.10.25.68/.git => http://10.10.25.68/.git/
http://10.10.25.68/.git/HEAD
http://10.10.25.68/.git/config
http://10.10.25.68/.git/index
http://10.10.25.68/css => http://10.10.25.68/css/
http://10.10.25.68/index.html
```

## git

Let's clone repository with `wget`:

```bash
joshua@kaligra:~/Documents/thm/githappens/git$ wget -r http://10.10.25.68/.git/
--2023-08-03 16:06:09--  http://10.10.25.68/.git/
Connecting to 10.10.25.68:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘10.10.25.68/.git/index.html’

10.10.25.68/.git/index.html                         [ <=>                                                                                                  ]   1.36K  --.-KB/s    in 0s

2023-08-03 16:06:09 (112 MB/s) - ‘10.10.25.68/.git/index.html’ saved [1391]

..
..
..
Saving to: ‘10.10.25.68/.git/logs/refs/heads/master’

10.10.25.68/.git/logs/refs/heads/master         100%[=====================================================================================================>]     216  --.-KB/s    in 0s

2023-08-03 16:06:15 (30.2 MB/s) - ‘10.10.25.68/.git/logs/refs/heads/master’ saved [216/216]

FINISHED --2023-08-03 16:06:15--
Total wall clock time: 6.3s
Downloaded: 102 files, 72K in 0.003s (20.4 MB/s)

```

Let's check repository's history:

```bash
joshua@kaligra:~/Documents/thm/githappens/git/10.10.25.68$ git log
commit d0b3578a628889f38c0affb1b75457146a4678e5 (HEAD -> master, tag: v1.0)
Author: Adam Bertrand <hydragyrum@gmail.com>
Date:   Thu Jul 23 22:22:16 2020 +0000

    Update .gitlab-ci.yml

commit 77aab78e2624ec9400f9ed3f43a6f0c942eeb82d
Author: Hydragyrum <hydragyrum@gmail.com>
Date:   Fri Jul 24 00:21:25 2020 +0200

    add gitlab-ci config to build docker file.

commit 2eb93ac3534155069a8ef59cb25b9c1971d5d199
Author: Hydragyrum <hydragyrum@gmail.com>
Date:   Fri Jul 24 00:08:38 2020 +0200

    setup dockerfile and setup defaults.

commit d6df4000639981d032f628af2b4d03b8eff31213
Author: Hydragyrum <hydragyrum@gmail.com>
Date:   Thu Jul 23 23:42:30 2020 +0200

    Make sure the css is standard-ish!

commit d954a99b96ff11c37a558a5d93ce52d0f3702a7d
Author: Hydragyrum <hydragyrum@gmail.com>
Date:   Thu Jul 23 23:41:12 2020 +0200

    re-obfuscating the code to be really secure!

commit bc8054d9d95854d278359a432b6d97c27e24061d
Author: Hydragyrum <hydragyrum@gmail.com>
Date:   Thu Jul 23 23:37:32 2020 +0200

    Security says obfuscation isn't enough.

    They want me to use something called 'SHA-512'

commit e56eaa8e29b589976f33d76bc58a0c4dfb9315b1
Author: Hydragyrum <hydragyrum@gmail.com>
Date:   Thu Jul 23 23:25:52 2020 +0200

    Obfuscated the source code.

    Hopefully security will be happy!

commit 395e087334d613d5e423cdf8f7be27196a360459
Author: Hydragyrum <hydragyrum@gmail.com>
Date:   Thu Jul 23 23:17:43 2020 +0200

    Made the login page, boss!

commit 2f423697bf81fe5956684f66fb6fc6596a1903cc
Author: Adam Bertrand <hydragyrum@gmail.com>
Date:   Mon Jul 20 20:46:28 2020 +0000

    Initial commit

```

In the second commit we see comment "Made the login page, boss!" while in third commit "Obfuscated the source code"

We can assume that on commit `395e087334d613d5e423cdf8f7be27196a360459` we will find something in cleartext:

```bash
joshua@kaligra:~/Documents/thm/githappens/git/10.10.25.68$ git diff 395e087334d613d5e423cdf8f7be27196a360459
diff --git a/README.md b/README.md
deleted file mode 100644
index 209515b..0000000
--- a/README.md
+++ /dev/null
@@ -1,3 +0,0 @@
-# git-fail
-
-Sometimes, bad things happen to good sites
\ No newline at end of file
diff --git a/css/style.css b/css/style.css
index 48926fd..4cf7572 100644
--- a/css/style.css
+++ b/css/style.css
@@ -178,7 +178,9 @@ body:before {
   );
   text-align: center;
   background-size: 800% 800%;
+  background-clip: text;
   -webkit-background-clip: text;
+  color: transparent;
   -webkit-text-fill-color: transparent;
   font-size: 24px;
   animation: rainbow 8s ease infinite;
diff --git a/dashboard.html b/dashboard.html
..
..
..
console.log(form.elements);
-        let username = form.elements["username"].value;
-        let password = form.elements["password"].value;
-        if (
-          username === "admin" &&
-          password === "Th1s_1s_4_L0ng_4nd_S3cur3_P4ssw0rd!"
..
..
..
```

We found our flag.

