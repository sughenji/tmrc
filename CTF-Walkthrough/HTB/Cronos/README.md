# Cronos

URL: https://app.hackthebox.com/machines/Cronos

Level: Medium

Start time: 22 Jan 2022, 4:24pm GMT+1

End time: 22 Jan 2022, 6:36pm GMT+1

Actual play time: 1 hours 25 minutes


## Walkthrough

### Enumeration

#### NMAP

Basic nmap scan:

```
# Nmap 7.92 scan initiated Sat Jan 22 16:23:06 2022 as: nmap -T4 -p- -oN 01_nmap 10.10.10.13
Nmap scan report for 10.10.10.13
Host is up (0.055s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http

# Nmap done at Sat Jan 22 16:24:45 2022 -- 1 IP address (1 host up) scanned in 99.27 seconds
```

Again with -sC and -sV:

```
# Nmap 7.92 scan initiated Sat Jan 22 16:25:35 2022 as: nmap -T4 -p22,53,80 -sC -sV -oN 02_nmap 10.10.10.13
Nmap scan report for 10.10.10.13
Host is up (0.063s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan 22 16:25:52 2022 -- 1 IP address (1 host up) scanned in 16.89 seconds
```

Let's check more about DNS (since we have 53/TCP open, we also run UDP scan):

```
# Nmap 7.92 scan initiated Sat Jan 22 16:35:46 2022 as: nmap -T4 -p53 -sU -sT -sV --script=dns-check-zone.nse,dns-srv-enum.nse,dns-zone-transfer.nse -oN 03_nmap_DNS_enum 10.10.10.13
Nmap scan report for 10.10.10.13
Host is up (0.052s latency).

PORT   STATE SERVICE VERSION
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
53/udp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan 22 16:35:53 2022 -- 1 IP address (1 host up) scanned in 7.02 seconds
```

Web server shows a default Apache page, let's assume that there is "virtual host routing" involved.

We put cronos.htb in our /etc/hosts file:

```
root@kaligra:/usr/share/nmap/scripts# grep crono /etc/hosts
10.10.10.13     cronos.htb
```

We check again web server, we obtain another page:

![Screenshot_2022-01-22_16-41-12](https://user-images.githubusercontent.com/42389836/150674604-5aa175bf-3fa6-474a-bdbf-fb38760fd94f.png)

Nothing interesting in HTML source code:

```
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <title>Cronos</title>

        <!-- Fonts -->
        <link href="https://fonts.googleapis.com/css?family=Raleway:100,600" rel="stylesheet" type="text/css">

        <!-- Styles -->
        <style>
            html, body {
                background-color: #fff;
                color: #636b6f;
                font-family: 'Raleway', sans-serif;
                font-weight: 100;
                height: 100vh;
                margin: 0;
            }

            .full-height {
                height: 100vh;
            }

            .flex-center {
                align-items: center;
                display: flex;
                justify-content: center;
            }

            .position-ref {
                position: relative;
            }

            .top-right {
                position: absolute;
                right: 10px;
                top: 18px;
            }

            .content {
                text-align: center;
            }

            .title {
                font-size: 84px;
            }

            .links > a {
                color: #636b6f;
                padding: 0 25px;
                font-size: 12px;
                font-weight: 600;
                letter-spacing: .1rem;
                text-decoration: none;
                text-transform: uppercase;
            }

            .m-b-md {
                margin-bottom: 30px;
            }
        </style>
    </head>
    <body>
        <div class="flex-center position-ref full-height">

            <div class="content">
                <div class="title m-b-md">
                    Cronos
                </div>

                <div class="links">
                    <a href="https://laravel.com/docs">Documentation</a>
                    <a href="https://laracasts.com">Laracasts</a>
                    <a href="https://laravel-news.com">News</a>
                    <a href="https://forge.laravel.com">Forge</a>
                    <a href="https://github.com/laravel/laravel">GitHub</a>
                </div>
            </div>
        </div>
    </body>
</html>
```

So, we assume that there is another virtual host with other stuff. Let's focus again on DNS.

We try zone transfer (AXFR) and we get more DNS records:

```
root@kaligra:/opt/htb/Cronos# dig axfr @10.10.10.13 cronos.htb

; <<>> DiG 9.17.19-1-Debian <<>> axfr @10.10.10.13 cronos.htb
; (1 server found)
;; global options: +cmd
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.             604800  IN      NS      ns1.cronos.htb.
cronos.htb.             604800  IN      A       10.10.10.13
admin.cronos.htb.       604800  IN      A       10.10.10.13
ns1.cronos.htb.         604800  IN      A       10.10.10.13
www.cronos.htb.         604800  IN      A       10.10.10.13
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
;; Query time: 136 msec
;; SERVER: 10.10.10.13#53(10.10.10.13) (TCP)
;; WHEN: Sat Jan 22 16:40:06 CET 2022
;; XFR size: 7 records (messages 1, bytes 203)
```

So, we need to also add admin.cronos.htb on our /etc/hosts file.

Let's check web page:

![Screenshot_2022-01-22_16-41-49](https://user-images.githubusercontent.com/42389836/150674731-6d2311c5-0519-4123-b931-38ab41218c70.png)

We get a basic login page.

We try a very basic SQLi string:

![Screenshot_2022-01-22_17-53-20](https://user-images.githubusercontent.com/42389836/150674756-b5a9b790-8e7e-4e2a-ba77-67ffe22a49e3.png)


And we get access.

![Screenshot_2022-01-22_16-43-18](https://user-images.githubusercontent.com/42389836/150674781-498194a8-4539-497b-82ae-ccc506a00d56.png)


