# Smag Grotto

URL: https://tryhackme.com/room/smaggrotto

Level: Easy

Start time: 1 February 2022, 4:37pm GMT+1

End time: 1 February 2022, 7:24pm GMT+1

Actual play time: 1 hours 31 minutes

## Walkthrough

### Enumeration


#### NMAP


Let's start with a basic nmap scan:

```
# Nmap 7.92 scan initiated Tue Feb  1 16:36:16 2022 as: nmap -T4 -p- -oN 01_nmap 10.10.175.45
Nmap scan report for 10.10.175.45
Host is up (0.063s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

# Nmap done at Tue Feb  1 16:37:29 2022 -- 1 IP address (1 host up) scanned in 73.32 seconds
```

We got 2 open ports. Let's check again with service detection (-sV) and default script (-sC):

```
# Nmap 7.92 scan initiated Tue Feb  1 16:38:28 2022 as: nmap -T4 -p22,80 -sC -sV -oN 02_nmap 10.10.175.45
Nmap scan report for 10.10.175.45
Host is up (0.056s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 74:e0:e1:b4:05:85:6a:15:68:7e:16:da:f2:c7:6b:ee (RSA)
|   256 bd:43:62:b9:a1:86:51:36:f8:c7:df:f9:0f:63:8f:a3 (ECDSA)
|_  256 f9:e7:da:07:8f:10:af:97:0b:32:87:c9:32:d7:1b:76 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Smag
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Feb  1 16:38:39 2022 -- 1 IP address (1 host up) scanned in 10.67 seconds
```
#### HTTP

We check target with our browser:

![Screenshot_2022-02-01_16-40-47](https://user-images.githubusercontent.com/42389836/152342610-54607455-611b-43c5-9873-9b6a4bfbc1e2.png)

Nothing interesting in HTML source. We run `gobuster`:

```
root@kaligra:/opt/thm/Smag_Grotto# gobuster dir -u http://10.10.175.45 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.175.45
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/02/01 16:46:23 Starting gobuster in directory enumeration mode
===============================================================
/mail                 (Status: 301) [Size: 311] [--> http://10.10.175.45/mail/]
/server-status        (Status: 403) [Size: 277]

===============================================================
2022/02/01 17:08:06 Finished
===============================================================
```

We open /mail folder and we found a webpage with some email messages:

![Screenshot_2022-02-01_16-47-02](https://user-images.githubusercontent.com/42389836/152342955-babb1e48-6c12-48fb-b6b0-8bc5db0f0478.png)

There is a .pcap file, we download it and open in Wireshark:

![Screenshot_2022-02-01_16-49-46](https://user-images.githubusercontent.com/42389836/152343129-ccd7eb07-5ef0-4e90-bdc3-1fc3ff2ff7c1.png)

![Screenshot_2022-02-01_16-50-11](https://user-images.githubusercontent.com/42389836/152343217-e513e1f2-b6c8-4f29-9f5a-383d02791a8e.png)

