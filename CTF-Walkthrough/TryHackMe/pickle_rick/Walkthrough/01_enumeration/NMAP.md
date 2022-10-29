```
joshua@kaligra:~/Documents/thm/Pickle Rick/Walkthrough/01_nmap$ sudo nmap -T4 -Pn -p- 10.10.104.194 -oA nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-29 11:44 CEST
Nmap scan report for 10.10.104.194
Host is up (0.065s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 30.82 seconds
```

```
joshua@kaligra:~/Documents/thm/Pickle Rick/Walkthrough/01_nmap$ sudo nmap -T4 -Pn -p80 -sC -sV 10.10.104.194 -oA nmap_detailed
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-29 11:46 CEST
Nmap scan report for 10.10.104.194
Host is up (0.054s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Rick is sup4r cool

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.05 seconds

```



