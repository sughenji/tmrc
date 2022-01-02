# Chill Hack

URL: https://tryhackme.com/room/chillhack



Level: Easy



Start time: 1 January 2021, 8:13pm GMT+1


End time: 2 January 2021, 2:15pm GMT+1


Actual play time: 4 hours 26 minutes


## Walkthrough

### Enumeration


#### NMAP


Let's start with a basic nmap scan:

```# nmap -T4 -p- -oN 01_nmap 10.10.183.96


# Nmap 7.91 scan initiated Sat Jan  1 20:12:21 2022 as: nmap -T4 -p- -oN 01_nmap 10.10.183.96
Nmap scan report for 10.10.183.96
Host is up (0.059s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

# Nmap done at Sat Jan  1 20:13:12 2022 -- 1 IP address (1 host up) scanned in 50.68 seconds
```







### FTP


### HTTP


