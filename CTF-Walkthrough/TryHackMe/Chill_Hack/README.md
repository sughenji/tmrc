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

```
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

We got 3 open ports. Let's check again with service detection (-sV) and default script (-sC):

```
# Nmap 7.91 scan initiated Sat Jan  1 20:13:58 2022 as: nmap -T4 -p21,22,80 -sV -sC -oN 02_nmap 10.10.183.96
Nmap scan report for 10.10.183.96
Host is up (0.057s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.8.147.132
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 09:f9:5d:b9:18:d0:b2:3a:82:2d:6e:76:8c:c2:01:44 (RSA)
|   256 1b:cf:3a:49:8b:1b:20:b0:2c:6a:a5:51:a8:8f:1e:62 (ECDSA)
|_  256 30:05:cc:52:c6:6f:65:04:86:0f:72:41:c8:a4:39:cf (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Game Info
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan  1 20:14:21 2022 -- 1 IP address (1 host up) scanned in 22.55 seconds
```

### FTP

Since we see that anonymous FTP is allowed, we grab the note.txt file:

```
# ftp 10.10.183.96
Connected to 10.10.183.96.
220 (vsFTPd 3.0.3)
Name (10.10.183.96:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
226 Directory send OK.
ftp> get note.txt
local: note.txt remote: note.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note.txt (90 bytes).
226 Transfer complete.
90 bytes received in 0.00 secs (122.4103 kB/s)
ftp> quit
221 Goodbye.


# cat note.txt
Anurodh told me that there is some filtering on strings being put in the command -- Apaar
```

We got a note from Anurodh about some strings filtering mechanism in action. We will see it soon. 


### HTTP


