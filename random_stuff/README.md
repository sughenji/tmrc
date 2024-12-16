# Random Stuff


- Linux
  - [Compiling C code on Linux](#compiling-c-code-on-linux)
  - [TMUX](#tmux)
  - [Ansible](#ansible)
  - [VIM](#vim)
  - [ulimit](#ulimit)
  - [bash]
	- [Process substitution](#process-substitution)
	- [eval](#eval)
- Github
  - [create ssh pair](#create-ssh-pair)
  - [switch to ssh authentication](#switch-to-ssh-authentication)

- TelegramBot
  - [create a bot](#create-a-bot)
  - [get chatid](#get-chatid)
  - [send message]
	 - [Python](#python)
	 - [Powershell](#powershell)
- Web
  - [Google Dorks](#google-dorks)
  - [Scraping Youtube playlist](#scraping-youtube-playlist)

- Networking
  - [wireguard](#wireguard)
  	- [wireguard on Windows server](#wireguard-on-windows-server)
  	- [wireguard on Mikrotik](#wireguard-on-mikrotik)
	- [wireguard roadwarrior](#wireguard-roadwarrior)
  - [scapy](#scapy)
	- [list commands](#list-commands)
	- [read pcap file](#read-pcap-file)
	- [print detail of a packet](#print-detail-of-a-packet)
	- [print field of a packet](#print-field-of-a-packet)
	- [print only icmp packet](#print-only-icmp-packet)
  	- [print only icmp echo request](#print-only-icmp-echo-request)
	- [forge icmp](#forge-icmp)
  - [wireshark](#wireshark)
	- [maxmind](#maxmind)
  - [rsync](#rsync)

- Wireless pentest
  - [cracking wpa](#cracking-wpa)
  - [hashcat rules](#hashcat-rules)

- Restic
  - [create repository](#restic-create-repository)
  - [backup](#restic-backup)
  - [forget](#restic-forget)
  - [check](#restic-check)
  - [script to check several repos](#restic-check-several-repos)
  - [restic script on gravity](#restic-script-on-gravity)




### Compiling C code on Linux

```
i686-w64-mingw32-gcc multiplestrings.c -o  multiplestrings.exe -lws2_32
```

NMAP:

https://seclists.org/nmap-dev/2017/q2/86

Doesn't work :(

```
$ file nmap
nmap: ELF 64-bit LSB pie executable, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=174172ed2f4b3791eb6dde98060cd7b1818bd2ad, for GNU/Linux 3.2.0, with debug_info, not stripped
```

Other resource:

https://github.com/kost/nmap-android/releases

### TMUX

Session -> can contain multiple windows -> which in turn can contain multiple panels

#### spawn new session

```
tmux new -s RSYSLOG
```

#### Resize pane down 

```
:resize-pane -D
```

#### Resize pane down 5 lines

```
:resize-pane -D 5
```

#### Toggle status bar

```
:set status off
```

#### "zoom" current pane

```
prefix+z
```

#### change prefix

Open `.tmux.conf` and set this

```
set -g prefix ^W
```

after:

```
:source-file .tmux.conf
```

#### load plugins

clone repository

```
git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
```

```
sugo@server$ cat .tmux.conf 

# plugins

set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'

# active plugins
run '~/.tmux/plugins/tpm/tpm'
```




### Ansible

Inventory:

```
sugo@vboxdebian:~/ansible$ cat inventory.yaml
matilda_cluster:
  hosts:
    relay01:
      ansible_host: 192.168.69.91
    relay02:
      ansible_host: 192.168.69.73
    relay03:
      ansible_host: 192.168.69.77

mailers:
  hosts:
    mailer1:
      ansible_host: 192.168.32.75
    mailer2:
      ansible_host: 192.168.32.69
    mailer3:
      ansible_host: 192.168.32.68

mailclusters:
  children:
    matilda_cluster:
    mailers:

rancid:
  hosts:
    rancido:
      ansible_host: 192.168.50.253
```

`apt update` playbook:

```
sugo@vboxdebian:~/ansible$ cat mailclusters_debian_update.yaml
---
- hosts: mailclusters
  tasks:
    - name: Run apt update
      apt: update_cache=yes force_apt_get=yes cache_valid_time=3600
```

(we are using `root` user)

```
ansible-playbook -i inventory.yaml  mailclusters_debian_update.yaml -u root
```

`apt update && apt upgrade` playbook:

```
sugo@vboxdebian:~/ansible$ cat mailclusters_debian_upgrade.yaml
---
- hosts: mailclusters
  tasks:
    - name: Run apt update
      apt: update_cache=yes force_apt_get=yes cache_valid_time=3600
    - name: Run apt upgrade
      apt: upgrade=dist force_apt_get=yes
```

For `yum update`:

Add your user to `sudoers`, like:

```
# to allow yum 
sugo            ALL=(ALL)       NOPASSWD: /usr/bin/yum
```

Populate your inventory:

```
diameters:
  hosts:
    diameter:
      ansible_host: xx.yy.69.82
    diameter2:
      ansible_host: xx.yy.69.4
    diameter3:
      ansible_host: xx.yy.69.80
```

Use `shell` module:

```
$ ansible diameters -m shell -i inventory.yaml -usugo -a "sudo yum update -y"
```




### VIM

remove all highlights:

```
:noh
```

### ulimit

```
# sudo -u bareos bash -c 'ulimit -n'
1024
```

https://woshub.com/too-many-open-files-error-linux/

## bash

### process substitution

Useful if you want, for example, compare two directories.

```bash
joshua@kaligra:~$ ls dir1
a  b  c  d  f
joshua@kaligra:~$ ls dir2
b  c  e
joshua@kaligra:~$ diff <(ls dir1) <(ls dir2)
1d0
< a
4,5c3
< d
< f
---
> e
```

```bash
joshua@kaligra:~$ cat <(ls dir1)
a
b
c
d
f
joshua@kaligra:~$ echo <(ls dir1)
/dev/fd/63
```

### eval

with `eval` the commands affect the current shell

https://stackoverflow.com/questions/43001805/whats-the-difference-between-eval-command-and-command

"If you know that a variable contains an executable command you can run it without eval. But if the variable might contain Bash code which is not simply an executable command (i.e. something you could imagine passing to the C function exec()), you need eval"

## Github

### Create SSH keypair:

```
ssh-keygen -t rsa -C github
```

(then we need to upload **public** key to our repository)

start SSH agent and add our private key:

```
eval $(ssh-agent)
ssh-add id_rsa_github
```

### switch to ssh authentication

```
git remote set-url origin git@github.com:sughenji/nomedelrepository.git
```

## TelegramBot

### create a bot

Use `BotFather` and type: `/newbot`

Select Name, username.

You will receive your token

### get chatid

Create a group, add your new bot to group.

Visite this link (with YOUR token) and get your Chat ID (eg. -3473842)

https://api.telegram.org/bot6577957123:AAEusEImcUt3xm8YESrTS6oagbsd-O_qwPk/getUpdates

### send message

#### python

```
#!/usr/bin/python3
import requests

def send_to_telegram(message):

    apiToken = '6577957123:AAEusEImcUt3xm8NOTrTS6oagasd-O_qwPk'
    # gruppo "Sugo bot"
    chatID= '-628611232'
    apiURL = f'https://api.telegram.org/bot{apiToken}/sendMessage'

    try:
        response = requests.post(apiURL, json={'chat_id': chatID, 'text': message})
        print(response.text)
    except Exception as e:
        print(e)

send_to_telegram("Hello from Python!")
```

#### powershell

```
$Message="ciao"
$Telegramtoken = "6577957123:AAEusEImcUt3xm8NOTrTS6oagasd-O_qwPk"
$Telegramchatid = "-62861232"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-RestMethod -Uri "https://api.telegram.org/bot$($Telegramtoken)/sendMessage?chat_id=$($Telegramchatid)&text=$($Message)"
```

## web

### google dorks

```
ext:inc "<?php"
```

### scraping youtube playlist

```bash
# apt install yt-dlp
$ yt-dlp --flat-playlist -i --print-to-file url malicious_pdf_analysys.txt "https://www.youtube.com/playlist?list=PLa-ohdLO29_Y2FeT24w-c9nA_AH84MIpp"
```

Enjoy your `malicious_pdf_analysys.txt` file with all links

## networking

## wireguard

### wireguard on Windows server

Generate private key:

```
root@kaligra:~# wg genkey
wAoz6b20shdfErHX5M4kxb6b/UjwUzKiKuAhXd2NU3w=
```

Generate public key:

```
root@kaligra:~# echo -n "wAoz6b20shdfErHX5M4kxb6b/UjwUzKiKuAhXd2NU3w=" | wg pubkey
9elkoSVZnhHTBbFf95wIn3EfNfqR4RFqic88GtbcWUs=
```

Very simple configuration file on server:

```
[Interface]
Address = 192.168.143.1/24
Privatekey = wAoz6b20shdfErHX5M4kxb6b/UjwUzKiKuAhXd2NU3w= (private key from above)
ListenPort = 12345
```

Now move on the first client, let's create one (same step as above for private/public keys).

Now let's generate configuration file on the first client:

```
# cat sugovpn.conf 
[Interface]
PrivateKey = aHVleM[CLIENT_PRIVATE_KEY]BxKuWXrRCjGE=
Address = 192.168.143.2/24 <- pick another address in the same lan segment

[Peer]
PublicKey = 9elkoSVZnhHTBbFf95wIn3EfNfqR4RFqic88GtbcWUs= <- this is the public key from SERVER
AllowedIPs = 192.168.143.1/32 <- this says: which ip/net do you want to reach through VPN?
Endpoint = 46.252.144.172:12345 <- public ip address and port of SERVER
PersistentKeepalive = 60
```


Now add this first client to your server configuration:


```
..
..
..
[Peer]
# sugovpn
Publickey = 40WjR2h5[CLIENT_PUBLIC_KEY]Jksdgws=
AllowedIPs = 192.168.143.2/24 <- same Address you wrote on sugovpn.conf file
```

To reload server configuration

```
wg-reload wg0
```

To start client (if config file is in `/etc/wireguard/wg0.conf`):

```
wg-quick up wg0
```

Windows Tips: basically I used this solutions:

https://github.com/micahmo/WgServerforWindowso

everything went smoothly, but I noticed that often the "Nat routing" was disabled.

I wrote this simple script:

```powershell
# Command to check (replace this with your actual command)
$commandOutput = Get-NetNat 

# Check if the output is empty
if (-not $commandOutput) {
    Write-Host "Command returned nothing. Launching another script..."
    new-netnat -name wg_server_nat -InternalIPInterfaceAddressPrefix 10.253.0.1/24
	    
}
```

### wireguard on mikrotik

VPN site-to-site

reference:

https://help.mikrotik.com/docs/display/ROS/WireGuard

On Mikrotik on site 1 (LAN: `192.168.101.0/24`, PUBLIC IP: `188.34.72.4`):

Create interface:

```
/interface/wireguard
add listen-port=13231 name=wireguard1
```

Take note on `public key` of site 1, let's say `SITE1PUBKEY`.

Configure an IP address on interface `wireguard1`, let's say `SITE1WGIP`, eg. `10.0.0.1/24`.

On Mikrotik on site 2 (LAN: `192.168.102./24`, PUBLIC IP: `65.42.43.23`):

```
/interface/wireguard
add listen-port=13231 name=wireguard1
```

Take note on `public key` of site 2, let's say `SITE2PUBKEY`.

Configure an IP address on interface `wireguard1`, let's say `SITE2WGIP`, eg. `10.0.0.2/24`.

On Mikrotik on site 1:

Add peer interface:

N.B.

**You must put in `allowed-address` the remote network, and even the remote peer wireguard IP (`SITE2WGIP`).**

```
/interface/wireguard/peers
add allowed-address=192.168.102.0/24,10.0.0.2/32 endpoint-address=65.42.43.23 endpoint-port=13231 interface=wireguard1 \
public-key="SITE2PUBKEY"
```

Configure a static route to SITE2 remote LAN network:

```
/ip/route
add dst-address=192.168.102.0/24 gateway=wireguard1
```

On Mikrotik on site 2:

Add peer interface:

```
/interface/wireguard/peers
add allowed-address=192.168.101.0/24,10.0.0.1/32 endpoint-address=188.34.72.4 endpoint-port=13231 interface=wireguard1 \
public-key="SITE1PUBKEY"
```

Configure a static route to SITE1 remote LAN network:

```
/ip/route
add dst-address=192.168.101.0/24 gateway=wireguard1
```

### wireguard roadwarrior

On Mikrotik, add a new peer.

Public key is the key you obtain from roadwarrior device.

Preshared key is the psk that you obtain from roadwarrior device, or: `wg genpsk` on Linux).

Allowed Address is the IP address configured on your roadwarrior device (eg. `10.0.0.69/24`)

On roadwarrior device (eg. Android device):

address = `10.0.0.69/24`

Peer:

public key: the public key from Mikrotik endpoint

PSK: see above

Endpoint: Mikrotik's public IP address

AllowedIPs: remote LAN behind Mikrotik (eg. `192.168.88.0/24`)

N.B. to route ALL traffic to wireguard tunnel, simply type in your roadwarrior device:

`AllowedIPs: 0.0.0.0/0`

## scapy

### list commands

```
>>> lsc()
IPID_count          : Identify IP id values classes in a list of packets
arpcachepoison      : Poison target's cache with (your MAC,victim's IP) couple
arping              : Send ARP who-has requests to determine which hosts are up
arpleak             : Exploit ARP leak flaws, like NetBSD-SA2017-002.
bind_layers         : Bind 2 layers on some specific fields' values.
bridge_and_sniff    : Forward traffic between interfaces if1 and if2, sniff and return
chexdump            : Build a per byte hexadecimal representation
computeNIGroupAddr  : Compute the NI group Address. Can take a FQDN as input parameter
..
..
```


### read pcap file

```
>>> from scapy.all import *
>>> rdpcap("/home/sugo/github/tmrc/network_traffic_analysis/eternalblue.pcap")
<eternalblue.pcap: TCP:1420 UDP:0 ICMP:0 Other:0>
```

or

```
>>> from scapy.all import *
>>> packets = rdpcap("/home/sugo/github/tmrc/network_traffic_analysis/eternalblue.pcap")
>>> packets.summary
<bound method _PacketList.summary of <eternalblue.pcap: TCP:1420 UDP:0 ICMP:0 Other:0>>
```

### print detail of a packet

```
>>> pkts[0].show()
###[ Ethernet ]###
  dst       = 52:54:00:12:35:00
  src       = 08:00:27:2f:03:77
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 84
..
..
```

### print field of a packet

```
>>> pkts[0].load
b'{\xbf\x93b\x00\x00\x00\x00\xadm\x06\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567'
```

### print only icmp packet

```
>>> pkts.summary
<bound method _PacketList.summary of <esercitazione_20230529.pcapng: TCP:1464 UDP:0 ICMP:50 Other:9>>
>>> pkts[ICMP].summary()
Ether / IP / ICMP 10.0.2.8 > 10.0.2.5 echo-request 0 / Raw
Ether / IP / ICMP 10.0.2.5 > 10.0.2.8 echo-reply 0 / Raw
Ether / IP / ICMP 10.0.2.8 > 10.0.2.5 echo-request 0 / Raw
..
..
```

### print only icmp echo request

```
from scapy.all import *

pkts = rdpcap("onlyicmp.pcap")

for p in pkts:
    if p[ICMP].type == 8:
        print(p[ICMP].id)
```


### forge icmp

with root or sudo rights


```python
>>> from scapy.all import *
>>> pingr = IP(dst="46.252.144.172")/ICMP()
>>> sr1(pingr)
```

get response:

```python
>>> resp = sr1(pingr)
Begin emission:
..Finished to send 1 packets.
.*
Received 147 packets, got 1 answers, remaining 0 packets
>>> resp[0].summary()
'IP / ICMP 4.2.2.1 > 172.16.20.40 echo-reply 0 / Padding'
```



## wireshark

### maxmind

Download files:

GeoLite2-ASN_

GeoLite2-City_

GeoLite2-Country

Go to Preferences -> Name Resolution -> MaxMind Database Directories

Go to Statistics -> Endpoints -> map

## rsync

Test for available shares on remote target (WITH authentication):

```
root@avatar:~# rsync backupuser@1.2.3.4::
Password: 
Multimedia     
Download       
Public         
homes       
```


## Wireless pentest

### cracking wpa

```
hashcat.exe -m 22000 ..\other.hc22000 d:\tmrc\hacking\wordlist\rockyou.txt
```

### hashcat rules

```
$ hashcat --stdout -r spipbest.rule wordlist.txt > wordlistpostrule.txt
```

```
$ hashcat --force --stdout -r /usr/share/hashcat/rules/best64.rule wordlist > wordlistpostrule
```

## restic create repository

```bash
restic -p /root/.restic_password -r sftp://backup_username@1.2.3.4/home/backup_username/ init
```

## restic backup

```bash
restic -p /root/.restic_password  -r sftp://backup_username@1.2.3.4/home/backup_username/  backup /etc /var/backups
```

## restic forget

Remember to actually prune data!

```bash
restic -p /root/.restic_password  -r sftp://backup_username@1.2.3.4/home/backup_username/ forget --keep-daily 6 --keep-weekly 2 --prune
```

## restic check

```bash
restic -p /root/.restic_password -r ... check
```

If you want a more reliable check, please add `--read-data`
 
## restic check several repos

(Passwords are store on encrypted luks device)

```bash
#!/bin/bash

# first, we need to unlock our vault

/usr/sbin/cryptsetup open --type luks /root/scripts/vaultfile myvault

/usr/bin/mount /dev/mapper/myvault /mnt/vault

# read repository's pass from file and start checking

for i in $(cat /mnt/vault/data.txt); do
        ACCOUNT=`echo $i | awk -F ',' '{ print $1 }'`
        KEY=`echo $i | awk -F ',' '{ print $2 }'`
        export RESTIC_PASSWORD_COMMAND="echo $KEY"
        echo "Checking repository: $ACCOUNT"
        restic check -r /home/$ACCOUNT
        if [ $? -ne 0 ]; then
                echo "Errors detected"!
        fi
done

# umount vault

/bin/umount /mnt/vault

# close vault

/usr/sbin/cryptsetup close myvault
```

## restic script on gravity

```
S C:\scripts> Get-Content .\restic_backup.bat
restic -r E:\ backup D:\cellulari D:\data D:\guitar D:\immagini D:\Listening D:\software D:\tmrc D:\video --exclude-file C:\scripts\restic_exclude.txt
restic -r E:\ forget --keep-yearly 12 --prune --cleanup-cache
```

```
PS C:\scripts> Get-Content C:\scripts\restic_exclude.txt
D:\tmrc\hacking\Br........
"D:\tmrc\hacking\The .........\labs"
D:\tmrc\hacking\wordlist
```

