# Random Stuff

- Windows
  - [Mount SSHFS](#mount-sshfs)
  - [Accessing SMB](#accessing-smb)
  - [Capture traffic](#capture-traffic)
  - [Powershell Test Connection](#powershell-test-connection)
  - [Update Notify Windows](#update-notify-windows)
  - [psexec](#psexec)
  - [Install openssh server powershell](#install-openssh-server-powershell)
  - [Manage Firewall with powershell](#manage-firewall-with-powershell)
- Linux
  - [Compiling C code on Linux](#compiling-c-code-on-linux)
  - [TMUX](#tmux)
  - [Ansible](#ansible)
  - [VIM](#vim)
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

- Networking
  - [wireguard](#wireguard)
  	- [wireguard on Windows server](#wireguard-on-windows-server)
  	- [wireguard on Mikrotik](#wireguard-on-mikrotik)
	- [wireguard roadwarrior](#wireguard-roadwarrior)
  

### Mount SSHFS

First install this:

https://github.com/winfsp/winfsp/releases

Then this:

https://github.com/winfsp/sshfs-win


```
net use s: \\sshfs.r\user@192.168.1.14!22222\home\user\Documents
```

```
net use s: /delete
```

### Accessing smb

Mount C$ with AD credentials:

```
mount -t cifs \\\\192.168.1.14\\C$ /mnt/ -o domain=SUGOLANDIA,user=sugo
```

### Capture traffic

Capture network traffic with files rotation

```
tshark.exe -b interval:3600 -b files:48 -f "port 53" -i Ethernet0 -w c:\users\sugo\downloads\traffic.pcapng
```

### Powershell test connection

```
PS C:\Users\sugo> Test-NetConnection -Port 1080 172.30.1.149
ComputerName     : 172.30.1.149
RemoteAddress    : 172.30.1.149
RemotePort       : 1080
InterfaceAlias   : Ethernet
SourceAddress    : 192.168.88.14
TcpTestSucceeded : True
```

### Update Notify Windows

```
$WUCOMPUTERNAME = (Get-CIMInstance CIM_ComputerSystem).name
$WUSUBJECT = "Windows Updates available for " + $WUCOMPUTERNAME
$WURECIPIENT = "checkupdate@micso.net"
$WURELAY = "relay.micso.it"
$WUFROM = $WUCOMPUTERNAME + "@micso.it"
$WULIST = Get-WUList
$HTMLBODY = ($WULIST|select KB,Title|ConvertTo-Html -As LIST -Head $WUCOMPUTERNAME|Out-String)
Send-MailMessage -To $WURECIPIENT -From $WUFROM -Subject $WUSUBJECT -SmtpServer $WURELAY -Body $HTMLBODY -BodyAsHtml
#Write-Output $HTMLBODY
```

### psexec

```
c:\SysinternalSuite>PsExec.exe -accepteula -s \\nomecomputer-pc cmd
```

```
c:\Users\Administrator\Downloads>net use x: \\192.168.1.129\Download /user:Administrator
Esecuzione comando riuscita.
c:\Users\Administrator\Downloads>x:
X:\wazuh-agent>copy wazuh-agent-4.4.1-1.msi c:\users\administrator\downloads\
        1 file copiati.
```

```
c:\Users\Administrator\Downloads>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. Tutti i diritti riservati.

Prova la nuova PowerShell multipiattaforma https://aka.ms/pscore6

PS C:\Users\Administrator\Downloads> .\wazuh-agent-4.4.1-1.msi /q WAZUH_MANAGER="192.168.10.5"
PS C:\Users\Administrator\Downloads> PS C:\Users\Administrator\Downloads> net start WazuhSvc

Avvio del servizio Wazuh riuscito.
```

### Install Openssh server Powershell

```
Get-WindowsCapability -Online | ? Name -like 'OpenSSH*'
```

```
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

```
PS C:\Windows\system32> get-service sshd

Status   Name               DisplayName
------   ----               -----------
Stopped  sshd               OpenSSH SSH Server
```

```
Set-Service -Name sshd -StartupType 'Automatic'
```

```
Start-Service sshd
```

### Manage firewall with powershell

```
PS C:\Windows\system32> Get-NetFirewallRule -DisplayName "Condivisione file e stampanti (richiesta echo - ICMPv4-In)"
Name                          : FPS-ICMP4-ERQ-In-NoScope
DisplayName                   : Condivisione file e stampanti (richiesta echo - ICMPv4-In)
Description                   : I messaggi di richiesta echo vengono inviati come richieste di ping agli altri nodi.
DisplayGroup                  : Condivisione file e stampanti
Group                         : @FirewallAPI.dll,-28502
Enabled                       : False <===============
Profile                       : Domain
..
..
..
```

To enable on ALL profiles:

```
PS C:\Windows\system32> Get-NetFirewallRule -DisplayName "Condivisione file e stampanti (richiesta echo - ICMPv4-In)" | where Profile -CLike "*" |  Enable-NetFirewallRule
PS C:\Windows\system32>
```






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

### Google Dorks

```
ext:inc "<?php"
```

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

