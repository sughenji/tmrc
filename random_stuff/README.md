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
