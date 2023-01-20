# Random Stuff

- [Mount SSHFS](#mount-sshfs)
- [Accessing SMB](#accessing-smb)
- [Capture traffic](#capture-traffic)
- [Powershell Test Connection](#powershell-test-connection)
- [Compiling C code on Linux](#compiling-c-code-on-linux)
- [TMUX](#tmux)
- [Update Notify Windows](#update-notify-windows)
- [Github](#github)
- [Ansible](#ansible)

## Mount SSHFS

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

## Accessing smb

Mount C$ with AD credentials:

```
mount -t cifs \\\\192.168.1.14\\C$ /mnt/ -o domain=SUGOLANDIA,user=sugo
```

## Capture traffic

Capture network traffic with files rotation

```
tshark.exe -b interval:3600 -b files:48 -f "port 53" -i Ethernet0 -w c:\users\sugo\downloads\traffic.pcapng
```

## Powershell test connection

```
PS C:\Users\sugo> Test-NetConnection -Port 1080 172.30.1.149
ComputerName     : 172.30.1.149
RemoteAddress    : 172.30.1.149
RemotePort       : 1080
InterfaceAlias   : Ethernet
SourceAddress    : 192.168.88.14
TcpTestSucceeded : True
```

## Compiling C code con Linux

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

## TMUX

### Resize pane down 

```
:resize-pane -D
```

### Resize pane down 5 lines

```
:resize-pane -D 5
```

## Update Notify Windows

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

## Github

Create SSH keypair:

```
ssh-keygen -t rsa -C github
```

(then we need to upload **public** key to our repository)

start SSH agent and add our private key:

```
eval $(ssh-agent)
ssh-add id_rsa_github
```

switch to SSH authentication:

```
git remote set-url origin git@github.com:sughenji/nomedelrepository.git
```

## Ansible

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



