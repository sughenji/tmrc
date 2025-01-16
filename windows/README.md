- [Active Directory](active_directory/README.md)
- [Mount SSHFS](#mount-sshfs)
- [Accessing SMB](#accessing-smb)
- [Capture traffic](#capture-traffic)
- [Powershell Test Connection](#powershell-test-connection)
- [Update Notify Windows](#update-notify-windows)
- [psexec](#psexec)
- [Install openssh server powershell](#install-openssh-server-powershell)
- [Manage Firewall with powershell](#manage-firewall-with-powershell)
- [Script to send email reminder password expiring](#script-to-send-email-reminder-password-expiring)
- [Manage registry through CLI](#manage-registry-through-cli)

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
$WURECIPIENT = "checkupdate@domain.net"
$WURELAY = "relay.domain.it"
$WUFROM = $WUCOMPUTERNAME + "@domain.it"
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

### Script to send email reminder password expiring


```powershell
# Importare il modulo Active Directory
Import-Module ActiveDirectory

# Configurare i dettagli del server SMTP
$smtpServer = "smtp-out.domain.ext"
$smtpFrom = "noc@domain.ext"
$smtpSubject = "[DOMAIN] Avviso scadenza password di dominio"

# Ottieni la data corrente e aggiungi 7 giorni
$expiryDate = (Get-date).AddDays(7).ToString('yyyy/MM/dd')
# mi faccio printare la data di riferimento, giusto per
#Write-Host $expiryDate

# Recupera tutti gli utenti dal dominio Active Directory che rispondono ai seguenti criteri:
# 1) sono abilitati
# 2) hanno scadenza password abilitata (non vogliamo inviare alert a utenti la cui password NON scade, per nostra scelta)
# 3) NON sono membri dell'OU customer (per il momento ai clienti/consulenti esterni non mandiamo reminder)
# 4) NON matchano gli utenti "fittizi" (es. extest_96a4813aea414)
$users = Get-ADUser -Filter * -Property DisplayName, EmailAddress, passwordNeverExpires, msDS-UserPasswordExpiryTimeComputed | Where-Object { $_.Enabled -eq $true -and $_.passwordNeverExpires -eq $false -and $_.distinguishedName -notlike "*OU=customers,DC=domain,DC=local" -and $_.distinguishedName -notMatch "extest_" }   

foreach ($user in $users) {
        $userDate = ([datetime]::FromFileTime($user."msDS-UserPasswordExpiryTimeComputed").ToString("yyyy/MM/dd"))
        # giusto un test per farmi printare cose:
        #Write-Host $user.DisplayName,$userDate,$user.EmailAddress
        if ($userDate -lt $expiryDate -and $userDate -gt (Get-date).ToString('yyyy/MM/dd') ) {
        $emailBody = @"
Ciao $($user.DisplayName),<br />

La password del tuo utente $($user.UserPrincipalName) scade il $($userdate).<br />
Ti preghiamo di aggiornare la tua password prima di questa data.<br />
Per farlo, puoi premere Control+Alt+Canc sul tuo PC e scegliere il menu "Cambia password".<br />
In alternativa, puoi accedere sulla webmail https://exchange.domain.ext, cliccare in alto a destra sul simbolo dell'ingranaggio, scegliere "Opzioni"; successivamente, dal menu di sinistra "Generale", "Il mio account", potrai cliccare su "Modifica password".<br />

Buon lavoro,<br />
IT Staff
"@ 
        #Write-Host $user.DisplayName,$userDate,$user.EmailAddress,$smtpSubject
        # Invia la mail
        Send-MailMessage -SmtpServer $smtpServer -From $smtpFrom -To $user.EmailAddress -Subject $smtpSubject -Body $emailBody -BodyAsHtml
        } 
}
```

### manage registry through cli

to see the current value:

```powershell
C:\Users\sugo>reg query "HKEY_USERS\S-1-5-21-00000000-1518580609-3671465160-1630\Control Panel\Desktop" /v ScreenSaveTimeOut

HKEY_USERS\S-1-5-21-00000000-1518580609-3671465160-1630\Control Panel\Desktop
    ScreenSaveTimeOut    REG_SZ    300
```

to change the value:

```powershell
C:\Users\sugo>reg add "HKEY_USERS\S-1-5-21-00000000-1518580609-3671465160-1630\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d 3600 /f
Operazione completata.
```

