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
- [Export RDP logs](#export-rdp-logs)
- [Scheduled tasks](#scheduled-tasks)

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

list keys under a certain path:

```powershell
C:\Users\sugo>REG QUERY "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Client" /s

HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\Client
    fEnableUsbBlockDeviceBySetupClass    REG_DWORD    0x1
    fEnableUsbNoAckIsochWriteToDevice    REG_DWORD    0x50
    fEnableUsbSelectDeviceByInterface    REG_DWORD    0x1
    fClientDisableUDP    REG_DWORD    0x1
..
..
..
```

### export rdp logs


```powershell
<#

.SYNOPSIS 
    This script reads the event log "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" from 
    multiple servers and outputs the human-readable results to a CSV.  This data is not filterable in the native 
    Windows Event Viewer.

    Version: November 9, 2016


.DESCRIPTION
    This script reads the event log "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" from 
    multiple servers and outputs the human-readable results to a CSV.  This data is not filterable in the native 
    Windows Event Viewer.

    NOTE: Despite this log's name, it includes both RDP logins as well as regular console logins too.
    
    Author:
    Mike Crowley
    https://BaselineTechnologies.com

 .EXAMPLE
 
    .\RDPConnectionParser.ps1 -ServersToQuery Server1, Server2 -StartTime "November 1"
 
.LINK
    https://MikeCrowley.us/tag/powershell

#>

Param(
    [array]$ServersToQuery = (hostname),
    [datetime]$StartTime = "January 1, 1970"
)

    foreach ($Server in $ServersToQuery) {

        $LogFilter = @{
            LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
            ID = 21, 23, 24, 25
            StartTime = $StartTime
            }

        $AllEntries = Get-WinEvent -FilterHashtable $LogFilter -ComputerName $Server

        $AllEntries | Foreach { 
            $entry = [xml]$_.ToXml()
            [array]$Output += New-Object PSObject -Property @{
                TimeCreated = $_.TimeCreated
                User = $entry.Event.UserData.EventXML.User
                IPAddress = $entry.Event.UserData.EventXML.Address
                EventID = $entry.Event.System.EventID
                ServerName = $Server
                }        
            } 

    }

    $FilteredOutput += $Output | Select TimeCreated, User, ServerName, IPAddress, @{Name='Action';Expression={
                if ($_.EventID -eq '21'){"logon"}
                if ($_.EventID -eq '22'){"Shell start"}
                if ($_.EventID -eq '23'){"logoff"}
                if ($_.EventID -eq '24'){"disconnected"}
                if ($_.EventID -eq '25'){"reconnection"}
                }
            }

    $Date = (Get-Date -Format s) -replace ":", "."
    $FilePath = "$env:USERPROFILE\Desktop\$Date`_RDP_Report.csv"
    $FilteredOutput | Sort TimeCreated | Export-Csv $FilePath -NoTypeInformation

Write-host "Writing File: $FilePath" -ForegroundColor Cyan
Write-host "Done!" -ForegroundColor Cyan


#End
```

### scheduled tasks

To see details of a task:

```powershell
PS C:\scripts> schtasks /query /tn "Cancella backup vecchi" /v /fo LIST

Cartella: \
Nome host:                                                    ROFL-LADY
Nome attività:                                                \Cancella backup vecchi
Prossima esecuzione:                                          15/04/2025 01:00:00
Stato:                                                        Pronta
Modalità accesso:                                             Interattivo/Background
Ultima esecuzione:                                            30/11/1999 00:00:00
Ultimo esito:                                                 267011
Autore:                                                       ROFL-LADY\Administrator
Attività da eseguire:                                         powershell.exe -File C:\scripts\cancella_backup_vecchi.ps1
Avvio in:                                                     N/D
Commento:                                                     N/D
Stato attività pianificata:                                   Abilitata
Tempo di inattività:                                          Disabilitata
Risparmio energia:                                            Interrompi in modalità di alimentazione a batterie
Esegui come utente:                                           SYSTEM
Elimina l'attività se non ripianificata:                      Disabilitata
Interrompi l'attività se è in esecuzione da X ore e X minuti: 72:00:00
Pianificazione:                                               Dati di pianificazione non disponibili in questo formato.
Tipo di pianificazione:                                       Ogni giorno
Ora di avvio:                                                 01:00:00
Data di avvio:                                                14/04/2025
Data di fine:                                                 N/D
giorni:                                                       Ogni 1 giorni
mesi:                                                         N/D
Ripeti: Ogni:                                                 Disabilitata
Ripeti: Fino a: Ora:                                          Disabilitata
Ripeti: Fino a: Durata:                                       Disabilitata
Ripeti: Interrompi se ancora in esecuzione:                   Disabilitata
```