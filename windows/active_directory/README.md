# psremote

## interesting url

https://www.techthoughts.info/powershell-remoting/#Configuring_WinRM

https://github.com/techthoughts2/Learn-PowerShell-Code-Examples/blob/master/LearnPowerShell/EP9%20-%20PowerShell%20Remoting.ps1

https://learn.microsoft.com/it-it/troubleshoot/windows-client/system-management-components/configure-winrm-for-https

## Returns all commands that contains `session`:

```
PS C:\Users\sugo> get-command -noun pssession

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Connect-PSSession                                  3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Disconnect-PSSession                               3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Enter-PSSession                                    3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Exit-PSSession                                     3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Export-PSSession                                   3.1.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-PSSession                                      3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Import-PSSession                                   3.1.0.0    Microsoft.PowerShell.Utility
Cmdlet          New-PSSession                                      3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Receive-PSSession                                  3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Remove-PSSession                                   3.0.0.0    Microsoft.PowerShell.Core


PS C:\Users\sugo>
```

## Enable PsRemoting

```
Enable-PSRemoting (-Force)
```

This will spawn WinRM service (default port 5985/tcp).

To check if PsRemoting is enabled:

```
Enter-PSSession -ComputerName localhost
```

it works? :)

Check if there are TrustedHosts:

```
get-item wsman:\localhost\client\trustedhosts
```

Add a trustedhost:

```
set-item wsman:\localhost\client\trustedhosts -Value 192.168.111.43
```


## Create PSSession with our DC:

```
$dc = New-PSSession 10.0.2.19 -Credential (Get-Credential)
```

Copy a file through PSSession:

```
Copy-Item .\file.txt -ToSession $dc c:\windows\tasks
```

## Create PSSession with multiple remote servers:

```
$servers = New-PSSession -ComputerName hostname1, hostname2, hostname3 -Credential
```

We can also load remote server list from a text file:

```
$devices = Get-Content -Path c:\Users\sugo\Downloads\listServers.txt
```

Run same command on multiple sessions:

```
Invoke-Command -Session $servers -ScriptBlock {hostname}
```


## Create PSSession and get credentials through CLI (no GUI)

rif. https://devblogs.microsoft.com/powershell/getting-credentials-from-the-command-line/

```
PS C:\Users\local_admin\Documents> $key = "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds"
PS C:\Users\local_admin\Documents> Set-ItemProperty $key ConsolePrompting True
PS C:\Users\local_admin\Documents> New-PSSession 10.0.2.19 -Credential (get-credential)

PS C:\Users\local_admin\Documents> New-PSSession 10.0.2.19 -Credential (get-credential)

cmdlet Get-Credential at command pipeline position 1
Supply values for the following parameters:
Credential
User: xyz.com\administrator
Password for user xyz.com\administrator: ************


 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  2 WinRM2          10.0.2.19       RemoteMachine   Opened        Microsoft.PowerShell     Available


PS C:\Users\local_admin\Documents> hostname
DESKTOP-CRO0797
PS C:\Users\local_admin\Documents> Enter-PSSession 2
[10.0.2.19]: PS C:\Users\Administrator\Documents> hostname
DC1
[10.0.2.19]: PS C:\Users\Administrator\Documents>
```

How to check if `WSMAN` is locally enabled:

(negative response)

```
PS C:\Users\sugo> test-wsman
test-wsman : <f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="2150858770"
Machine="SUGO-PC.sugolandia.local"><f:Message>Il client non è in grado di connettersi alla destinazione specificata nella
richiesta. Verificare che il servizio nella destinazione sia in esecuzione e accetti le richieste. Consultare i
registri e la documentazione per il servizio WS-Management in esecuzione nella destinazione, nella maggior parte dei
casi IIS o Gestione remota Windows. Se la destinazione è il servizio Gestione remota Windows, eseguire il comando
seguente nella destinazione per analizzare e configurare il servizio Gestione remota Windows: "winrm quickconfig".
</f:Message></f:WSManFault>
In riga:1 car:1
+ test-wsman
+ ~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Test-WSMan], InvalidOperationException
    + FullyQualifiedErrorId : WsManError,Microsoft.WSMan.Management.TestWSManCommand
```

(positive response)

```
PS C:\Users\administrator.SUGOLANDIA> test-wsman


wsmid           : http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd
ProtocolVersion : http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd
ProductVendor   : Microsoft Corporation
ProductVersion  : OS: 0.0.0 SP: 0.0 Stack: 3.0
```


How to check listener configuration:

```
PS C:\Users\administrator.SUGOLANDIA> winrm enumerate winrm/config/listener
Listener
    Address = *
    Transport = HTTP
    Port = 5985
    Hostname
    Enabled = true
    URLPrefix = wsman
    CertificateThumbprint
    ListeningOn = 127.0.0.1, 192.168.1.12, ::1, fe80::c448:a4b6:5eb4:764f%15
```


# manage users

```
PS C:\Users\sugo> $name = "Francesco Politi"
PS C:\Users\sugo> echo $name
Francesco Politi
PS C:\Users\sugo> $name[0]
F
PS C:\Users\sugo> $name[0] + $name.split(" ")
FFrancesco Politi
PS C:\Users\sugo> $name[0] + $name.split(" ")[1]
FPoliti
PS C:\Users\sugo> $name[0] + $name.split(" ")[1].tolower()
Fpoliti
PS C:\Users\sugo> ($name[0] + $name.split(" ")[1]).tolower()
fpoliti
PS C:\Users\sugo>
```

## Create users from Excel

```
# Generate not so complex random passwords
# credits: https://activedirectoryfaq.com/2017/08/creating-individual-random-passwords/

function Get-RandomCharacters($length, $characters) {
    $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
    $private:ofs=""
    return [String]$characters[$random]
}

function Scramble-String([string]$inputString){     
    $characterArray = $inputString.ToCharArray()   
    $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
    $outputString = -join $scrambledStringArray
    return $outputString 
}

# Check if Import-Excel module is installed
if (Get-InstalledModule | Where-Object {$_.Name -eq "ImportExcel" }) {
        write-host "Ok, module Import-Excel is already imported.`n"
    }
else {
    Write-Host "Please run first: Install-Module ImportExcel -scope currentuser"
    EXIT 1
}

$ExcelUsersFile = $args[0]
$Domain = $args[1]

$operators = Import-Excel $ExcelUsersFile -HeaderName "Nome", "Cognome" -StartRow 2

foreach ($user in $operators) { 
	$password = Get-RandomCharacters -length 7 -characters 'abcdefghiklmnoprstuvwxyz'
	$password += Get-RandomCharacters -length 1 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
	$password += Get-RandomCharacters -length 1 -characters '1234567890'
	$password += Get-RandomCharacters -length 1 -characters '!$%?@#+'
	$password = Scramble-String $password	
	
	Write-Output "Nome: $($user."Nome")" >> .\$Domain-log.txt
	Write-Output "Cognome: $($user."Cognome")" >> .\$Domain-log.txt
	$username = (($user."Nome")[0]+"."+($user."Cognome").replace("'", "").replace(" ","")).tolower()
    Write-Output "[*] Creating User... $($user."Nome") $($user."Cognome")" 
	Write-Output "Username: $username" >> .\$Domain-log.txt
	Write-Output "Password: $password`n" >> .\$Domain-log.txt
	Write-Output "`n"
    $secpassword = ConvertTo-SecureString -String $password -AsPlainText -Force
    New-ADUser -SamAccountName $username -UserPrincipalName $username@$Domain -GivenName $($user."Nome") -SurName $($user."Cognome") -Name "$($user."Nome") $($user."Cognome")" -DisplayName "$($user."Nome") $($user."Cognome")"-AccountPassword $secpassword -Enabled $true -ChangePasswordAtLogon $true
    Write-Output "User $($user."Nome") $($user."Cognome") successfully created!`n"
}
Write-Output "Please check $domain-log.txt file for details.`n"

```


# Export security policy settings

```
secedit /export /cfg c:\Windows\Tasks\secpol.cfg
```

# Rename Computer

```
Rename-Computer "ws01" -DomainCredential (Get-Credential)
```

# Execute script on remote target

```
Invoke-Command -Computer ws01 -ScriptBlock { whoami }
```

# Mount share with powershell

```
PS C:\> $username = 'sugo'
PS C:\> $password = 'Password!'
PS C:\> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\> New-PSDrive -Name "Z" -Root "\\10.0.2.200\Finance" -PSProvider "FileSystem" -Credential $cred

Name           Used (GB)     Free (GB) Provider      Root                                                              CurrentLocation
----           ---------     --------- --------      ----                                                              ---------------
Z                                      FileSystem    \\10.0.2.200\Finance
```

Per importare il modulo che ci consentirà di usare i comandi successivi:

```
PS C:\Users\Administrator> Import-Module -Name ActiveDirectory
```

## creare un utente

```
PS C:\Users\Administrator> New-ADUser -UserPrincipalName "sughettiplus@smuggles.local" -SamAccountName "sughettiplus" -GivenName "NOME" -SurName "COGNOME" -Name "NAME" -DisplayName "DISPLAYNAME" -Enabled $true -AccountPassword(Read-Host -AsSecureString "Input Password")
Input Password: ***********
```


## creare un utente in una specifica OU

```
PS C:\Users\Administrator> New-ADUser -UserPrincipalName "horace@smuggles.local" -SamAccountName "horace" -GivenName "Orazio" -SurName "Costa" -Name "Orazio Costa" -DisplayName "Orazio Costa" -Enabled $true -AccountPassword(Read-Host -AsSecureString "Input Password") -Path "OU=Sbandieratori,OU=RagazziViaPal,DC=smuggles,DC=local"
Input Password: ***********
```

## Per creare un utente e forzare cambio password al prossimo login

```
PS C:\Users\Administrator> New-ADUser -UserPrincipalName "pdifulvio@smuggles.local" -SamAccountName "pdifulvio" -GivenName "Patrizia" -SurName "Di Fulvio" -Name "Patrizia Di Fulvio" -DisplayName "Patrizia Di Fulvio" -Enabled $true -AccountPassword(Read-Host -AsSecureString "Input Password") -Path "OU=Sbandieratori,OU=RagazziViaPal,DC=smuggles,DC=local" -ChangePasswordAtLogon $true
Input Password: **********
```

## Vedere data ultimo accesso utente

```
Get-ADUser -identity sugo -properties LastLogonDate
```

## Vedere data ultimo cambio password di un utente:

```
Get-ADUser  sugo -properties passwordlastset | ft Name, passwordlastset
```

## Vedere data scadenza utente AD

```
C:\Users\sugo_adm>net user XXXX /domain
Nome utente                           XXXX 
Nome completo                         XXXX YYYYY
Commento
Commento utente
Codice paese/area geografica          000 (Predefinito del sistema)
Account attivo                        Sì
Scadenza account                      Mai

Ultima impostazione password          09/01/2023 10:27:32
Scadenza password                     08/07/2023 10:27:32
Password cambiabile                   09/01/2023 10:27:32
Password richiesta                    Sì
L'utente può cambiare la password     Sì

Workstation consentite                Tutti
Script di accesso
Profilo utente
Home directory
Ultimo accesso                        21/06/2023 11:09:14

Ore di accesso consentito             Tutti

Appartenenze al gruppo locale         *SapBO_user
Appartenenze al gruppo globale        *Utenti Amministrazion
                                      *Domain Users
                                      *Utenti VPN 
                                      *Utenti x
Esecuzione comando riuscita.
```

## Vedere data ultima modifica utente (può coincidere con data disattivazione account)

```
PS C:\Windows\system32> get-aduser -identity sugo -properties Modified
DistinguishedName : CN=sugo,CN=Users,DC=micso,DC=local
Enabled           : False
GivenName         : sugo
Modified          : 17/11/2023 17:37:36
```

In alternativa si può consultare l'event viewer "Security", event id: 4725

## Togliere opzione "nessuna scadenza password"

```
Set-ADUser -identity admints -PasswordNeverExpires $false
```

## Forzare cambio password ad un utente

```
Set-ADUser -identity admints -ChangePasswordAtLogon $true
```

## Cercare utenti che hanno una particolare stringa nel SamAccountName

```
PS C:\Users\administrator.DOMAIN> Get-ADUser -Filter "SamAccountName -like '*_adm'" | Select-Object Name,SamAccountName

Name                     SamAccountName
----                     --------------
Francesco Politi Admin   sugo_adm
```

## Mostrare elenco utenti e data dell'ultimo cambio password

```
PS C:\Users\administrator.DOMAIN> Get-ADUser -filter * -property PasswordLastSet | ft SamAccountName, PasswordLastSet
```

## Verificare se la password di un utente è scaduta

```
PS C:\Users\sugo_adm> Get-ADUser -identity sugo_adm -properties PasswordLastSet, PasswordExpired, PasswordNeverExpires |
 ft Name, PasswordLastSet, PasswordExpired, PasswordNeverExpires

Name                   PasswordLastSet     PasswordExpired PasswordNeverExpires
----                   ---------------     --------------- --------------------
Francesco Politi Admin 21/12/2022 00:52:00           False                False


PS C:\Users\sugo_adm>
```

## elenco utenti attivi con flag "nessuna scadenza password"

```
get-aduser -Filter 'enabled -eq $true' -properties Name, PasswordNeverExpires | where { $_.passwordNeverExpires -eq "true" } |  Select-Object DistinguishedName,Name
```

## elenco utenti e relativa data di scadenza password

```
Get-ADUser -filter {Enabled -eq $True -and PasswordNeverExpires -eq $False} –Properties "DisplayName", "msDS-UserPasswordExpiryTimeComputed" |
Select-Object -Property "Displayname",@{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}
```

Simile, ma anche con l'email

```
Get-ADUser -Filter * -Property DisplayName, EmailAddress, PasswordNeverExpires, msDS-UserPasswordExpiryTimeComputed | Where { $_.Enabled -eq $true -and $_.PasswordNeverExpires -eq $false } | ft DisplayName,EmailAddress,@{Name="Expiration date";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}
```

## data creazione utente AD

```
PS C:\Users\Administrator\Downloads> get-aduser -identity sugo -properties whencreated | fl whencreated


whencreated : 17/09/2010 16:58:44
```



## Forzare il sync del SYSVOL

```
C:\Users\administrator.DOMAIN>repadmin /syncall
```

## Verifica replica

```
C:\Users\administrator.DOMAIN>dcdiag /test:VerifyReplicas
```


