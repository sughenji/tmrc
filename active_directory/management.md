# management

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

This will spawn WinRM service (port 5985/tcp).

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

## Create usernames

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


## Export security policy settings

```
secedit /export /cfg c:\Windows\Tasks\secpol.cfg
```

## Rename Computer

```
Rename-Computer "ws01" -DomainCredential (Get-Credential)
```

## Execute script on remote target

```
Invoke-Command -Computer ws01 -ScriptBlock { whoami }
```

## Mount share with powershell

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

