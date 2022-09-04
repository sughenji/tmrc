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

## 
