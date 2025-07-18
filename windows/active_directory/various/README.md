# workstation

## add computer to domain with powershell

```powershell
PS C:\Users\sugo> $domain = "budapest.local"
PS C:\Users\sugo> $username = "BUDAPEST\administrator"
PS C:\Users\sugo> $password = "Password1" |  ConvertTo-SecureString -AsPlainText -Force
PS C:\Users\sugo> $credential = New-Object System.Management.Automation.PSCredential ($username, $password)
PS C:\Users\sugo> Add-Computer -DomainName $domain -Credential $credential -Restart -Force
```

