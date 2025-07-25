# Script per estrarre IP degli accessi su Exchange (IIS)

```powershell
# Exchange IIS Logs Only - User Login Source IP Extractor
# This script extracts source IP addresses from IIS logs for Exchange authentication events

param(
    [Parameter(Mandatory=$false)]
    [string]$UserIdentity = "*",
    
    [Parameter(Mandatory=$false)]
    [datetime]$StartDate = (Get-Date).AddDays(-7),
    
    [Parameter(Mandatory=$false)]
    [datetime]$EndDate = (Get-Date),
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\ExchangeIISLoginIPs.csv",
    
    [Parameter(Mandatory=$true)]
    [string]$IISLogPath = "C:\inetpub\logs\LogFiles\W3SVC1",
    
    [Parameter(Mandatory=$false)]
    [string]$BackEndIISLogPath = "C:\inetpub\logs\LogFiles\W3SVC2",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeBackEndLogs,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowFailedAttempts,
    
    [Parameter(Mandatory=$false)]
    [switch]$VerboseOutput
)

# Function to parse IIS logs for Exchange authentication events
function Get-IISExchangeLogins {
    param(
        [string]$Identity,
        [datetime]$Start,
        [datetime]$End,
        [string]$LogPath,
        [string]$LogType = "Frontend",
        [bool]$ShowFailed = $false,
        [bool]$Verbose = $false
    )
    
    Write-Host "Parsing IIS logs from: $LogPath ($LogType)" -ForegroundColor Cyan
    
    if (-not (Test-Path $LogPath)) {
        Write-Warning "IIS log path not found: $LogPath"
        return @()
    }
    
    try {
        $loginData = @()
        
        # Get log files within date range (including u_ex format)
        $logFiles = Get-ChildItem -Path $LogPath -Filter "*.log" | Where-Object {
            $_.LastWriteTime -ge $Start.AddDays(-1) -and $_.LastWriteTime -le $End.AddDays(1)
        }
        
        Write-Host "Found $($logFiles.Count) log files to process" -ForegroundColor Gray
        
        foreach ($logFile in $logFiles) {
            if ($Verbose) {
                Write-Host "Processing: $($logFile.Name)" -ForegroundColor Gray
            }
            
            $content = Get-Content $logFile.FullName
            $headers = @()
            $headerFound = $false
            $processedLines = 0
            $matchedLines = 0
            
            foreach ($line in $content) {
                $processedLines++
                
                # Parse W3C header to get field positions
                if ($line -match "^#Fields:") {
                    $headers = ($line -replace "^#Fields: ", "") -split "\s+"
                    $headerFound = $true
                    if ($Verbose) {
                        Write-Host "Found headers: $($headers -join ', ')" -ForegroundColor DarkGray
                    }
                    continue
                }
                
                # Skip comment lines
                if ($line -match "^#" -or -not $headerFound) {
                    continue
                }
                
                # Split log entry
                $fields = $line -split "\s+"
                
                if ($fields.Count -ge $headers.Count) {
                    try {
                        # Create hashtable for easy field access
                        $logEntry = @{}
                        for ($i = 0; $i -lt $headers.Count; $i++) {
                            $logEntry[$headers[$i]] = if ($fields[$i] -eq "-") { "" } else { $fields[$i] }
                        }
                        
                        # Parse timestamp
                        $logDate = $logEntry["date"]
                        $logTime = $logEntry["time"]
                        if ($logDate -and $logTime) {
                            $timestamp = [datetime]::ParseExact("$logDate $logTime", "yyyy-MM-dd HH:mm:ss", $null)
                            
                            # Skip if outside date range
                            if ($timestamp -lt $Start -or $timestamp -gt $End) {
                                continue
                            }
                        } else {
                            continue
                        }
                        
                        # Get relevant fields
                        $clientIP = $logEntry["c-ip"]
                        $method = $logEntry["cs-method"]
                        $uri = $logEntry["cs-uri-stem"]
                        $query = $logEntry["cs-uri-query"]
                        $status = $logEntry["sc-status"]
                        $substatus = $logEntry["sc-substatus"]
                        $userAgent = $logEntry["cs(User-Agent)"]
                        $username = $logEntry["cs-username"]
                        $referer = $logEntry["cs(Referer)"]
                        $bytes = $logEntry["sc-bytes"]
                        $timeTaken = $logEntry["time-taken"]
                        
                        # Filter for Exchange-related authentication activities
                        $isExchangeAuth = $false
                        $authType = ""
                        $extractedUser = $username
                        $isSuccessful = $false
                        
                        # Determine if this is a successful authentication
                        $successCodes = @("200", "302", "304")
                        $failureCodes = @("401", "403", "404")
                        
                        if ($status -in $successCodes) {
                            $isSuccessful = $true
                        }
                        
                        # OWA authentication patterns
                        if ($uri -match "/(owa|exchange)/auth" -or 
                            $uri -match "/owa/logon\.aspx" -or
                            $uri -match "/owa/auth\.owa" -or
                            ($uri -match "/owa/" -and $method -eq "POST")) {
                            $isExchangeAuth = $true
                            $authType = "OWA"
                        }
                        
                        # ECP authentication patterns
                        elseif ($uri -match "/ecp/auth" -or 
                                ($uri -match "/ecp/" -and $method -eq "POST")) {
                            $isExchangeAuth = $true
                            $authType = "ECP"
                        }
                        
                        # EWS authentication patterns
                        elseif ($uri -match "/ews/exchange\.asmx" -or
                                $uri -match "/EWS/Exchange\.asmx") {
                            $isExchangeAuth = $true
                            $authType = "EWS"
                        }
                        
                        # ActiveSync authentication patterns
                        elseif ($uri -match "/Microsoft-Server-ActiveSync") {
                            $isExchangeAuth = $true
                            $authType = "ActiveSync"
                        }
                        
                        # RPC/HTTP (Outlook Anywhere)
                        elseif ($uri -match "/rpc/rpcproxy\.dll") {
                            $isExchangeAuth = $true
                            $authType = "RPC/HTTP"
                        }
                        
                        # MAPI/HTTP (Outlook 2013+)
                        elseif ($uri -match "/mapi/(nspi|emsmdb)") {
                            $isExchangeAuth = $true
                            $authType = "MAPI/HTTP"
                        }
                        
                        # Autodiscover
                        elseif ($uri -match "/autodiscover/autodiscover\.xml") {
                            $isExchangeAuth = $true
                            $authType = "Autodiscover"
                        }
                        
                        # PowerShell remoting (Exchange Management Shell)
                        elseif ($uri -match "/powershell") {
                            $isExchangeAuth = $true
                            $authType = "PowerShell"
                        }
                        
                        # Extract username from query string if not in username field
                        if (-not $extractedUser) {
                            if ($query -match "username=([^&]+)") {
                                $extractedUser = [System.Web.HttpUtility]::UrlDecode($matches[1])
                            }
                            elseif ($query -match "user=([^&]+)") {
                                $extractedUser = [System.Web.HttpUtility]::UrlDecode($matches[1])
                            }
                            elseif ($query -match "mailbox=([^&]+)") {
                                $extractedUser = [System.Web.HttpUtility]::UrlDecode($matches[1])
                            }
                        }
                        
                        # Check if this matches our search criteria
                        if ($isExchangeAuth -and $clientIP) {
                            # Filter by success/failure if specified
                            if (-not $ShowFailed -and -not $isSuccessful) {
                                continue
                            }
                            
                            $userMatch = ($Identity -eq "*" -or 
                                         ($extractedUser -and $extractedUser -like "*$Identity*") -or
                                         ($username -and $username -like "*$Identity*"))
                            
                            if ($userMatch) {
                                $matchedLines++
                                
                                $loginData += [PSCustomObject]@{
                                    User = if ($extractedUser) { $extractedUser } else { $username }
                                    LoginTime = $timestamp
                                    SourceIP = $clientIP
                                    AuthType = $authType
                                    Method = $method
                                    StatusCode = $status
                                    SubStatus = $substatus
                                    Success = $isSuccessful
                                    UserAgent = $userAgent
                                    URI = $uri
                                    Query = $query
                                    Referer = $referer
                                    Bytes = $bytes
                                    TimeTaken = $timeTaken
                                    LogType = $LogType
                                    LogFile = $logFile.Name
                                    Source = "IIS"
                                }
                            }
                        }
                    }
                    catch {
                        # Skip malformed lines
                        if ($Verbose) {
                            Write-Warning "Skipped malformed line: $($_.Exception.Message)"
                        }
                        continue
                    }
                }
            }
            
            if ($Verbose) {
                Write-Host "  Processed $processedLines lines, found $matchedLines matches" -ForegroundColor DarkGray
            }
        }
        
        Write-Host "Found $($loginData.Count) authentication records from $LogType logs" -ForegroundColor Green
        return $loginData
    }
    catch {
        Write-Warning "Error parsing IIS logs from $LogPath : $($_.Exception.Message)"
        return @()
    }
}

# Function to analyze and summarize login data
function Show-LoginSummary {
    param([array]$LoginData)
    
    if ($LoginData.Count -eq 0) {
        Write-Host "No login data to summarize." -ForegroundColor Yellow
        return
    }
    
    Write-Host "`n=== LOGIN SUMMARY ===" -ForegroundColor Green
    
    # Summary by Authentication Type
    $authTypeSummary = $LoginData | Group-Object AuthType | Sort-Object Count -Descending
    Write-Host "`nAuthentication Types:" -ForegroundColor Yellow
    $authTypeSummary | Format-Table Name, Count -AutoSize
    
    # Summary by Success/Failure
    $successSummary = $LoginData | Group-Object Success | Sort-Object Name
    Write-Host "Success/Failure Summary:" -ForegroundColor Yellow
    $successSummary | Format-Table @{Name="Result"; Expression={if($_.Name -eq "True") {"Success"} else {"Failed"}}}, Count -AutoSize
    
    # Top Source IPs
    $ipSummary = $LoginData | Group-Object SourceIP | Sort-Object Count -Descending | Select-Object -First 10
    Write-Host "Top 10 Source IPs:" -ForegroundColor Yellow
    $ipSummary | Format-Table @{Name="Source IP"; Expression={$_.Name}}, Count -AutoSize
    
    # Top Users
    $userSummary = $LoginData | Where-Object {$_.User} | Group-Object User | Sort-Object Count -Descending | Select-Object -First 10
    if ($userSummary.Count -gt 0) {
        Write-Host "Top 10 Users:" -ForegroundColor Yellow
        $userSummary | Format-Table @{Name="User"; Expression={$_.Name}}, Count -AutoSize
    }
    
    # Timeline (by hour)
    $timelineSummary = $LoginData | Group-Object {$_.LoginTime.ToString("yyyy-MM-dd HH:00")} | Sort-Object Name
    Write-Host "Activity Timeline (by hour):" -ForegroundColor Yellow
    $timelineSummary | Select-Object -First 20 | Format-Table @{Name="Hour"; Expression={$_.Name}}, Count -AutoSize
}

# Main script execution
try {
    Write-Host "=== Exchange IIS Logs Login Source IP Extractor ===" -ForegroundColor Green
    Write-Host "Date Range: $StartDate to $EndDate" -ForegroundColor Yellow
    Write-Host "User Filter: $UserIdentity" -ForegroundColor Yellow
    Write-Host "IIS Log Path: $IISLogPath" -ForegroundColor Yellow
    if ($IncludeBackEndLogs) {
        Write-Host "Backend IIS Log Path: $BackEndIISLogPath" -ForegroundColor Yellow
    }
    Write-Host "Show Failed Attempts: $ShowFailedAttempts" -ForegroundColor Yellow
    
    $allLoginData = @()
    
    # Parse Frontend IIS Logs
    Write-Host "`n--- Parsing Frontend IIS Logs ---" -ForegroundColor Magenta
    $frontendLogins = Get-IISExchangeLogins -Identity $UserIdentity -Start $StartDate -End $EndDate -LogPath $IISLogPath -LogType "Frontend" -ShowFailed $ShowFailedAttempts -Verbose $VerboseOutput
    $allLoginData += $frontendLogins
    
    # Parse Backend IIS Logs (if requested)
    if ($IncludeBackEndLogs -and (Test-Path $BackEndIISLogPath)) {
        Write-Host "`n--- Parsing Backend IIS Logs ---" -ForegroundColor Magenta
        $backendLogins = Get-IISExchangeLogins -Identity $UserIdentity -Start $StartDate -End $EndDate -LogPath $BackEndIISLogPath -LogType "Backend" -ShowFailed $ShowFailedAttempts -Verbose $VerboseOutput
        $allLoginData += $backendLogins
    }
    elseif ($IncludeBackEndLogs) {
        Write-Warning "Backend IIS log path not found: $BackEndIISLogPath"
    }
    
    # Remove duplicates and sort by login time
    $uniqueLogins = $allLoginData | Sort-Object LoginTime -Descending
    
    if ($uniqueLogins.Count -gt 0) {
        # Display results
        Write-Host "`n=== DETAILED RESULTS ===" -ForegroundColor Green
        Write-Host "Found $($uniqueLogins.Count) authentication records:" -ForegroundColor Green
        
        # Show sample of results
        Write-Host "`nSample Results (first 20 records):" -ForegroundColor Cyan
        $uniqueLogins | Select-Object -First 20 | Format-Table User, LoginTime, SourceIP, AuthType, Success, StatusCode -AutoSize
        
        # Export to CSV
        $uniqueLogins | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-Host "`nFull results exported to: $OutputPath" -ForegroundColor Green
        
        # Show summary
        Show-LoginSummary -LoginData $uniqueLogins
        
    } else {
        Write-Host "`nNo authentication records found for the specified criteria." -ForegroundColor Red
        Write-Host "`nTroubleshooting tips:" -ForegroundColor Yellow
        Write-Host "1. Verify IIS log path is correct" -ForegroundColor Gray
        Write-Host "2. Check if IIS logging is enabled for the Exchange virtual directories" -ForegroundColor Gray
        Write-Host "3. Ensure the date range includes activity periods" -ForegroundColor Gray
        Write-Host "4. Try using -VerboseOutput to see detailed processing info" -ForegroundColor Gray
        Write-Host "5. Include failed attempts with -ShowFailedAttempts" -ForegroundColor Gray
    }
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    Write-Host "Stack trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
}

# Example usage:
# .\Get-ExchangeIISLoginIPs.ps1 -IISLogPath "C:\inetpub\logs\LogFiles\W3SVC1" -UserIdentity "jdoe"
# .\Get-ExchangeIISLoginIPs.ps1 -IISLogPath "C:\inetpub\logs\LogFiles\W3SVC1" -IncludeBackEndLogs -ShowFailedAttempts -VerboseOutput
# .\Get-ExchangeIISLoginIPs.ps1 -IISLogPath "D:\Logs\IIS" -UserIdentity "*" -StartDate "2024-05-01" -EndDate "2024-05-31"

# Common Exchange IIS log locations:
# Frontend: C:\inetpub\logs\LogFiles\W3SVC1
# Backend: C:\inetpub\logs\LogFiles\W3SVC2
# Custom locations may vary based on your Exchange installation
```

