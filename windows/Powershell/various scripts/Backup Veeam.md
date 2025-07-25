```powershell
function Get-TimeStamp {
    
    return "[{0:yyyy/MM/dd} {0:HH:mm:ss}]" -f (Get-Date)
    
}

# per le notifiche su Telegram
$Telegramtoken = "XXXXXX45:XXXXX-a5EpXXXXXXXXczpQ"
$Telegramchatid = "-1111111111"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# popolo la variable $cred con l'utente per accedere su nas-alba
$cred = Get-VBRCredentials -Name veeam | ?{$_.Description -eq "veeamstorage"}

$vms = "vm1","vm2","vm3"

# imposto la chiave di cifratura
$enc = Get-VBREncryptionKey -Description "Password bla"

Write-Output "$(Get-TimeStamp) *** Starting backups!" >> .\backup-nas-log.txt

foreach ($virtualmachine in $vms)
{
    # Registra il tempo di inizio
    $startTime = Get-Date
    Write-Output "$(Get-TimeStamp) Starting backup $virtualmachine!" >> .\backup-nas-log.txt
    $vm = find-vbrvientity -name $virtualmachine
    Invoke-RestMethod -Uri "https://api.telegram.org/bot$($Telegramtoken)/sendMessage?chat_id=$($Telegramchatid)&text=Inizio backup Veeam di $virtualmachine su nas" | Out-Null
    
    try {
        Start-VBRZip -Entity $vm -Folder \\nas.domain.it\share_data\Veeam -EncryptionKey $enc -NetworkCredentials $cred -ErrorAction Stop
        # Calcola il tempo impiegato
        $endTime = Get-Date
        $duration = $endTime - $startTime
        $durationFormatted = "{0:hh\:mm\:ss}" -f $duration
        Write-Output "$(Get-TimeStamp) Done backup $virtualmachine! Tempo impiegato: $durationFormatted" >> .\backup-nas-log.txt
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$($Telegramtoken)/sendMessage?chat_id=$($Telegramchatid)&text=Fine backup Veeam di $virtualmachine su nas - Tempo: $durationFormatted" | Out-Null
    }
    catch {
        Write-Output "$(Get-TimeStamp) error" >> .\backup-nas-log.txt
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$($Telegramtoken)/sendMessage?chat_id=$($Telegramchatid)&text=ERRORE durante il backup Veeam di $virtualmachine su nas: $($_.Exception.Message)"
    }
}

Write-Output "$(Get-TimeStamp) *** Backups finished!" >> .\backup-nas-log.txt

#$noquiesceVMS = "vm4"

foreach ($virtualmachine in $noquiesceVMS)
{
    # Registra il tempo di inizio
    $startTime = Get-Date
    Write-Output "$(Get-TimeStamp) Starting backup $virtualmachine!" >> .\backup-nas-log.txt
    $vm = find-vbrvientity -name $virtualmachine
    Invoke-RestMethod -Uri "https://api.telegram.org/bot$($Telegramtoken)/sendMessage?chat_id=$($Telegramchatid)&text=Inizio backup Veeam di $virtualmachine su nas"
    Start-VBRZip -Entity $vm -Folder \\nas.domain.it\share_data\Veeam -DisableQuiesce -EncryptionKey $enc -NetworkCredentials $cred
    # Calcola il tempo impiegato
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $durationFormatted = "{0:hh\:mm\:ss}" -f $duration
    Write-Output "$(Get-TimeStamp) Done backup $virtualmachine! Tempo impiegato: $durationFormatted" >> .\backup-nas-log.txt
    Invoke-RestMethod -Uri "https://api.telegram.org/bot$($Telegramtoken)/sendMessage?chat_id=$($Telegramchatid)&text=Fine backup Veeam di $virtualmachine su nas - Tempo: $durationFormatted" | Out-Null
}
```
