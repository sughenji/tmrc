# chkdsk result

Applications, event id 1001



# Log files size (evtx)

## see the current values 

```powershell
PS C:\Windows\system32> Get-Eventlog -List | ft -autosize

   Max(K) Retain OverflowAction      Entries Log
   ------ ------ --------------      ------- ---
      512      7 OverwriteOlder          593 Active Directory Web Services
   20.480      0 OverwriteAsNeeded    43.019 Application
   15.168      0 OverwriteAsNeeded     2.316 DFS Replication
      512      0 OverwriteAsNeeded     3.410 Directory Service
  102.400      0 OverwriteAsNeeded   243.261 DNS Server
   20.480      0 OverwriteAsNeeded         0 HardwareEvents
      512      7 OverwriteOlder            0 Internet Explorer
      512      7 OverwriteOlder          137 Kaspersky Endpoint Security
   20.480      0 OverwriteAsNeeded         0 Key Management Service
1.048.576      0 OverwriteAsNeeded 7.089.711 Security
    4.096      7 OverwriteOlder          674 Storage Array Events
   20.480      0 OverwriteAsNeeded    59.653 System
   15.360      0 OverwriteAsNeeded     5.656 Windows PowerShell
```

Security default size: `131.072 KB`

## set size of log file with powershell

```powershell
wevtutil sl "Security" /ms:134217728
```

## check the size through GUI

Right click on log file:

![](_attachment/Pasted%20image%2020250219095940.png)

