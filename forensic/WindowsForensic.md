# Windows Forensic

## General info

OS version: `winver` 

Other infos: `systeminfo`

Where `registry hives` are stored on a Windows system:

`C:\Windows\System32\Config`

DEFAULT (mounted on HKEY_USERS\DEFAULT)

SAM (mounted on HKEY_LOCAL_MACHINE\SAM)

SECURITY (mounted on HKEY_LOCAL_MACHINE\Security)

SOFTWARE (mounted on HKEY_LOCAL_MACHINE\Software)

SYSTEM (mounted on HKEY_LOCAL_MACHINE\System)

### Hives containing user information:

C:\Users\<username>\NTUSER.DAT (mounted on HKEY_CURRENT_USER when a user logs in)

C:\Users\<username>\AppData\Local\Microsoft\Windows\USRCLASS.DAT (mounted on HKEY_CURRENT_USER\Software\CLASSES)

### The Amcache Hive (information on programs that were recently run on the system)

`C:\Windows\AppCompat\Programs\Amcache.hve`

### Transaction Logs

Are stored on same path, with extension .LOG, .LOG1, and so on.

### Hives backup

Stored on `C:\Windows\System32\Config\RegBack` every ten days.

### EVTX

(you should install this before: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

Microsoft-Windows-Sysmon/Operational (Event ID 3) - Network connection (Look for suspicious ports)

Microsoft-Windows-Sysmon/Operational (Event ID 11) - FileCreate 

Microsoft-Windows-Sysmon/Operational (Event IDs 23, 26) - FileDelete

## Interesting keys

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run (software executed on every logon)


## Tools

KAPE https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape

Autopsy https://www.autopsy.com/

FTK Imager https://www.exterro.com/ftk-imager https://accessdata.com/product-download/ftk-imager-version-4-2-0

Redline https://fireeye.market/apps/211364

DumpIt.exe

win32dd.exe / win64dd.exe 

AccessData's Registry Viewer https://accessdata.com/product-download/registry-viewer-2-0-0

Zimmerman's Registry Explorer https://ericzimmerman.github.io/#!index.md

RegRipper https://github.com/keydet89/RegRipper3.0

WinPmem (RAM dump) https://github.com/Velocidex/WinPmem

Event Log Explorer https://eventlogxp.com/

srum-dump https://github.com/MarkBaggett/srum-dump

RDP-Parser https://le-tools.com/RDP-Parser.html

Forensicator: https://hakin9.org/live-forensicator-powershell-script-to-aid-incidence-response-and-live-forensics/

## Network Forensic Tool

Network Miner

Scalpel

Hands on:

https://www.malware-traffic-analysis.net/

https://cyberdefenders.org/



## Online Resources

https://www.garykessler.net/library/file_sigs.html

## Specific info on system

### OS version:

`SOFTWARE\Microsoft\Windows NT\CurrentVersion`

### Computer Name:

`SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`

### Time Zone Information:

`SYSTEM\CurrentControlSet\Control\TimeZoneInformation`

### Network Interfaces and Past Networks:

`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`

`SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged`

`SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed`

### Autostart Programs (Autoruns):

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`

`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`

`SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run`

`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

### Services

`SYSTEM\CurrentControlSet\Services`

### SAM hive and user information:

`SAM\Domains\Account\Users`

### Recent Files:

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.pdf`

`NTUSER.DAT\Software\Microsoft\Office\VERSION`

`NTUSER.DAT\Software\Microsoft\Office\15.0\Word`

rif. https://docs.microsoft.com/en-us/deployoffice/install-different-office-visio-and-project-versions-on-the-same-computer#office-releases-and-their-version-number

rif. https://www.microsoft.com/security/blog/2008/05/07/what-is-a-windows-live-id/
	
### Shellbags

`USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`

`USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`

`NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`

`NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`

### Open/Save and LastVisited Dialog MRUs:

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU`

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`

### Windows Explorer Address/Search Bars:

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`

### Evidence of Execution

#### UserAssist 

`NTUSER.DAT\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\{GUID}\Count`

Other resources:

https://blog.didierstevens.com/programs/userassist/

https://www.nirsoft.net/utils/userassist_view.html

#### ShimCache:

`SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`

#### AmCache

`C:\Windows\appcompat\Programs\Amcache.hve`

`Amcache.hve\Root\File\{Volume GUID}\`

#### BAD/DAM

`SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`

`SYSTEM\CurrentControlSet\Services\dam\UserSettings\{SID}`

### External Devices

#### Device identification

`SYSTEM\CurrentControlSet\Enum\USBSTOR`

`SYSTEM\CurrentControlSet\Enum\USB`

#### First/Last Times:

`SYSTEM\CurrentControlSet\Enum\USBSTOR\Ven_Prod_Version\USBSerial#\Properties\{83da6326-97a6-4088-9453-a19231573b29}\####`

#### USB device Volume Name:

`SOFTWARE\Microsoft\Windows Portable Devices\Devices`



