# Memoryforensics

Level: easy

https://tryhackme.com/room/memoryforensics

# Volatility profile

```
joshua@kaligra:~/Documents/thm/memoryforensics$ vol.py -f Snapshot6.vmem imageinfo
Volatility Foundation Volatility Framework 2.6.1
*** Failed to import volatility.plugins.malware.apihooks (NameError: name 'distorm3' is not defined)
*** Failed to import volatility.plugins.malware.threads (NameError: name 'distorm3' is not defined)
*** Failed to import volatility.plugins.mac.apihooks_kernel (ImportError: Error loading the diStorm dynamic library (or cannot load library into process).)
*** Failed to import volatility.plugins.mac.check_syscall_shadow (ImportError: Error loading the diStorm dynamic library (or cannot load library into process).)
*** Failed to import volatility.plugins.ssdt (NameError: name 'distorm3' is not defined)
*** Failed to import volatility.plugins.mac.apihooks (ImportError: Error loading the diStorm dynamic library (or cannot load library into process).)
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/joshua/Documents/thm/memoryforensics/Snapshot6.vmem)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf80002c4a0a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002c4bd00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2020-12-27 06:20:05 UTC+0000
     Image local date and time : 2020-12-26 22:20:05 -0800
```

We will use: `Win7SP1x64`

# Task 2

```
joshua@kaligra:~/Documents/thm/memoryforensics$ vol.py --profile Win7SP1x64 -f Snapshot6.vmem hashdump
Volatility Foundation Volatility Framework 2.6.1
*** Failed to import volatility.plugins.malware.apihooks (NameError: name 'distorm3' is not defined)
*** Failed to import volatility.plugins.malware.threads (NameError: name 'distorm3' is not defined)
*** Failed to import volatility.plugins.mac.apihooks_kernel (ImportError: Error loading the diStorm dynamic library (or cannot load library into process).)
*** Failed to import volatility.plugins.mac.check_syscall_shadow (ImportError: Error loading the diStorm dynamic library (or cannot load library into process).)
*** Failed to import volatility.plugins.ssdt (NameError: name 'distorm3' is not defined)
*** Failed to import volatility.plugins.mac.apihooks (ImportError: Error loading the diStorm dynamic library (or cannot load library into process).)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
John:1001:aad3b435b51404eeaad3b435b51404ee:47fbd6536d7868c873d5ea455f2fc0c9:::
HomeGroupUser$:1002:aad3b435b51404eeaad3b435b51404ee:91c34c06b7988e216c3bfeb9530cabfb:::
```

```
joshua@kaligra:~/Documents/thm/memoryforensics$ hashcat -m 1000 '47fbd6536d7868c873d5ea455f2fc0c9' /usr/share/wordlists/rockyou.txt
hashcat (v6.2.5) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-4770K CPU @ 3.50GHz, 1441/2947 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1
..
..
..
47fbd6536d7868c873d5ea455f2fc0c9:charmander999

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: 47fbd6536d7868c873d5ea455f2fc0c9
Time.Started.....: Sun Aug 21 13:02:21 2022 (7 secs)
Time.Estimated...: Sun Aug 21 13:02:28 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1489.7 kH/s (0.06ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 9181184/14344385 (64.01%)
Rejected.........: 0/9181184 (0.00%)
Restore.Point....: 9180672/14344385 (64.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: charmed72 -> charm1975
Hardware.Mon.#1..: Util: 59%

Started: Sun Aug 21 13:02:17 2022
Stopped: Sun Aug 21 13:02:29 2022
```

Answer: `charmander999`

# Task 3

```
joshua@kaligra:~/Documents/thm/memoryforensics$ vol.py --profile Win7SP1x64 -f Snapshot19.vmem shutdowntime
Volatility Foundation Volatility Framework 2.6.1
*** Failed to import volatility.plugins.malware.apihooks (NameError: name 'distorm3' is not defined)
*** Failed to import volatility.plugins.malware.threads (NameError: name 'distorm3' is not defined)
*** Failed to import volatility.plugins.mac.apihooks_kernel (ImportError: Error loading the diStorm dynamic library (or cannot load library into process).)
*** Failed to import volatility.plugins.mac.check_syscall_shadow (ImportError: Error loading the diStorm dynamic library (or cannot load library into process).)
*** Failed to import volatility.plugins.ssdt (NameError: name 'distorm3' is not defined)
*** Failed to import volatility.plugins.mac.apihooks (ImportError: Error loading the diStorm dynamic library (or cannot load library into process).)
Registry: SYSTEM
Key Path: ControlSet001\Control\Windows
Key Last updated: 2020-12-27 22:50:12 UTC+0000
Value Name: ShutdownTime
Value: 2020-12-27 22:50:12 UTC+0000
```

Answer: `2020-12-27 22:50:12`

# Task 4

```
joshua@kaligra:~/Documents/thm/memoryforensics$ vol.py --profile Win7SP1x64 -f Snapshot19.vmem cmdscan
Volatility Foundation Volatility Framework 2.6.1
*** Failed to import volatility.plugins.malware.apihooks (NameError: name 'distorm3' is not defined)
*** Failed to import volatility.plugins.malware.threads (NameError: name 'distorm3' is not defined)
*** Failed to import volatility.plugins.mac.apihooks_kernel (ImportError: Error loading the diStorm dynamic library (or cannot load library into process).)
*** Failed to import volatility.plugins.mac.check_syscall_shadow (ImportError: Error loading the diStorm dynamic library (or cannot load library into process).)
*** Failed to import volatility.plugins.ssdt (NameError: name 'distorm3' is not defined)
*** Failed to import volatility.plugins.mac.apihooks (ImportError: Error loading the diStorm dynamic library (or cannot load library into process).)
**************************************************
CommandProcess: conhost.exe Pid: 2488
CommandHistory: 0x21e9c0 Application: cmd.exe Flags: Allocated, Reset
CommandCount: 7 LastAdded: 6 LastDisplayed: 6
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x60
Cmd #0 @ 0x1fe3a0: cd /
Cmd #1 @ 0x1f78b0: echo THM{You_found_me} > test.txt
Cmd #2 @ 0x21dcf0: cls
Cmd #3 @ 0x1fe3c0: cd /Users
Cmd #4 @ 0x1fe3e0: cd /John
Cmd #5 @ 0x21db30: dir
Cmd #6 @ 0x1fe400: cd John
Cmd #15 @ 0x1e0158: "
Cmd #16 @ 0x21db30: dir
```

Answer: `You_found_me`

# Task 5

```
joshua@kaligra:~/Documents/thm/memoryforensics$ vol.py --profile Win7SP1x64 -f Snapshot14.vmem truecryptpassphrase
Volatility Foundation Volatility Framework 2.6.1
*** Failed to import volatility.plugins.malware.apihooks (NameError: name 'distorm3' is not defined)
*** Failed to import volatility.plugins.malware.threads (NameError: name 'distorm3' is not defined)
*** Failed to import volatility.plugins.mac.apihooks_kernel (ImportError: Error loading the diStorm dynamic library (or cannot load library into process).)
*** Failed to import volatility.plugins.mac.check_syscall_shadow (ImportError: Error loading the diStorm dynamic library (or cannot load library into process).)
*** Failed to import volatility.plugins.ssdt (NameError: name 'distorm3' is not defined)
*** Failed to import volatility.plugins.mac.apihooks (ImportError: Error loading the diStorm dynamic library (or cannot load library into process).)
Found at 0xfffff8800512bee4 length 11: forgetmenot
```

Answer: `forgetmenot`	
