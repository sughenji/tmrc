# Post compromise

- [Audit log](#audit-log)
- [cPanel logs](#cpanel-logs)
- [Search in time](#search-in-time)
- [Obfuscated PHP code](#obfuscated-php-code)
- [Online scanner](#online-scanner)
- [Manual scan](#manual-scan)
- [Plugins](#plugins)

# Audit Log

(we must have `WordFence` installed)

```
SELECT from_unixtime(ctime),username,INET6_NTOA(IP),action FROM `wccorp_wflogins` ORDER BY `from_unixtime(ctime)` ASC;
```

# cPanel Logs

(we must have in WHM >> Tweak Settings >> Logging: "Log successful logins" On!)

check file `/usr/local/cpanel/logs/login_log`

FTP logs are in `/var/log/messages`

```
# grep "is now logged in" /var/log/messages |grep -v 127.0.0.1
```

# Search in time

```
find -newerct "8 Sep 2022" ! -newerct "9 Sep 2022" -ls |grep php
```

```
find / -mtime 10 # find files that were modified in the last 10 days
find / -atime 10 # find files that were accessed in the last 10 day
find / -cmin -60 # find files changed within the last hour (60 minutes)
find / -amin -60 # find files accesses within the last hour (60 minutes)
```


# Obfuscated PHP Code

https://glot.io/snippets/efruafhnez

# Online Scanner

https://sitecheck.sucuri.net/

https://www.isitwp.com/wordpress-website-security-scanner/

https://wpsec.com/?ref=syedbalkhi18

http://www.scanwp.com/

https://hackertarget.com/wordpress-security-scan/

https://wprecon.com/

https://www.webinspector.com/website-malware-scanner/

https://urlquery.net/

https://www.virustotal.com/gui/home/upload

https://safeweb.norton.com/

# Manual scan

Search for php files in `uploads` directory (you should not find any)

# Plugins

https://it.wordpress.org/plugins/gotmls/ 


