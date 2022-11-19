# Post compromise

- [Audit log](#audit-log)
- [cPanel logs](#cpanel-logs)
- [Search in time](#search-in-time)
- [Obfuscated PHP code](#obfuscated-php-code)

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

# Obfuscated PHP Code

https://glot.io/snippets/efruafhnez



