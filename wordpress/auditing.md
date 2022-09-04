# Auditing

- [Audit log](#audit-log)

# Audit Log

(we must have `WordFence` installed)

```
SELECT from_unixtime(ctime),username,INET6_NTOA(IP),action FROM `wccorp_wflogins` ORDER BY `from_unixtime(ctime)` ASC;
```


