
`ossec.conf` is vulnerabiliy detecton ON on wazuh-manager?




è possibile integrare VirusTotal con il modulo Wazuh FIM

riferimento:

https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html

`/var/ossec/etc/ossec.conf`

```xml
<!-- File integration monitor -->
<syscheck>
 <disabled>no</disabled>
```

```xml
<!-- directory to check -->
add this:
<directory realtime="yes">/home/sugo/Downloads</directories>
```


