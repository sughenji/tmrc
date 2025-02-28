
## only-syn

to see only traffic which *starts* (SYN) from this machine (ip: 1.2.3.4)

```bash
tcpdump -nn 'tcp[tcpflags] == tcp-syn' and src host 1.2.3.4
```



