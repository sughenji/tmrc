# Random Stuff

Mount SSHFS

```
net use s: \\sshfs.r\user@192.168.1.14!22222\home\user\Documents
```

Mount C$ with AD credentials:

```
mount -t cifs \\\\192.168.1.14\\C$ /mnt/ -o domain=SUGOLANDIA,user=sugo
```
