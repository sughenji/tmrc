# Random Stuff

- [Mount SSHFS](#mount-sshfs)

## Mount SSHFS

First install this:

https://github.com/winfsp/winfsp/releases

Then this:

https://github.com/winfsp/sshfs-win


```
net use s: \\sshfs.r\user@192.168.1.14!22222\home\user\Documents
```

```
net use s: /delete
```


Mount C$ with AD credentials:

```
mount -t cifs \\\\192.168.1.14\\C$ /mnt/ -o domain=SUGOLANDIA,user=sugo
```

Capture network traffic with files rotation

```
tshark.exe -b interval:3600 -b files:48 -f "port 53" -i Ethernet0 -w c:\users\sugo\downloads\traffic.pcapng
```
