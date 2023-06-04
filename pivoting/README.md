# Pivoting

- [chisel](#chisel)
- [ssh tunneling](#ssh-tunneling)

## chisel

On pivot host:

```
./chisel server -v -p 1234 --socks5
```

On attack host:

```
./chisel client IP_PIVOT_HOST:1234 socks
```

Configure `proxychains` with:

```
socks5	127.0.0.1 1080
```

Now, from attack host, you can run:

```
proxychains xfreerdp /v:10.0.2.200 /u:administrator /p:asd
```

## ssh tunneling


```
ssh -D 9050 sugo@some-remote-host
```

Edit `/etc/proxychains.conf` with this line:

```
socks4 127.0.0.1 9050
```

Run `nmap`:

```
proxychains nmap -Pn -sT some-other-remote-ip
```

Note: on target host, traffic will have sock's source ip, not yours.





