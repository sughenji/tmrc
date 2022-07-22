# Pivoting

- [chisel](#chisel)

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
