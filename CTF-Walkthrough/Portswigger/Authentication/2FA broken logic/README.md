https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic

wiener's login phases:

```http
POST /login HTTP/2
Host: 0a7400230339cbd8e4f7cbac00d500c3.web-security-academy.net
Cookie: verify=wiener; session=b85gDyYatG9fCV4Amw62m5H2Kvo3kZC5
Content-Length: 30
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="131", "Not_A Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Origin: https://0a7400230339cbd8e4f7cbac00d500c3.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.140 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a7400230339cbd8e4f7cbac00d500c3.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

username=wiener&password=peter
```

```http
GET /login2 HTTP/2
Host: 0a7400230339cbd8e4f7cbac00d500c3.web-security-academy.net
Cookie: verify=wiener; session=ZigneBT2Sg5wqLSaW8YgCMdEd0MvZGDb
Cache-Control: max-age=0
Accept-Language: it-IT,it;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.140 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Sec-Ch-Ua: "Chromium";v="131", "Not_A Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Referer: https://0a7400230339cbd8e4f7cbac00d500c3.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
```

after this, wiener needs to put his 2FA code  (we can retrieve it from "email client" menu):

```bash
Sent:     2025-01-11 16:23:24 +0000
From:     no-reply@0a7400230339cbd8e4f7cbac00d500c3.web-security-academy.net
To:       wiener@exploit-0a3000d80399cbe5e487ca2e01af00a4.exploit-server.net
Subject:  Security code

Hello!

Your security code is 0890.

Please enter this in the app to continue.

Thanks,
Support team
```

```http
POST /login2 HTTP/2
Host: 0a7400230339cbd8e4f7cbac00d500c3.web-security-academy.net
Cookie: verify=wiener; session=ZigneBT2Sg5wqLSaW8YgCMdEd0MvZGDb
Content-Length: 13
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="131", "Not_A Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Origin: https://0a7400230339cbd8e4f7cbac00d500c3.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.140 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a7400230339cbd8e4f7cbac00d500c3.web-security-academy.net/login2
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

mfa-code=0890
```

wiener's home

```http
GET /my-account?id=wiener HTTP/2
Host: 0a7400230339cbd8e4f7cbac00d500c3.web-security-academy.net
Cookie: verify=wiener; session=l3NlBUkTU5IbRUf8jbqwMsE4eitU7qmn
Cache-Control: max-age=0
Accept-Language: it-IT,it;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.140 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Sec-Ch-Ua: "Chromium";v="131", "Not_A Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Referer: https://0a7400230339cbd8e4f7cbac00d500c3.web-security-academy.net/my-account?id=wiener
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

```