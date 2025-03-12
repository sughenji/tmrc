https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change

L'obiettivo è accedere con utente `carlos`, e con una password presente in una lista già fornita:

https://portswigger.net/web-security/authentication/auth-lab-passwords

...ci si potrebbe domandare: perché non fare brute-force direttamente sul form di login?

Probabilmente per questo motivo:

![](_attachment/Pasted%20image%2020250302125237.png)

...evidentemente il form di accesso blocca dopo x tentativi di accesso. Il form per il reset password no :)

Vediamo dunque qual'è una richiesta di cambio password "legittima" (relativa al cambio password di `wiener`):

```html
POST /my-account/change-password HTTP/2
Host: 0a1400d404a7bea2845c3b480055000b.web-security-academy.net
Cookie: session=iSM2rL8HdXYet2wZ2LxEsvHtDGOR7Z1v
Content-Length: 86
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="133", "Not(A:Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Origin: https://0a1400d404a7bea2845c3b480055000b.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a1400d404a7bea2845c3b480055000b.web-security-academy.net/my-account?id=wiener
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

username=wiener&current-password=peter&new-password-1=password&new-password-2=password
```

risposta:

```html
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 2641

..
..
```



vediamo anche una richiesta di cambio password in cui mettiamo, volutamente, la password corrente sbagliata:

```html
POST /my-account/change-password HTTP/2
Host: 0a1400d404a7bea2845c3b480055000b.web-security-academy.net
Cookie: session=CsrdzZ1DshclWvDhuSXNLhwYUnp2nYso
Content-Length: 79
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="133", "Not(A:Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Origin: https://0a1400d404a7bea2845c3b480055000b.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a1400d404a7bea2845c3b480055000b.web-security-academy.net/my-account?id=wiener
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

username=wiener&current-password=rofl&new-password-1=rofl3&new-password-2=rofl3
```

risposta:

```html
HTTP/2 302 Found
Location: /login
Set-Cookie: session=W8rLaM0LCJQ9MMkcsQUHmSOvNnj7vLwx; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 0 <============
```

## try to brute force

inviamo questa richiesta al tab "intruder"

(dobbiamo sostituire ovviamente `wiener` con `carlos`) 

ho anche tolto il Cookie

```html
POST /my-account/change-password HTTP/2
Host: 0a1400d404a7bea2845c3b480055000b.web-security-academy.net
Content-Length: 86
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="133", "Not(A:Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Origin: https://0a1400d404a7bea2845c3b480055000b.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a1400d404a7bea2845c3b480055000b.web-security-academy.net/my-account?id=carlos
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

username=carlos&current-password=peter&new-password-1=password&new-password-2=password
```

...tutti i nostri tentativi sembrano NON andare a buon fine:

![](_attachment/Pasted%20image%2020250302132433.png)

idea: probabilmente nelle nostre richieste dobbiamo eliminare l'header `Content-Lenght`, in quanto NON sarebbe corrispondente ai nostri payload (la lunghezza delle password non è sempre la stessa).

EDIT: ho visto la soluzione, probabilmente non ci sarei arrivato :D



