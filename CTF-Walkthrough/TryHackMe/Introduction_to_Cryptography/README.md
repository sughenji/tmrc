# Introduction to Cryptography

## Hashing

```
#!/usr/bin/python3

import hashlib
import hmac

file = open('order.txt', "r")
key = b'3RfDFz82'
content = file.read().encode()

hmac_value = hmac.new(key, content, hashlib.sha256).hexdigest()
print(hmac_value)
```

## Authenticating with passwords

```
$ hashcat -m 0 '3fc0a7acf087f549ac2b266baf94b8b1' /usr/share/wordlists/rockyou.txt
```

(answer: `qwerty123`)

