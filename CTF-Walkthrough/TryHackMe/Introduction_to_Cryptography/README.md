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
