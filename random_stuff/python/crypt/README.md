# encrypt string in sha256

```python
import hashlib
h = hashlib.new("SHA256") # initialize the sha256() method
h.update(b"Hello World!") # we want bytes
print(h.digest())
b'\x7f\x83\xb1e\x7f\xf1\xfcS\xb9-\xc1\x81H\xa1\xd6]\xfc-K\x1f\xa3\xd6w(J\xdd\xd2\x00\x12m\x90i'
print(h.hexdigest())
7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069

# oppure
h = hashlib.sha256()
h.update(b"Hello World!") # we want bytes
print(h.hexdigest())
```