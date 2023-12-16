# Python

- [Simple GET request](#simple-get-request)
- [GET request with parameter](#get-request-with-parameter)
- [GET request with header](#get-request-with-header)
- [GET request with manual cookie](#get-request-with-manual-cookie)


## simple get request

```
#!/usr/bin/python3
import requests
r = requests.get('http://someurl.domain/')
print(r.text)
```

with BeautifulSoup

```
>>> import requests
>>> from bs4 import BeautifulSoup as bs
>>> r = requests.get('http://someurl.domain/')
>>> soup = bs(r.text)
>>> print(type(soup))
<class 'bs4.BeautifulSoup'>
>>> print(soup)
<html><body><p>flag{g3t7ing_4l0ng}</p></body></html>
>>>
```

## get request with parameter

```
#!/usr/bin/python3
import requests
payload = { 'id': 'flag' }
r = requests.get('http://someurl.domain/server-records', params=payload)
print(r.text)
```

## get request with header

```
#!/usr/bin/python3

import requests

"""
url = 'https://api.github.com/some/endpoint'
headers = {'user-agent': 'my-app/0.0.1'}
r = requests.get(url, headers=headers)
"""

url = 'http://someurl.domain/flag'
headers = { 'X-Password': 'admin' }
r = requests.get(url, headers=headers)
print(r.text)
```

```
url = 'http://someurl.domain/users'
headers = {'Accept': 'application/xml'}
r = requests.get(url, headers=headers)
print('With Accept header:\n')
print(r.text)
```

## get request with manual cookie

```
import requests

url = 'http://someurl.domain'
cookies = dict(password='admin')
r = requests.get(url, cookies=cookies)
print(r.text)
```

