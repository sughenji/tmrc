# Python

- [Simple GET request](#simple-get-request)
- [GET request with parameter](#get-request-with-parameter)
- [GET request with header](#get-request-with-header)
- [GET request with manual cookie](#get-request-with-manual-cookie)
- [print cookie](#print-cookie)
- [HEAD method](#head-method)
- [POST request](#post-request)
- [POST with JSON body](#post-with-json-body)
- [OPTIONS method](#options-method)
- [Token CSRF](#token-csrf)
- [Extract HTML elements](#extract-html-elements)
- [Scraping with regexp](#scraping-with-regexp)
- [Loggin into DVWA](#logging-into-dvwa)
- [Upload file](#upload-file)


## simple get request

```
#!/usr/bin/python3
import requests
r = requests.get('http://someurl.domain/')
print(r.text)
```

to only print status code:

```
>>> print(r.status_code)
200
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

## print cookie

```
import requests

s = requests.Session()
s.get('http://domain.url/token')
print('Cookie:\n')
print(s.cookies)
r = s.get('http://domain.url/flag')
print(r.text)
```

## head method

```
#!/usr/bin/python3

import requests
r = requests.head('http://domain.url/')
print(r.headers)
```

## post request

```
import requests

payload = { 'username': 'admin', 'password': 'admin' }
r = requests.post('http://domain.url/login', data=payload)
print(r.text)
```

## post with json body

```
import requests

r = requests.post('http://domain.url/login', json={
    "username": "admin",
    "password": "admin"
})

print(f"Status Code: {r.status_code}, Response: {r.json()}")
```

## options method

```
import requests

r = requests.options('http://domain.url/')
print('Headers ricevuti:\n')
print(r.headers)
```

## token csrf

In this example, the token is obtained with an initial POST request.

Then, the CSRF token is sent to other pages (index 1..4):


```
import requests

s = requests.Session()
req = s.post('http://domain.url/login', json={"username": "admin", "password": "admin"})

token = req.json()['csrf']

for i in range(4):
    req = s.get('http://domain.url/flag_piece', params={ "index": i, "csrf": token }, cookies=req.cookies)
    print(req.text)
    token = req.json()['csrf']
```

## extract html elements

```
#!/usr/bin/python3

import requests

url = 'http://domain.url/'

r = requests.get(url)

from bs4 import BeautifulSoup
soup = BeautifulSoup(r.content, 'html.parser')

# stampo il titolo
print(soup.title)
print(soup.title.string)

# printo i paragrafi
for link in soup.find_all('p'):
        print(link)
```

more advanced example (only "red" elements)

```
#!/usr/bin/python3

import requests
from bs4 import BeautifulSoup as bs

req = requests.get('http://domain.url/')

"""
print(req.text)
"""

soup = bs(req.text, 'html.parser')

for letter in soup.find_all('span', {'class': 'red'}):
    print(letter.text, end="")
```

only comments:

```
#!/usr/bin/python3

import requests
import bs4

req = requests.get('http://domain.url')
soup = bs4.BeautifulSoup(req.text, 'html.parser')
#print(soup)
comments = soup.find_all(string=lambda text: isinstance(text, bs4.Comment))
for c in comments:
    print(c)
    print("===========")
    c.extract()
```

extract links and javascript according to regexp:


```
#!/usr/bin/python3

"""
https://pytutorial.com/get-get-script-beautifulsoup/
"""

import requests,bs4,re

url = 'http://domain.url'

req = requests.get(url)

soup = bs4.BeautifulSoup(req.text, 'html.parser')
#print(soup)

# estrae e printa tutti i link
links = soup.find_all('link')
print(links)

# estrae e printa tutti gli script
scripts = soup.find_all('script')
print(scripts)

# estrae solo il src
for script in scripts:
    print(script['src'])

for script in scripts:
    req2 = requests.get(url+script['src'])
    res = req2.text

m = re.compile('.*flag.*')

mo = m.search(res)

print(mo.group())
```

or

```
#!/usr/bin/python3

import bs4, requests, re

url='http://domain.url'

req = requests.get(url)

soup = bs4.BeautifulSoup(req.text, 'html.parser')

print('Printing links ...')
print('=' * 30)
for link in soup.find_all('a'):
    print(link.get('href'))

print('Printing javascript ...')
print('=' * 30)
script_list = []
for script in soup.find_all('script'):
    print(script.get('src'))
    script_list.append(script.get('src'))

# creating regexp

r = re.compile('.*flag.*')

print('Scraping resources ...')
for i in script_list:
    print(url + i)
    req = requests.get(url+i)
    body = req.text
    mo = r.search(body)
    print(mo.group())
```

## scraping with regexp

```
#!/usr/bin/python

import re,requests
from bs4 import BeautifulSoup as bs

url = 'http://domain.url/'

pattern = re.compile(r'^flag')

# let's define an empty list
urilist = []

# define a "scrape" function

def scrape(url):
    req = requests.get(url)
    soup = bs(req.text, 'html.parser')

    # find all h1 items
    for head in soup.find_all('h1'):
        if re.match(pattern, head.text):
            print("Flag founded!!!")
            print(head.text)
            exit()

    for link in soup.find_all('a', href=True):
        uri = link['href']
        print("...Testing: "+uri)
        if uri not in urilist:
            urilist.append(uri)

scrape(url)
for i in urilist:
    scrape(url+i)
```

## logging into dvwa

this example involves cookie, csrf, some headers:

```
#!/usr/bin/python3

import requests
from bs4 import BeautifulSoup

# our proxy (burp?)
proxy = { 'http': 'http://127.0.0.1:8080' }

url = 'http://192.168.106.253/DVWA/login.php'
s = requests.Session()
req = s.get(url)
soup = BeautifulSoup(req.text, 'html.parser')

# we get our cookie
c = (req.cookies["PHPSESSID"])
print("Cookie: " + c + "\n")

# we need to grab only the "hidden" HTML object
hidden_input = soup.find('input', type='hidden')

# this is our token for the next request
csrf_token = hidden_input.get('value', '')
print("user_token: " + csrf_token + "\n")

# our actual POST request

payload = { 'username': 'gordonb', 'password': 'abc123', 'Login': 'Login', 'user_token': csrf_token }
headers = { 'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': 'PHPSESSID='+c }

req2 = s.post(url, data=payload, proxies=proxy, headers=headers)
print(req2.text)
```

## upload file

of course you need to know the correct names of the form

```python
import requests

file = open("logo.png", "rb")

url = "http://192.168.106.253/study/upload.php"

u = requests.post(url, files = {"fileToUpload": file})

if u.ok:
    print("File uploaded succesfully!")
else:
    print("Upload failed!")
```










