### create a bot

Use `BotFather` and type: `/newbot`

Select Name, username.

You will receive your token

### get chatid

Create a group, add your new bot to group.

Visite this link (with YOUR token) and get your Chat ID (eg. -3473842)

https://api.telegram.org/bot6577957123:AAEusEImcUt3xm8YESrTS6oagbsd-O_qwPk/getUpdates

### send message

#### python

```
#!/usr/bin/python3
import requests

def send_to_telegram(message):

    apiToken = '6577957123:AAEusEImcUt3xm8NOTrTS6oagasd-O_qwPk'
    # gruppo "Sugo bot"
    chatID= '-628611232'
    apiURL = f'https://api.telegram.org/bot{apiToken}/sendMessage'

    try:
        response = requests.post(apiURL, json={'chat_id': chatID, 'text': message})
        print(response.text)
    except Exception as e:
        print(e)

send_to_telegram("Hello from Python!")
```

#### powershell

```
$Message="ciao"
$Telegramtoken = "6577957123:AAEusEImcUt3xm8NOTrTS6oagasd-O_qwPk"
$Telegramchatid = "-62861232"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-RestMethod -Uri "https://api.telegram.org/bot$($Telegramtoken)/sendMessage?chat_id=$($Telegramchatid)&text=$($Message)"
