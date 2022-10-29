![[Pasted image 20221029115012.png]]

HTML source:

```
<!DOCTYPE html>
<html lang="en">
<head>
  <title>Rick is sup4r cool</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="[assets/bootstrap.min.css](view-source:https://10-10-104-194.p.thmlabs.com/assets/bootstrap.min.css)">
  <script src="[assets/jquery.min.js](view-source:https://10-10-104-194.p.thmlabs.com/assets/jquery.min.js)"></script>
  <script src="[assets/bootstrap.min.js](view-source:https://10-10-104-194.p.thmlabs.com/assets/bootstrap.min.js)"></script>
  <style>
  .jumbotron {
    background-image: url("assets/rickandmorty.jpeg");
    background-size: cover;
    height: 340px;
  }
  </style>
</head>
<body>

  <div class="container">
    <div class="jumbotron"></div>
    <h1>Help Morty!</h1></br>
    <p>Listen Morty... I need your help, I've turned myself into a pickle again and this time I can't change back!</p></br>
    <p>I need you to <b>*BURRRP*</b>....Morty, logon to my computer and find the last three secret ingredients to finish my pickle-reverse potion. The only problem is,
    I have no idea what the <b>*BURRRRRRRRP*</b>, password was! Help Morty, Help!</p></br>
  </div>

  <!--
    Note to self, remember username!
    Username: R1ckRul3s
  -->

</body>
</html>
```

/assets

![[Pasted image 20221029115526.png]]


```
joshua@kaligra:~/Documents/thm/Pickle Rick/Walkthrough/01_enumeration$ gobuster dir -u https://10-10-104-194.p.thmlabs.com/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,bak,php
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10-10-104-194.p.thmlabs.com/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Extensions:              txt,bak,php
[+] Timeout:                 10s
===============================================================
2022/10/29 12:10:39 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 306]
/login.php            (Status: 200) [Size: 882]
/assets               (Status: 301) [Size: 343] [--> http://10-10-104-194.p.thmlabs.com/assets/]
/portal.php           (Status: 302) [Size: 0] [--> /login.php]
/robots.txt           (Status: 200) [Size: 17]

```


```
joshua@kaligra:~/Documents/thm/Pickle Rick/Walkthrough/01_enumeration$ wget http://10-10-104-194.p.thmlabs.com/robots.txt
--2022-10-29 12:12:45--  http://10-10-104-194.p.thmlabs.com/robots.txt
Resolving 10-10-104-194.p.thmlabs.com (10-10-104-194.p.thmlabs.com)... 54.246.5.175
Connecting to 10-10-104-194.p.thmlabs.com (10-10-104-194.p.thmlabs.com)|54.246.5.175|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 17 [text/plain]
Saving to: ‘robots.txt’

robots.txt                                      100%[=====================================================================================================>]      17  --.-KB/s    in 0s

2022-10-29 12:12:45 (759 KB/s) - ‘robots.txt’ saved [17/17]

joshua@kaligra:~/Documents/thm/Pickle Rick/Walkthrough/01_enumeration$ cat robots.txt
Wubbalubbadubdub

```

