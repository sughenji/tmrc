# CyberHeroes

URL: https://tryhackme.com/room/cyberheroes

Level: Easy

Date: 5 Aug 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [Website](#website)
	- [Feroxbuster](#feroxbuster)
	- [Burpsuite](#burpsuite)
	- [Page Source](#page-source)
	




## Reconnaissance

### nmap

```bash
joshua@kaligra:~/Documents/thm/cyberheroes$ sudo nmap -T4 -p- 10.10.253.134 -oA nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-05 13:07 CEST
Nmap scan report for 10.10.253.134
Host is up (0.061s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 38.31 seconds
```

```bash
joshua@kaligra:~/Documents/thm/cyberheroes$ sudo nmap -T4 -p80 -sC -sV 10.10.253.134 -oA nmap2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-05 13:08 CEST
Nmap scan report for 10.10.253.134
Host is up (0.054s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.48 ((Ubuntu))
|_http-server-header: Apache/2.4.48 (Ubuntu)
|_http-title: CyberHeros : Index

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.00 seconds
```

### website

![](Pasted%20image%2020230805130926.png)

![](Pasted%20image%2020230805131040.png)

`admin/admin`

![](Pasted%20image%2020230805131103.png)

### feroxbuster

```bash
joshua@kaligra:~/Documents/thm/cyberheroes$ feroxbuster --silent -u http://10.10.253.134 -t 200 -L 1 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -o ferox.txt
http://10.10.253.134/
http://10.10.253.134/assets => http://10.10.253.134/assets/
http://10.10.253.134/server-status
```

### Burpsuite

We fire up `Burpsuite`, but we notice that there is no network traffic during login phase:

![](Pasted%20image%2020230805131806.png)

So, authentication should be managed with some JS, maybe.

### Page source


Let's check page source:

```html
<script>
    function authenticate() {
      a = document.getElementById('uname')
      b = document.getElementById('pass')
      const RevereString = str => [...str].reverse().join('');
      if (a.value=="h3ck3rBoi" & b.value==RevereString("54321@terceSrepuS")) { 
        var xhttp = new XMLHttpRequest();
        xhttp.onreadystatechange = function() {
          if (this.readyState == 4 && this.status == 200) {
            document.getElementById("flag").innerHTML = this.responseText ;
            document.getElementById("todel").innerHTML = "";
            document.getElementById("rm").remove() ;
          }
        };
        xhttp.open("GET", "RandomLo0o0o0o0o0o0o0o0o0o0gpath12345_Flag_"+a.value+"_"+b.value+".txt", true);
        xhttp.send();
      }
      else {
        alert("Incorrect Password, try again.. you got this hacker !")
      }
    }
  </script>
```

![](Pasted%20image%2020230805132836.png)

Pretty easy.

