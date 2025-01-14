### Compiling C code on Linux

```
i686-w64-mingw32-gcc multiplestrings.c -o  multiplestrings.exe -lws2_32
```

NMAP:

https://seclists.org/nmap-dev/2017/q2/86

Doesn't work :(

```
$ file nmap
nmap: ELF 64-bit LSB pie executable, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=174172ed2f4b3791eb6dde98060cd7b1818bd2ad, for GNU/Linux 3.2.0, with debug_info, not stripped
```

Other resource:

https://github.com/kost/nmap-android/releases

### TMUX

Session -> can contain multiple windows -> which in turn can contain multiple panels

#### spawn new session

```
tmux new -s RSYSLOG
```

#### Resize pane down 

```
:resize-pane -D
```

#### Resize pane down 5 lines

```
:resize-pane -D 5
```

#### Toggle status bar

```
:set status off
```

#### "zoom" current pane

```
prefix+z
```

#### change prefix

Open `.tmux.conf` and set this

```
set -g prefix ^W
```

after:

```
:source-file .tmux.conf
```

#### load plugins

clone repository

```
git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
```

```
sugo@server$ cat .tmux.conf 

# plugins

set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'

# active plugins
run '~/.tmux/plugins/tpm/tpm'
```




### Ansible

Inventory:

```
sugo@vboxdebian:~/ansible$ cat inventory.yaml
matilda_cluster:
  hosts:
    relay01:
      ansible_host: 192.168.69.91
    relay02:
      ansible_host: 192.168.69.73
    relay03:
      ansible_host: 192.168.69.77

mailers:
  hosts:
    mailer1:
      ansible_host: 192.168.32.75
    mailer2:
      ansible_host: 192.168.32.69
    mailer3:
      ansible_host: 192.168.32.68

mailclusters:
  children:
    matilda_cluster:
    mailers:

rancid:
  hosts:
    rancido:
      ansible_host: 192.168.50.253
```

`apt update` playbook:

```
sugo@vboxdebian:~/ansible$ cat mailclusters_debian_update.yaml
---
- hosts: mailclusters
  tasks:
    - name: Run apt update
      apt: update_cache=yes force_apt_get=yes cache_valid_time=3600
```

(we are using `root` user)

```
ansible-playbook -i inventory.yaml  mailclusters_debian_update.yaml -u root
```

`apt update && apt upgrade` playbook:

```
sugo@vboxdebian:~/ansible$ cat mailclusters_debian_upgrade.yaml
---
- hosts: mailclusters
  tasks:
    - name: Run apt update
      apt: update_cache=yes force_apt_get=yes cache_valid_time=3600
    - name: Run apt upgrade
      apt: upgrade=dist force_apt_get=yes
```

For `yum update`:

Add your user to `sudoers`, like:

```
# to allow yum 
sugo            ALL=(ALL)       NOPASSWD: /usr/bin/yum
```

Populate your inventory:

```
diameters:
  hosts:
    diameter:
      ansible_host: xx.yy.69.82
    diameter2:
      ansible_host: xx.yy.69.4
    diameter3:
      ansible_host: xx.yy.69.80
```

Use `shell` module:

```
$ ansible diameters -m shell -i inventory.yaml -usugo -a "sudo yum update -y"
```




### VIM

remove all highlights:

```
:noh
```

### ulimit

```
# sudo -u bareos bash -c 'ulimit -n'
1024
```

https://woshub.com/too-many-open-files-error-linux/

## bash

### process substitution

Useful if you want, for example, compare two directories.

```bash
joshua@kaligra:~$ ls dir1
a  b  c  d  f
joshua@kaligra:~$ ls dir2
b  c  e
joshua@kaligra:~$ diff <(ls dir1) <(ls dir2)
1d0
< a
4,5c3
< d
< f
---
> e
```

```bash
joshua@kaligra:~$ cat <(ls dir1)
a
b
c
d
f
joshua@kaligra:~$ echo <(ls dir1)
/dev/fd/63
```

### eval

with `eval` the commands affect the current shell

https://stackoverflow.com/questions/43001805/whats-the-difference-between-eval-command-and-command

"If you know that a variable contains an executable command you can run it without eval. But if the variable might contain Bash code which is not simply an executable command (i.e. something you could imagine passing to the C function exec()), you need eval"

### merge two text files with a common column

File 1:

```bash
username;cleartextpassword
000001;password1
000003;password2
000004;Password3
000005;Password@123
000006;p4ssw0rd
000007;Password123
```

File 2:

```bash
username;hash
000001;10b222970537b97919db36ec757370d2
000003;f1f16683f3e0208131b46d37a79c8921
000004;5ce9c348d27da686330914930683eca6
000005;637a2b9c5880de28b39d106a50082588
000006;f1697e66a08b79532d5802a5cf6ffa4c
000007;a907ac8f85bbece3069a52a39947b287
```

If the goal is to obation a single output with all three columns (`username`, `cleartextpassword`, `hash`), we can use:

```bash
$ for i in $(cat file1); do USER=$(echo $i | awk -F ';' '{ print $1 }'); CLEARTEXTPASS=$(echo $i | awk -F ';' '{ print $2 }'); HASH=$(grep $USER file2 | awk -F ';' '{ print $2 }'); echo $USER";"$CLEARTEXTPASS";"$HASH; done
000001;password1;10b222970537b97919db36ec757370d2
000003;password2;f1f16683f3e0208131b46d37a79c8921
000004;Password3;5ce9c348d27da686330914930683eca6
000005;Password@123;637a2b9c5880de28b39d106a50082588
000006;p4ssw0rd;f1697e66a08b79532d5802a5cf6ffa4c
000007;Password123;a907ac8f85bbece3069a52a39947b287
```

