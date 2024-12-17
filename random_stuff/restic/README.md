## restic create repository

```bash
restic -p /root/.restic_password -r sftp://backup_username@1.2.3.4/home/backup_username/ init
```

## restic backup

```bash
restic -p /root/.restic_password  -r sftp://backup_username@1.2.3.4/home/backup_username/  backup /etc /var/backups
```

## restic forget

Remember to actually prune data!

```bash
restic -p /root/.restic_password  -r sftp://backup_username@1.2.3.4/home/backup_username/ forget --keep-daily 6 --keep-weekly 2 --prune
```

## restic check

```bash
restic -p /root/.restic_password -r ... check
```

If you want a more reliable check, please add `--read-data`
 
## restic check several repos

(Passwords are store on encrypted luks device)

```bash
#!/bin/bash

# first, we need to unlock our vault

/usr/sbin/cryptsetup open --type luks /root/scripts/vaultfile myvault

/usr/bin/mount /dev/mapper/myvault /mnt/vault

# read repository's pass from file and start checking

for i in $(cat /mnt/vault/data.txt); do
        ACCOUNT=`echo $i | awk -F ',' '{ print $1 }'`
        KEY=`echo $i | awk -F ',' '{ print $2 }'`
        export RESTIC_PASSWORD_COMMAND="echo $KEY"
        echo "Checking repository: $ACCOUNT"
        restic check -r /home/$ACCOUNT
        if [ $? -ne 0 ]; then
                echo "Errors detected"!
        fi
done

# umount vault

/bin/umount /mnt/vault

# close vault

/usr/sbin/cryptsetup close myvault
```

## restic script on gravity

```
S C:\scripts> Get-Content .\restic_backup.bat
restic -r E:\ backup D:\cellulari D:\data D:\guitar D:\immagini D:\Listening D:\software D:\tmrc D:\video --exclude-file C:\scripts\restic_exclude.txt
restic -r E:\ forget --keep-yearly 12 --prune --cleanup-cache
```

```
PS C:\scripts> Get-Content C:\scripts\restic_exclude.txt
D:\tmrc\hacking\Br........
"D:\tmrc\hacking\The .........\labs"
D:\tmrc\hacking\wordlist
```

