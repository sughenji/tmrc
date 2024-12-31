- [Symmetric encryption with GPG](#symmetric-encryption-with-gpg)
- [Symmetric encryption with OpenSSL](#symmetric-encryption-with-openssl)
- [Generate private key](#generate-private-key)
- [Generate public key](#generate-public-key)
- [Export GPG public key](#export-gpg-public-key)
- [Export GPG private key](#export-gpg-private-key)
- [Import GPG private key](#import-gpg-private-key)
- [Decrypt with GPG private key](#decrypt-with-gpg-private-key)
- [Encrypt with public key](#encrypt-with-public-key)
- [Decrypt with private key](#decrypt-with-private-key)
- [Generate Diffie Hellman](#generate-diffie-hellman) 
- [Create LUKS device](#create-luks-device)
- [SSH](#ssh)

# Symmetric encryption with gpg

To see ciphers:

```
$ gpg --version |grep -A5 Supported
Supported algorithms:
Pubkey: RSA, ?, ?, ELG, DSA
Cipher: IDEA, 3DES, CAST5, BLOWFISH, AES, AES192, AES256, TWOFISH,
        CAMELLIA128, CAMELLIA192, CAMELLIA256
Hash: MD5, SHA1, RIPEMD160, SHA256, SHA384, SHA512, SHA224
Compression: Uncompressed, ZIP, ZLIB, BZIP2
```


```
$ gpg --armor --symmetric --cipher-algo TWOFISH lettera
```

To decrypt:

```
gpg --output original_message.txt --decrypt message.gpg
```

# Symmetric encryption with openssl

```
openssl aes-256-cbc -e -in message.txt -out encrypted_message
```

to decrypt:

```
openssl aes-256-cbc -d -in encrypted_message -out original_message.txt
```

# generate private key

```
$ openssl genrsa -out private-key.pem 2048
```

# generate public key

```
$ openssl rsa -in private-key.pem -pubout -out public-key.pem
```

To see details

```
$ openssl rsa -in private-key.pem -text -noout
```

# export gpg public key

```bash
$ gpg --output vstore_pub_key --armor --export asd@domain.it
```

# export gpg private key

```bash
$ gpg --output vstore_private_key --armor --export-secret-key --pinentry-mode=loopback asd@domain.it
Password:
```

# import gpg private key

```bash
$ gpg --import priv
gpg: key 44F9A09421EDDFDD: public key "Vault Backup (Vault Backup) <asd@domain.it>" imported
gpg: key 44F9A09421EDDFDD: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
```

In case of "permission denied" error:

```
gpg --pinentry-mode=loopback --import priv
```

# decrypt with gpg private key

```bash
$ gpg --output dump.sql --decrypt vdb.20240321152725.gpg
gpg: encrypted with 4096-bit RSA key, ID 3A9CAB6E524B9A77, created 2021-07-01
      "Vault Backup (Vault Backup) <asd@domain.it>"
```

In case of "permission denied" error:

```
gpg --pinentry-mode=loopback --output dump.sql --decrypt vdb.20240402024000.gp
```

# encrypt with public key

```
openssl pkeyutl -encrypt -in plaintext.txt -out ciphertext -inkey public-key.pem -pubin
```

# decrypt with private key

```
openssl pkeyutl -decrypt -in ciphertext -inkey private-key.pem -out decrypted.txt
```

# generate diffie hellman

```
$ openssl dhparam -out dhparams.pem 2048
```

to see details

```
openssl dhparam -in dhparams.pem -text -noout
```


# create luks device

Eg. on Debian

```bash
apt install cryptsetup
dd if=/dev/urandom of=./vaultfile bs=1M count=50
cryptsetup --verify-passphrase luksFormat ./vaultfile
cryptsetup open --type luks ./vaultfile myvault
mkfs.ext4 -L myvault /dev/mapper/myvault
mkdir /mnt/vault
mount /dev/mapper/myvault /mnt/vault/
```

to close device:


```bash
/bin/umount /mnt/vault
/usr/sbin/cryptsetup close myvault
```

# ssh

which version on remote host?

```bash
$ ssh -Q protocol-version server.company.org
2
```

which host key algorithms on remote host?

```bash
$ nmap --script=ssh-hostkey.nse -p 22 server.company.org
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-27 17:47 CET
Nmap scan report for server.company.org
Host is up (0.00049s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   1024 a0:d2:e2:92:2f:49:b7:7e:b0:81:8b:3c:e0:55:0c:19 (DSA)
|_  2048 4b:10:eb:5b:bc:61:1e:96:bd:14:93:e9:dd:85:6b:ef (RSA)

Nmap done: 1 IP address (1 host up) scanned in 30.41 seconds
```