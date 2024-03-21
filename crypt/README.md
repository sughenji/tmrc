# Crypt

- [Symmetric encryption with GPG](#symmetric-encryption-with-gpg)
- [Symmetric encryption with OpenSSL](#symmetric-encryption-with-openssl)
- [Generate private key](#generate-private-key)
- [Generate public key](#generate-public-key)
- [Export GPG public key](#export-gpg-public-key)
- [Export GPG private key](#export-gpg-private-key)
- [Encrypt with public key](#encrypt-with-public-key)
- [Decrypt with private key](#decrypt-with-private-key)
- [Generate Diffie Hellman](#generate-diffie-hellman) 

## Symmetric encryption with gpg

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

## Symmetric encryption with openssl

```
openssl aes-256-cbc -e -in message.txt -out encrypted_message
```

to decrypt:

```
openssl aes-256-cbc -d -in encrypted_message -out original_message.txt
```

## generate private key

```
$ openssl genrsa -out private-key.pem 2048
```

## generate public key

```
$ openssl rsa -in private-key.pem -pubout -out public-key.pem
```

To see details

```
$ openssl rsa -in private-key.pem -text -noout
```

## export gpg public key

```bash
$ gpg --output vstore_pub_key --armor --export asd@domain.it
```

## export gpg private key

```bash
$ gpg --output vstore_private_key --armor --export-secret-key --pinentry-mode=loopback asd@domain.it
Password:
```



## encrypt with public key

```
openssl pkeyutl -encrypt -in plaintext.txt -out ciphertext -inkey public-key.pem -pubin
```

## decrypt with private key

```
openssl pkeyutl -decrypt -in ciphertext -inkey private-key.pem -out decrypted.txt
```

## generate diffie hellman

```
$ openssl dhparam -out dhparams.pem 2048
```

to see details

```
openssl dhparam -in dhparams.pem -text -noout
```

