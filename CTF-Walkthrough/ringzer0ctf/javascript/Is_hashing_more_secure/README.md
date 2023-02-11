# Is hashing more secure?

https://ringzer0ctf.com/challenges/30

```
// Look's like weak JavaScript auth script :)
	$(".c_submit").click(function(event) {
		event.preventDefault();
		var p = $("#cpass").val();
		if(Sha1.hash(p) == "b89356ff6151527e89c4f3e3d30c8e6586c63962")
```

Found cleartext password with Google :)

BTW:

```
sugo@kali:/opt/tools/SecLists/Passwords$ grep -rl adminz *
bt4-password.txt
Cracked-Hashes/milw0rm-dictionary.txt
darkc0de.txt
Honeypot-Captures/multiplesources-passwords-fabian-fingerle.de.txt
Leaked-Databases/000webhost.txt
Leaked-Databases/honeynet.txt
Leaked-Databases/phpbb-withcount.txt
Leaked-Databases/alleged-gmail-passwords.txt
Leaked-Databases/phpbb.txt
Leaked-Databases/phpbb-cleaned-up.txt
Leaked-Databases/honeynet2.txt
Leaked-Databases/honeynet-withcount.txt
Leaked-Databases/md5decryptor-uk.txt
mssql-passwords-nansh0u-guardicore.txt
xato-net-10-million-passwords.txt
```

