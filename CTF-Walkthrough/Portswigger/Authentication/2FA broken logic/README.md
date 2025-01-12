https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic

For this lab, brute force is required :)  
So, since I have no Burpsuite Pro edition, I chose to use Zaproxy.  

# happy case: login as wiener

![](_attachment/Pasted%20image%2020250112200843.png)

![](_attachment/Pasted%20image%2020250112200928.png)

we are asked for the 4-digit PIN, so we check the "email client":

![](_attachment/Pasted%20image%2020250112201014.png)

after putting the right code, we are allowed to access our account page:

https://0a58008a03c3748780b176be00c7009c.web-security-academy.net/my-account?id=wiener


![](_attachment/Pasted%20image%2020250112201128.png)

# try to request a 2FA for another user: carlos

we can modify our previous request to `/login2` with another value for the `verify` parameter:

![](_attachment/Pasted%20image%2020250112201401.png)

instead of `wiener`, we chose `carlos`.

This will *trigger* the generation of another 4-digit code.

# fuzzing the 4 digit code

We can use the builtin Fuzzer tool, but pay attention: we need to use 4 digit values.

So, using "Numberzz" from 1 to 10000 will not work :)

We generate instead a text file with all 4 digit combinations 

```python
sugo@kali:~/Documents/portswigger/2fa-broken-login$ cat generate-pin.py
#!/usr/bin/python3
def generate_pins():
    pins = []
    for i in range(10000):  # I numeri da 0 a 9999
        pins.append(f"{i:04}")  # Formatta ogni numero con zeri iniziali per renderlo a 4 cifre
    return pins

# Stampa tutti i PIN generati
if __name__ == "__main__":
    all_pins = generate_pins()
    for pin in all_pins:
        print(pin)

```

# brute force

Now we can pick our previous POST request to `/login2` and configuring fuzzing.  
Of course, we specify `carlos` as username:  

![](_attachment/Pasted%20image%2020250112201844.png)

![](_attachment/Pasted%20image%2020250112201919.png)

![](_attachment/Pasted%20image%2020250112202025.png)

we observe our request and we look for a `302` response:


![](_attachment/Pasted%20image%2020250112195754.png)

# login as carlos

now we can replace the cookie value (and the username) and get access to our page and solve the lab:  


![](_attachment/Pasted%20image%2020250112195859.png)

![](_attachment/Pasted%20image%2020250112195935.png)