#web #webexploitation #webpenetrationtest #zaproxy

Date: 2025/01/12

https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic

For this lab, is required to use brute-force.  
Since we don't have Burpsuite Pro edition, and the `Intruder` would be very slow, we chose to use `Zaproxy` (https://www.zaproxy.org/).    

# happy case: login as wiener

![](_attachment/Pasted%20image%2020250112200843.png)

![](_attachment/Pasted%20image%2020250112200928.png)

We are asked for the 4-digit PIN, so we check the "email client":

![](_attachment/Pasted%20image%2020250113102812.png)

![](_attachment/Pasted%20image%2020250113103338.png)

after putting the right code, we are allowed to access our account page:

https://0a58008a03c3748780b176be00c7009c.web-security-academy.net/my-account?id=wiener


![](_attachment/Pasted%20image%2020250112201128.png)

# try to request a 2FA for another user: carlos

in the `History` menu, we can search for our previous GET request to `/login2`

![](_attachment/Pasted%20image%2020250113103542.png)

we can right-click and chose "Open in Requester tab":

![](_attachment/Pasted%20image%2020250113103725.png)

We can replace the `verify` parameter and replace `wiener` with `carlos`:

![](_attachment/Pasted%20image%2020250113104456.png)

This will *trigger* the generation of another 4-digit code.

# "half" login with wiener

now we access with `wiener:peter` but instead of putting the right PIN, we insert a wrong one.  
Now we search this `POST` request to `/login2` in our history and modify it with the "Fuzz" function:

![](_attachment/Pasted%20image%2020250113105134.png)
# fuzzing the 4 digit code

We can use the builtin Fuzzer tool, but pay attention: we need to use 4 digit values: using "Numberzz" from 1 to 9999 will not work (eg: we need to put `0001` and not `1`).  

We can use the `4-digits-0000-9999.txt` file from Seclist repository:

https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/4-digits-0000-9999.txt

![](_attachment/Pasted%20image%2020250113105638.png)



We need to remember to click on "Edit" button and change username (`carlos`):

![](_attachment/Pasted%20image%2020250113110227.png)

![](_attachment/Pasted%20image%2020250113110316.png)

Now we can observe our requests:  

![](_attachment/Pasted%20image%2020250113111350.png)

..and look for `302` response:  

![](_attachment/Pasted%20image%2020250113113428.png)

Now we need to look a `Response` tab of our `302` request and copy the `session` cookie value:  

![](_attachment/Pasted%20image%2020250113113803.png)


# login as carlos

now we can replace the cookie value (and the username) and get access to our page (`/my-account`) and solve the lab:  


![](_attachment/Pasted%20image%2020250112195859.png)

![](_attachment/Pasted%20image%2020250112195935.png)