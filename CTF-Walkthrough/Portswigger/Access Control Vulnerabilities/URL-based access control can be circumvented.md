
https://github.com/frank-leitner/portswigger-websecurity-academy/tree/main/07_access_control/URL-based_access_control_can_be_circumvented

non ci sarei arrivato :)

bisogna editare la richiesta, trasformandola in una semplice `GET /` e inserendo l'header `X-Original-URL: /admin`

per farlo, la si intercetta e la si edita qui:

![](_attachments/Pasted%20image%2020240906134336.png)


