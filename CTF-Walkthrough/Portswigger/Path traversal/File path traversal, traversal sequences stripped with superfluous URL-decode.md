
#websecurity #webexploitation 

The application blocks input containing path traversal sequences. It then performs a URL-decode of the input before using it.


`../` questa sequenza viene bloccata..

io la scrivo DIRETTAMENTE in urlencode, tanto poi ci penserà LUI a decodificarla..

intanto facciamo un "happy case"

encodo IO `58.jpg`, che diventa `%35%38%2e%6a%70%67`


![](_attachments/Pasted%20image%2020240903150132.png)

e sembra funzionare :)

![](_attachments/Pasted%20image%2020240903150142.png)



questo ritorna "bad request"

`GET /image?filename=%2f%65%74%63%2f%70%61%73%73%77%64 HTTP/2`

idem questo

`%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64`

soluzione:

https://github.com/frank-leitner/portswigger-websecurity-academy/blob/main/03-directory_traversal/File_path_traversal%2C_traversal_sequences_stripped_with_superfluous_URL-decode/README.md

