# Hardening

- disable LLMNR

- disable netbios over TCP/IP

- disable PrintSpoolerService (rif. https://tryhackme.com/room/printnightmarehpzqlp8 - mitigation)


- disable SMBv1

- enable SMB signing?

- Enforce password complexity

- Do not use regular users in Domain Admin group, use dedicated ones (eg. sugo_adm)

- check if you have users with reversible password 

- check if you have user with LM hashes

- disable Always Elevated Installer


