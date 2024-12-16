# LAB

https://github.com/WazeHell/vulnerable-AD

Got first-names list here:

https://raw.githubusercontent.com/devthejo/first-names-list/master/first-names.txt

We have about 14K first names:

```
PS C:\Users\local_admin\Documents> Get-Content .\first-names.txt | Measure-Object


Count    : 13953
Average  :
Sum      :
Maximum  :
Minimum  :
Property :
```

Get random item:

```
PS C:\Users\local_admin\Documents> Get-Random (get-content .\first-names.txt)
antoni
```

Capitalize first letter:

```
$name = get-random (get-content .\first-names.txt)
(get-culture).textinfo.totitlecase($name)
Anagel
```



