```table-of-contents
```
# net logon type 2

per cercare un utente specifico (in questo caso: `e.nemecsek`)

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[
        EventData[Data[@Name='LogonType']='2']
        and
        EventData[Data[@Name='TargetUserName']='e.nemecsek']
        and
        System[(EventID='4624')]
      ] 
    </Select>
  </Query>
</QueryList>
```

![](_attachment/Pasted%20image%2020250703113332.png)

