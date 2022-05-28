# Networ Traffic Analysis

## Eternalblue

Consider PCAP from Snort Container:

https://hub.docker.com/r/ciscotalos/snort3

path: /home/snorty/examples/intro/lab2/eternalblue.pcap

```
snorty@snort3:~$ snort -q  --talos -r examples/intro/lab2/eternalblue.pcap --rule-path ~/snort3/etc/rules/

##### eternalblue.pcap #####
        [1:41978:5] OS-WINDOWS Microsoft Windows SMB remote code execution attempt (alerts: 27)
        [1:42944:2] OS-WINDOWS Microsoft Windows SMB remote code execution attempt (alerts: 3)
#####
```

Let's check rules:

```
snorty@snort3:~$ grep -rl "OS-WINDOWS Microsoft Windows SMB remote code execution attempt" snort3/etc/rules/*
snort3/etc/rules/snort3-community.rules
```

```
alert tcp any any -> $HOME_NET 445 ( msg:"OS-WINDOWS Microsoft Windows SMB remote code execution attempt"; flow:to_server,established; content:"|FF|SMB3|00 00 00 00|",depth 9,offset 4; byte_extract:2,26,TotalDataCount,relative,little; byte_test:2,>,TotalDataCount,20,relative,little; metadata:policy balanced-ips drop,policy connectivity-ips drop,policy max-detect-ips drop,policy security-ips drop,ruleset community; service:netbios-ssn; reference:cve,2017-0144; reference:cve,2017-0146; reference:url,blog.talosintelligence.com/2017/05/wannacry.html; reference:url,isc.sans.edu/forums/diary/ETERNALBLUE+Possible+Window+SMB+Buffer+Overflow+0Day/22304/; reference:url,technet.microsoft.com/en-us/security/bulletin/MS17-010; classtype:attempted-admin; sid:41978; rev:5; )
alert tcp any any -> $HOME_NET 445 ( msg:"OS-WINDOWS Microsoft Windows SMB remote code execution attempt"; flow:to_server,established; content:"|FF|SMB|A0 00 00 00 00|",depth 9,offset 4; content:"|01 00 00 00 00|",within 5,distance 59; byte_test:4,>,0x8150,-33,relative,little; metadata:policy balanced-ips drop,policy connectivity-ips drop,policy max-detect-ips drop,policy security-ips drop,ruleset community; service:netbios-ssn; reference:cve,2017-0144; reference:cve,2017-0146; reference:url,isc.sans.edu/forums/diary/ETERNALBLUE+Possible+Window+SMB+Buffer+Overflow+0Day/22304/; reference:url,technet.microsoft.com/en-us/security/bulletin/MS17-010; classtype:attempted-admin; sid:42944; rev:2; )
```

Pattern: `|FF|SMB3|00 00 00 00|`

Hex: `FF 53 4D 42 33 00 00 00 00`

![filter1](https://user-images.githubusercontent.com/42389836/163867724-1604691d-4bff-46b8-a6df-f76241ee814a.JPG)


![filter2](https://user-images.githubusercontent.com/42389836/163867765-529c8bf4-6a7e-4bca-86ea-598cb189d7b0.JPG)

## Emotet

https://feodotracker.abuse.ch/browse/emotet/
