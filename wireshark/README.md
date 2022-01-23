# Wireshark cheat sheet

- list interfaces

```
C:\Users\sugo>dumpcap -D
1. \Device\NPF_{771AE0CD-82C9-418D-85F9-C179AA3A2AAB} (Connessione alla rete locale (LAN)* 8)
2. \Device\NPF_{EFCC04D4-BCD4-4B23-BFAE-BA9E4AEE9F9C} (Connessione alla rete locale (LAN)* 7)
3. \Device\NPF_{5E1BA02D-9D6E-4E95-99A5-BFBE4DD7DEB4} (Connessione alla rete locale (LAN)* 6)
4. \Device\NPF_{D44A80DE-25DD-4888-9101-7D94296B8954} (VirtualBox Host-Only Network)
5. \Device\NPF_{974BD271-CC54-456C-8A14-661AD51E3F4F} (Ethernet)
6. \Device\NPF_Loopback (Adapter for loopback traffic capture)
7. \Device\NPF_{B9DC513E-DDB5-4956-82F7-2822A5F69349} (Ethernet 2)
8. \Device\NPF_{BD559BFB-A75F-41DA-BE84-DC44533A7B34} (Connessione alla rete locale (LAN))
```

- start collecting traffic in some folder, with some ring buffer of specified size:

```
C:\Users\sugo>dumpcap -i 5 -w d:\wireshark_capture\test.pcapng -b filesize:500000 -b files:10
```
