
## extract dns query

```bash
$ tshark -r file.pcap -Y "dns and udp.dstport==53" -T fields -e ip.src -e dns.qry.name |head
```

## extract only data from ICMP echo request packets

```bash
$ tshark -r esercitazione_20230529.pcapng -Y "icmp.type==8" -T fields -e data
```

### export objects in directory

```bash
$ tshark -r file.pcap --export-objects http,objects
```


