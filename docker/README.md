# disable autostart container

```
docker update --restart=no my-container
```

# portainer

## start & stop stack through API

First, create token for your account through Portainer interface:

![](_attachment/Pasted%20image%2020250509100637.png)

```bash
API_TOKEN="ptr_XXXXXXXXXXXXXXXXXXXXXXXXX"
```

Then, to obtain the stackId from name:

```bash
# I want stackId of "debug-track-demo":
STACKID=$(curl -s -k -H "X-API-Key: $API_TOKEN" https://moby.company.it:9443/api/stacks | jq '.[] | select(.Name=="debug-track-demo") | .Id')
echo $STACKID
```

To stop stack:

```bash
/usr/bin/curl -k -X POST "https://moby.company.it:9443/api/stacks/$STACKID/stop?endpointId=2" -H "X-API-Key: $API_TOKEN"
echo "[-] stack stopped"
```

To start stack:

```bash
/usr/bin/curl -k -X POST "https://moby.micso.it:9443/api/stacks/$STACKID/start?endpointId=2" -H "X-API-Key: $API_TOKEN"
echo "[+] stack started"
```

