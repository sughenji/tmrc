
### wireguard on Windows server

Generate private key:

```
root@kaligra:~# wg genkey
wAoz6b20shdfErHX5M4kxb6b/UjwUzKiKuAhXd2NU3w=
```

Generate public key:

```
root@kaligra:~# echo -n "wAoz6b20shdfErHX5M4kxb6b/UjwUzKiKuAhXd2NU3w=" | wg pubkey
9elkoSVZnhHTBbFf95wIn3EfNfqR4RFqic88GtbcWUs=
```

Very simple configuration file on server:

```
[Interface]
Address = 192.168.143.1/24
Privatekey = wAoz6b20shdfErHX5M4kxb6b/UjwUzKiKuAhXd2NU3w= (private key from above)
ListenPort = 12345
```

Now move on the first client, let's create one (same step as above for private/public keys).

Now let's generate configuration file on the first client:

```
# cat sugovpn.conf 
[Interface]
PrivateKey = aHVleM[CLIENT_PRIVATE_KEY]BxKuWXrRCjGE=
Address = 192.168.143.2/24 <- pick another address in the same lan segment

[Peer]
PublicKey = 9elkoSVZnhHTBbFf95wIn3EfNfqR4RFqic88GtbcWUs= <- this is the public key from SERVER
AllowedIPs = 192.168.143.1/32 <- this says: which ip/net do you want to reach through VPN?
Endpoint = 46.252.144.172:12345 <- public ip address and port of SERVER
PersistentKeepalive = 60
```


Now add this first client to your server configuration:


```
..
..
..
[Peer]
# sugovpn
Publickey = 40WjR2h5[CLIENT_PUBLIC_KEY]Jksdgws=
AllowedIPs = 192.168.143.2/24 <- same Address you wrote on sugovpn.conf file
```

To reload server configuration

```
wg-reload wg0
```

To start client (if config file is in `/etc/wireguard/wg0.conf`):

```
wg-quick up wg0
```

Windows Tips: basically I used this solutions:

https://github.com/micahmo/WgServerforWindowso

everything went smoothly, but I noticed that often the "Nat routing" was disabled.

I wrote this simple script:

```powershell
# Command to check (replace this with your actual command)
$commandOutput = Get-NetNat 

# Check if the output is empty
if (-not $commandOutput) {
    Write-Host "Command returned nothing. Launching another script..."
    new-netnat -name wg_server_nat -InternalIPInterfaceAddressPrefix 10.253.0.1/24
	    
}
```

### wireguard on mikrotik

VPN site-to-site

reference:

https://help.mikrotik.com/docs/display/ROS/WireGuard

On Mikrotik on site 1 (LAN: `192.168.101.0/24`, PUBLIC IP: `188.34.72.4`):

Create interface:

```
/interface/wireguard
add listen-port=13231 name=wireguard1
```

Take note on `public key` of site 1, let's say `SITE1PUBKEY`.

Configure an IP address on interface `wireguard1`, let's say `SITE1WGIP`, eg. `10.0.0.1/24`.

On Mikrotik on site 2 (LAN: `192.168.102./24`, PUBLIC IP: `65.42.43.23`):

```
/interface/wireguard
add listen-port=13231 name=wireguard1
```

Take note on `public key` of site 2, let's say `SITE2PUBKEY`.

Configure an IP address on interface `wireguard1`, let's say `SITE2WGIP`, eg. `10.0.0.2/24`.

On Mikrotik on site 1:

Add peer interface:

N.B.

**You must put in `allowed-address` the remote network, and even the remote peer wireguard IP (`SITE2WGIP`).**

```
/interface/wireguard/peers
add allowed-address=192.168.102.0/24,10.0.0.2/32 endpoint-address=65.42.43.23 endpoint-port=13231 interface=wireguard1 \
public-key="SITE2PUBKEY"
```

Configure a static route to SITE2 remote LAN network:

```
/ip/route
add dst-address=192.168.102.0/24 gateway=wireguard1
```

On Mikrotik on site 2:

Add peer interface:

```
/interface/wireguard/peers
add allowed-address=192.168.101.0/24,10.0.0.1/32 endpoint-address=188.34.72.4 endpoint-port=13231 interface=wireguard1 \
public-key="SITE1PUBKEY"
```

Configure a static route to SITE1 remote LAN network:

```
/ip/route
add dst-address=192.168.101.0/24 gateway=wireguard1
```

### wireguard roadwarrior

On Mikrotik, add a new peer.

Public key is the key you obtain from roadwarrior device.

Preshared key is the psk that you obtain from roadwarrior device, or: `wg genpsk` on Linux).

Allowed Address is the IP address configured on your roadwarrior device (eg. `10.0.0.69/24`)

On roadwarrior device (eg. Android device):

address = `10.0.0.69/24`

Peer:

public key: the public key from Mikrotik endpoint

PSK: see above

Endpoint: Mikrotik's public IP address

AllowedIPs: remote LAN behind Mikrotik (eg. `192.168.88.0/24`)

N.B. to route ALL traffic to wireguard tunnel, simply type in your roadwarrior device:

`AllowedIPs: 0.0.0.0/0`
