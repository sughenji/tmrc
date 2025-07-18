```table-of-contents
```


## VLAN vs VXLAN

Tramite le VXLAN è possibile estendere i confini di una rete L2 attraverso una rete sottostante (L3) definita **underlay**.

VLAN (field: 12 bit) è possibile creare circa 4000 VLAN

VXLAN (field: 24 bit) se ne possono creare più di 16 milioni

## Underlay vs Overlay

### Underlay

Rete fisica **ruotata** che collega tra loro leaf e spine.

Protocollo utilizzato per assicurare la raggiungibilità di tutti i nodi (leaf/spine): OSPF.

### Overlay

Rete virtuale costruita "sopra" la rete underlay.

Protocollo utilizzato: BGP-EPVN

## VTEP

Su ogni switch leaf è creato un tunnel VTEP che mette in collegamento i leaf tra loro:

```
# leaf1
interface loopback2
  description VTEP Loopback
  ip address 10.254.0.129/32
  ip router ospf UNDERLAY area 0.0.0.0
  ip pim sparse-mode
# leaf 2
interface loopback2
  description VTEP Loopback
  ip address 10.254.0.130/32
  ip router ospf UNDERLAY area 0.0.0.0
  ip pim sparse-mode
..
..
```

Sono i tunnel VTEP ad incapsulare/deincapsulare il traffico (tramite meccanismo "MAC-in-UDP")

## BUM traffic

Broadcast, Unknown unicast, Multicast

Come gestiamo questi traffici? vedi qui sotto:

## ARP suppression vs head-and-replication

Noi usiamo attualmente un "mix", ma la scelta definitiva dovrebbe essere head-and-replication, ossia tramite BGP

```
interface nve1
  no shutdown
  host-reachability protocol bgp
  source-interface loopback2
  member vni 10004
    mcast-group 239.0.0.4
  member vni 10007
    ingress-replication protocol bgp
  member vni 10011
    mcast-group 239.0.0.11
  member vni 10012
    ingress-replication protocol bgp
  member vni 10013
    ingress-replication protocol bgp
  member vni 10014
    ingress-replication protocol bgp
..
..
..
..
```

## NVE

Stato dell'interfaccia:

```
leaf1# sh nve inte
interface   internal    
leaf1# sh nve interface 
Interface: nve1, State: Up, encapsulation: VXLAN
 VPC Capability: VPC-VIP-Only [not-notified]
 Local Router MAC: 700f.6af1.eb19
 Host Learning Mode: Control-Plane
 Source-Interface: loopback2 (primary: 10.254.0.129, secondary: 0.0.0.0)
```

Nota che l'address learning è configurato come `Control-Plane` (non `Data-Plane`)

```
leaf2# show run interface nve1

!Command: show running-config interface nve1
!Running configuration last done at: Mon Sep 26 14:45:03 2022
!Time: Thu Oct  6 15:21:46 2022

version 9.3(8) Bios:version 07.69 

interface nve1
  no shutdown
  host-reachability protocol bgp
  source-interface loopback2
  member vni 10007
    mcast-group 239.0.0.7
  member vni 10011
    mcast-group 239.0.0.11
  member vni 10015
    mcast-group 239.0.0.15
..
..

leaf2# 
```

```
leaf1# show nve peers 
Interface Peer-IP                                 State LearnType Uptime   Router-Mac       
--------- --------------------------------------  ----- --------- -------- -----------------
nve1      10.254.0.130                            Up    CP        22w2d    n/a              
nve1      10.254.0.131                            Up    CP        22w1d    n/a              
nve1      10.254.0.134                            Up    CP        5w4d     n/a              

leaf1# 
```

```
leaf2# show nve peers 
Interface Peer-IP                                 State LearnType Uptime   Router-Mac       
--------- --------------------------------------  ----- --------- -------- -----------------
nve1      10.254.0.129                            Up    CP        22w2d    n/a              
nve1      10.254.0.131                            Up    CP        22w1d    n/a              
nve1      10.254.0.134                            Up    CP        5w4d     n/a    
```

Importante! **you will not see any output for this until traffic is initiated from both sides of the overlay**

## VNI

Vxlan Network Identifier, sostituisce il VLAN tag per identificare i vari segmenti di rete

Ne esiste uno per ogni broadcast domain, in pratica uno per ogni VLAN.

Match tra VNI e multicast-group:

```
leaf1# show nve vni
Codes: CP - Control Plane        DP - Data Plane          
       UC - Unconfigured         SA - Suppress ARP        
       SU - Suppress Unknown Unicast 
       Xconn - Crossconnect      
       MS-IR - Multisite Ingress Replication
 
Interface VNI      Multicast-group   State Mode Type [BD/VRF]      Flags
--------- -------- ----------------- ----- ---- ------------------ -----
nve1      10007    239.0.0.7         Up    CP   L2 [7]                  
nve1      10011    239.0.0.11        Up    CP   L2 [11]                 
nve1      10015    239.0.0.15        Up    CP   L2 [15]                 
..
..
```

match tra VLAN ID e VNI:

```
leaf2# show nve internal platform interface detail 
Printing details of all NVE Interfaces
|======|=========================|===============|===============|
|Intf  |State                    |PriIP          |SecIP          |
|======|=========================|===============|===============|
|nve1  |UP                       |10.254.0.130   |0.0.0.0        |
|======|=========================|===============|===============|

SW_BD/VNIs of interface nve1:
================================================
|======|======|=========================|======|====|======|========
|Sw BD |Vni   |State                    |Intf  |Type|Vrf-ID|Notified
|======|======|=========================|======|====|======|========
|7     |10007 |NONE                     |nve1  |CP  |0     |No      
|11    |10011 |NONE                     |nve1  |CP  |0     |No      
|15    |10015 |NONE                     |nve1  |CP  |0     |No      
|18    |10018 |NONE                     |nve1  |CP  |0     |No      
|19    |10019 |NONE                     |nve1  |CP  |0     |No      
|20    |10020 |NONE                     |nve1  |CP  |0     |No      
|35    |10035 |NONE                     |nve1  |CP  |0     |No      
|40    |10040 |NONE                     |nve1  |CP  |0     |No      
|69    |10069 |NONE                     |nve1  |CP  |0     |No      
|76    |10076 |NONE                     |nve1  |CP  |0     |No      
|77    |10077 |NONE                     |nve1  |CP  |0     |No      
|82    |10082 |NONE                     |nve1  |CP  |0     |No      
|99    |10099 |NONE                     |nve1  |CP  |0     |No      
|126   |10126 |NONE                     |nve1  |CP  |0     |No      
|201   |10201 |NONE                     |nve1  |CP  |0     |No      
|250   |10250 |NONE                     |nve1  |CP  |0     |No      
|252   |10252 |NONE                     |nve1  |CP  |0     |No      
|682   |10682 |NONE                     |nve1  |CP  |0     |No      
|======|======|=========================|======|====|======|========

Peers of interface nve1:
============================================
no peers
```

## EVPN Multihoming

Questa funzionalità è utile qualora si voglia dare ridondanza ad uno switch "normale", collegandolo ad esempio a 2 leaf.

In pratica, 2 leaf vengono configurati ciascuno con un VPC con una sola porta come membro.

Sembra inoltre necessario abilitare l'MST sui leaf, con i seguenti comandi:

```
# leaf2
spanning-tree mode mst

spanning-tree domain enable
spanning-tree mst 0-1 priority 8192
spanning-tree mst configuration
  name VXLAN-Fabric
  instance 1 vlan 1-4094
```

```
# leaf3
spanning-tree mode mst

spanning-tree domain enable
spanning-tree mst 0-1 priority 8192
spanning-tree mst configuration
  name VXLAN-Fabric
  instance 1 vlan 1-4094
```

abilitare a livello globale **Ethernet Segment Identifier** (esi):

```
evpn esi multihoming
```

Configurazione dei portchannel sui leaf:

```
# leaf2
interface port-channel10
  description vs swpoe-admins
  switchport mode trunk
  switchport trunk allowed vlan 20,82,250,682
  ethernet-segment 2
    system-mac 0200.0000.000a

# leaf3
interface port-channel10
  description vs swpoe-admins
  switchport mode trunk
  switchport trunk allowed vlan 20,82,250,682
  ethernet-segment 2
    system-mac 0200.0000.000a
```

Comandi da impartire sui leaf sulle porte verso lo switch "normale":

Sulle porte verso gli spine:

```
interface Ethernet1/53
  description Link Spine1
  no switchport
  evpn multihoming core-tracking
```

Lo switch "normale" va configurato invece con un regolare port-channel.

## Aggiunta di un nuovo leaf

Ricordarsi di configurare, sui 2 spine, le sessioni BGP :)

```
router bgp 65001
..
..
neighbor 10.254.0.72
    inherit peer RR-CLIENT
    description *** Leaf-7 ***
```

## Troubleshooting/verifica

### Stato dell'interfaccia nve

```
leaf1# sh nve interface 
Interface: nve1, State: Up, encapsulation: VXLAN
 VPC Capability: VPC-VIP-Only [not-notified]
 Local Router MAC: 700f.6af1.eb19
 Host Learning Mode: Control-Plane
 Source-Interface: loopback2 (primary: 10.254.0.129, secondary: 0.0.0.0)
```

### Verifica mapping tra VNI e multicast group

```
leaf1# show nve vni
Codes: CP - Control Plane        DP - Data Plane          
       UC - Unconfigured         SA - Suppress ARP        
       SU - Suppress Unknown Unicast 
       Xconn - Crossconnect      
       MS-IR - Multisite Ingress Replication
 
Interface VNI      Multicast-group   State Mode Type [BD/VRF]      Flags
--------- -------- ----------------- ----- ---- ------------------ -----
nve1      10004    239.0.0.4         Up    CP   L2 [4]                  
nve1      10007    UnicastBGP        Up    CP   L2 [7]                  
nve1      10011    239.0.0.11        Up    CP   L2 [11]                 
nve1      10012    UnicastBGP        Up    CP   L2 [12]                 
nve1      10013    UnicastBGP        Up    CP   L2 [13]                 
nve1      10014    UnicastBGP        Up    CP   L2 [14]                 
nve1      10015    239.0.0.15        Up    CP   L2 [15]                 
nve1      10020    239.0.0.20        Up    CP   L2 [20]                 
nve1      10028    239.0.0.28        Up    CP   L2 [28]                 
nve1      10035    UnicastBGP        Up    CP   L2 [35]       
..
..
..
..
.. 
```

### Verifica mapping tra VLAN e VNI

```
leaf1# sh vxlan
Vlan            VN-Segment
====            ==========
4               10004
7               10007
11              10011
..
..
582             10582
```

### Stato dei VTEPs sin qui discoverati

```
leaf1# sh nve peers 
Interface Peer-IP                                 State LearnType Uptime   Router-Mac       
--------- --------------------------------------  ----- --------- -------- -----------------
nve1      10.254.0.130                            Up    CP        2y21w    n/a              
nve1      10.254.0.131                            Up    CP        2y21w    n/a              
nve1      10.254.0.134                            Up    CP        2y5w     n/a              
nve1      10.254.254.2                            Up    CP        1y36w    n/a  
```

### Adiacenza OSPF degli spine con i leaf:

```
leaf1# sh ip ospf neighbors 
 OSPF Process ID UNDERLAY VRF default
 Total number of neighbors: 2
 Neighbor ID     Pri State            Up Time  Address         Interface
 spine1            1 FULL/ -          22w2d    10.254.1.1      Eth1/53 
 spine2            1 FULL/ -          22w2d    10.254.1.5      Eth1/54 

leaf2# sh ip ospf neighbors 
 OSPF Process ID UNDERLAY VRF default
 Total number of neighbors: 2
 Neighbor ID     Pri State            Up Time  Address         Interface
 spine1            1 FULL/ -          22w2d    10.254.1.9      Eth1/53 
 spine2            1 FULL/ -          22w2d    10.254.1.13     Eth1/54 
..
..
```

### Adiacenza BGP tra leaf e spine:

```
leaf1# show bgp l2vpn evpn summary 
BGP summary information for VRF default, address family L2VPN EVPN
BGP router identifier 10.254.0.129, local AS number 65001
BGP table version is 475294, L2VPN EVPN config peers 2, capable peers 2
930 network entries and 1439 paths using 242160 bytes of memory
BGP attribute entries [293/50396], BGP AS path entries [0/0]
BGP community entries [0/0], BGP clusterlist entries [6/24]

Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.254.0.1      4 65001  273776  210322   475294    0    0    22w2d 382       
10.254.0.2      4 65001  273755  210321   475294    0    0    22w2d 382       
```

Se il numero dei prefissi è ZERO, abbiamo problemi :)



### Mac address rilevati su un particolare VNI (es. 10035):

```
leaf1# show bgp l2vpn evpn  vni-id 10035
BGP routing table information for VRF default, address family L2VPN EVPN
BGP table version is 475356, Local Router ID is 10.254.0.129
Status: s-suppressed, x-deleted, S-stale, d-dampened, h-history, *-valid, >-best
Path type: i-internal, e-external, c-confed, l-local, a-aggregate, r-redist, I-injected
Origin codes: i - IGP, e - EGP, ? - incomplete, | - multipath, & - backup, 2 - best2

   Network            Next Hop            Metric     LocPrf     Weight Path
Route Distinguisher: 10.254.0.129:32802    (L2VNI 10035)
*>l[2]:[0]:[0]:[48]:[0010.f35c.f956]:[0]:[0.0.0.0]/216
                      10.254.0.129                      100      32768 i
*>l[2]:[0]:[0]:[48]:[0010.f35c.faea]:[0]:[0.0.0.0]/216
                      10.254.0.129                      100      32768 i
*>l[2]:[0]:[0]:[48]:[0855.317b.0d24]:[0]:[0.0.0.0]/216
                      10.254.0.129                      100      32768 i
*>l[2]:[0]:[0]:[48]:[488f.5aa6.4ad4]:[0]:[0.0.0.0]/216
                      10.254.0.129                      100      32768 i
*>l[2]:[0]:[0]:[48]:[5803.fb71.653f]:[0]:[0.0.0.0]/216
                      10.254.0.129                      100      32768 i
*>l[2]:[0]:[0]:[48]:[5803.fb71.6646]:[0]:[0.0.0.0]/216
                      10.254.0.129                      100      32768 i
*>l[2]:[0]:[0]:[48]:[9800.0000.1301]:[0]:[0.0.0.0]/216
                      10.254.0.129                      100      32768 i
*>l[2]:[0]:[0]:[48]:[bcba.c24a.6556]:[0]:[0.0.0.0]/216
                      10.254.0.129                      100      32768 i
*>l[2]:[0]:[0]:[48]:[bcba.c24a.6575]:[0]:[0.0.0.0]/216
                      10.254.0.129                      100      32768 i
*>l[2]:[0]:[0]:[48]:[ecc8.9c1d.429b]:[0]:[0.0.0.0]/216
                      10.254.0.129                      100      32768 i
*>l[2]:[0]:[0]:[48]:[ecc8.9c1d.42e2]:[0]:[0.0.0.0]/216
                      10.254.0.129                      100      32768 i
*>i[2]:[0]:[0]:[48]:[ecc8.9c81.e279]:[0]:[0.0.0.0]/216
                      10.254.0.130                      100          0 i
*>l[2]:[0]:[0]:[48]:[f84d.fca1.822b]:[0]:[0.0.0.0]/216
                      10.254.0.129                      100      32768 i
```

Oppure su una VLAN specifica:

```
leafto1# show l2route evpn mac evi 250

Flags -(Rmac):Router MAC (Stt):Static (L):Local (R):Remote (V):vPC link 
(Dup):Duplicate (Spl):Split (Rcv):Recv (AD):Auto-Delete (D):Del Pending
(S):Stale (C):Clear, (Ps):Peer Sync (O):Re-Originated (Nho):NH-Override
(Pf):Permanently-Frozen, (Orp): Orphan

Topology    Mac Address    Prod   Flags         Seq No     Next-Hops                              
----------- -------------- ------ ------------- ---------- ---------------------------------------
250         000c.29ae.55cf BGP    Rcv           0          10.254.0.129 (Label: 10250)            
250         0010.749d.685b BGP    Rcv           0          10.254.0.129 (Label: 10250)            
250         0010.f35c.f956 BGP    Rcv           0          10.254.0.129 (Label: 10250)            
250         0010.f35c.faea BGP    Rcv           0          10.254.0.129 (Label: 10250)            
250         0023.ac79.0b41 BGP    Rcv           0          10.254.0.130 (Label: 10250)            
250         0026.b97c.f8d2 BGP    Rcv           0          10.254.0.129 (Label: 10250)            
250         0050.5652.6901 BGP    Rcv           0          10.254.0.129 (Label: 10250)            
250         0050.565a.2cb7 BGP    Rcv           0          10.254.0.129 (Label: 10250)            
250         0050.56a6.25d2 BGP    Rcv           0          10.254.0.129 (Label: 10250)            
250         0050.56a6.6cc2 BGP    Rcv           0          10.254.0.129 (Label: 10250)            
250         0050.56a6.98c8 BGP    Rcv           0          10.254.0.129 (Label: 10250)            
250         0050.56a6.c880 BGP    Rcv           0          10.254.0.129 (Label: 10250)            
250         005d.73b9.5d94 BGP    Rcv           0          10.254.0.130 (Label: 10250)            
250         005d.73b9.6208 BGP    Rcv           0          10.254.0.130 (Label: 10250)           
```

Come sopra, ma per tutti i VNI:

```
leaf1# show l2route evpn mac all

Flags -(Rmac):Router MAC (Stt):Static (L):Local (R):Remote (V):vPC link 
(Dup):Duplicate (Spl):Split (Rcv):Recv (AD):Auto-Delete (D):Del Pending
(S):Stale (C):Clear, (Ps):Peer Sync (O):Re-Originated (Nho):NH-Override
(Pf):Permanently-Frozen, (Orp): Orphan

Topology    Mac Address    Prod   Flags         Seq No     Next-Hops                              
----------- -------------- ------ ------------- ---------- ---------------------------------------
7           000c.291f.6ef7 BGP    Rcv           0          10.254.0.131 (Label: 10007)            
7           000c.29a7.8f41 BGP    Rcv           0          10.254.0.131 (Label: 10007)            
7           0050.569b.0065 Local  L,            0          Po1                                    
7           00e0.ed32.35cd Local  L,            0          Po1                                    
7           00e0.ed57.b8b1 Local  L,            0          Po1                                    
7           64d1.543c.02a6 Local  L,            0          Po1                                    
7           9800.0000.1401 Local  L,            0          Po1                                    
7           c665.94c5.0605 BGP    Rcv           0          10.254.0.131 (Label: 10007)            
7           c665.983f.6506 BGP    Rcv           0          10.254.0.131 (Label: 10007)            
11          000a.e481.ba0d BGP    Rcv           0          10.254.0.130 (Label: 10011)            
11          0010.f35c.f956 Local  L,            0          Po1                                    
11          0010.f35c.faea Local  L,            0          Po1                                    
11          0050.5652.6901 Local  L,            0          Po1                                    
11          0050.565a.2cb7 Local  L,            0          Po1                                    
11          0050.569b.0019 Local  L,            0          Po1                                    
11          0050.569b.001b Local  L,            0          Po1                                    
..
..
..
```

### Esplorare il database BGP

```
leaf1# sh bgp l2vpn evpn 
BGP routing table information for VRF default, address family L2VPN EVPN
BGP table version is 7866121, Local Router ID is 10.254.0.129
Status: s-suppressed, x-deleted, S-stale, d-dampened, h-history, *-valid, >-best
Path type: i-internal, e-external, c-confed, l-local, a-aggregate, r-redist, I-injected
Origin codes: i - IGP, e - EGP, ? - incomplete, | - multipath, & - backup, 2 - best2

   Network            Next Hop            Metric     LocPrf     Weight Path
Route Distinguisher: 10.254.0.129:32774    (L2VNI 10007)
*>i[2]:[0]:[0]:[48]:[000c.299b.677f]:[0]:[0.0.0.0]/216
                      10.254.0.131                      100          0 i
*>i[2]:[0]:[0]:[48]:[000c.29d4.5efd]:[0]:[0.0.0.0]/216
                      10.254.0.131                      100          0 i
*>i[2]:[0]:[0]:[48]:[0010.f3ae.370d]:[0]:[0.0.0.0]/216
                      10.254.254.2                      100          0 i
* i                   10.254.254.2                      100          0 i
* i[2]:[0]:[0]:[48]:[0050.561c.d65d]:[0]:[0.0.0.0]/216
                      10.254.254.2                      100          0 i
*>i                   10.254.254.2                      100          0 i
* i[2]:[0]:[0]:[48]:[0050.569b.0065]:[0]:[0.0.0.0]/216
                      10.254.254.2                      100          0 i
*>i                   10.254.254.2                      100          0 i
*>i[2]:[0]:[0]:[48]:[0050.569c.6b9b]:[0]:[0.0.0.0]/216
                      10.254.254.2                      100          0 i
* i                   10.254.254.2                      100          0 i
*>i[2]:[0]:[0]:[48]:[1200.0000.aa01]:[0]:[0.0.0.0]/216
                      10.254.254.2                      100          0 i
* i                   10.254.254.2                      100          0 i
..
..
..
..
```

### Cercare un mac address

```
leaf1# show l2route evpn mac all | i 488f.5ad1.cb61
82          488f.5ad1.cb61 Local  L,            0          Eth1/4      
```

Altro comando per cercare un MAC address (in questo caso il device è sulla porta `eth1/4`):

```
leaf1# show mac address-table vlan 82 | i 488f.5ad1.cb61
*   82     488f.5ad1.cb61   dynamic  0         F      F    Eth1/4
```

Se invece esce "nveX" e non un'interfaccia, vuol dire che quel device non è collegato fisicamente su questo switch, vedi esempio seguente:

```
leaf1# show mac address-table vlan 82 | i afcd
C   82     58c1.7a04.afcd   dynamic  0         F      F    nve1(10.254.0.134)
```

### Cache arp suppression

...Cosa che NON ci interessa visto che NON usiamo arp-suppression :)

```
leaf1# sh ip arp suppression-cache detail 

Flags: + - Adjacencies synced via CFSoE
       L - Local Adjacency
       R - Remote Adjacency
       L2 - Learnt over L2 interface
       PS - Added via L2RIB, Peer Sync
       RO - Dervied from L2RIB Peer Sync Entry

Ip Address      Age      Mac Address    Vlan Physical-ifindex    Flags    Remote Vtep Addrs
```

### Verificare se un leaf sta annunciando un mac address agli spine

Es. su `leaf1`, sulla porta Eth1/5 c'è l'apparato `r-smsstation` con mac address `74:4D:28:AE:DA:DB`

Vediamo se `leaf1` lo sta annunciando a `spine1` e `spine2`:

```
leaf1# show bgp l2vpn evpn nei 10.254.0.1 advertised-routes | i dadb
*>l[2]:[0]:[0]:[48]:[744d.28ae.dadb]:[0]:[0.0.0.0]/216

leaf1# show bgp l2vpn evpn nei 10.254.0.2 advertised-routes | i dadb
*>l[2]:[0]:[0]:[48]:[744d.28ae.dadb]:[0]:[0.0.0.0]/216
```

### Verificare su un leaf se sta RICEVENDO un mac address da un altro leaf

Nell'esempio sottostante, sto cercando un mac-address che contiene `050c`

```
leaf1# show bgp l2vpn evpn nei 10.254.0.1 routes  | i 050c
*>i[2]:[0]:[0]:[48]:[789a.1816.050c]:[0]:[0.0.0.0]/216
*>i[2]:[0]:[0]:[48]:[789a.1816.050c]:[0]:[0.0.0.0]/216
```


## Link Utili

[https://nwktimes.blogspot.com/2019/05/evpn-esi-multihoming-part-i-evpn.html](https://nwktimes.blogspot.com/2019/05/evpn-esi-multihoming-part-i-evpn.html)

[https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/118978-config-vxlan-00.html](https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/118978-config-vxlan-00.html)

[https://github.com/manolab/vxlanpoc](https://github.com/manolab/vxlanpoc)

[https://www.packetcoders.io/how](https://www.packetcoders.io/how-to-build-a-nxos-9000v-based-evpn-vxlan-fabric/)