- [logoff user](#logoff-user)
- [change ACL](#change-acl)
- [remove ACL](#remove-acl)
- [display ACL](#display-acl)
- [show static nat mapping](#show-static-nat-mapping)
- [search user from ip](#search-user-from-ip)
- [show policy on interface](#show-policy-on-interface)
- [show interface errors](#show-interface-errors)

# logoff user

```
<c2-huawei>sy
Enter system view, return user view with return command.
[~c2-huawei]aaa
[~c2-huawei-aaa]cut access-user username w0077616@realm.biz all
Info:Totally,1 user has been cut off.
[~c2-huawei-aaa]
```

# change ACL

```
<c2-huawei>system-view 
Enter system view, return user view with return command.
[~c2-huawei]acl 2000
[~c2-huawei-acl4-basic-2000]rule 7 permit vpn-instance-any source 192.168.84.112 0.0.0.15
[*c2-huawei-acl4-basic-2000]
Warning: Uncommitted configurations found, commit them before exiting? [Y(yes)/N(no)/C(cancel)]:y
<c2-huawei>
```

# remove acl

```
[~c1-huawei-acl4-basic-2000]undo ru
[~c1-huawei-acl4-basic-2000]undo rule 7
[*c1-huawei-acl4-basic-2000]
Warning: Uncommitted configurations found, commit them before exiting? [Y(yes)/N(no)/C(cancel)]:y
```

# show static nat mapping

```
display nat static-mapping 1 mapping
```

# search user from ip

```
<c2-huawei>display access-user ip-address 172.16.28.143
  -------------------------------------------------------------------
  User access index             : 20299
  State                         : Used
  User name                     : w0099930@realm.biz
  Domain name                   : realm.biz
  User backup state             : No
  RUI user state                : -
  User access interface         : Virtual-Ethernet0/3/1.10
  User access PeVlan/CeVlan     : 190/-
  User access slot              : 0
  User MAC                      : 74ac-b974-b911
  User IP address               : 172.16.28.143(Radius)
  User IP netmask               : 255.255.255.255
  User gateway address          : 172.31.19.2
  User Primary-DNS              : 8.8.8.8
  User Secondary-DNS            : 8.8.4.4
  User Authen IP Type           : ipv4/-/-
  User Basic IP Type            : -/-/-
  IPv6 address assignment mode    : -
  RA link-prefix                  : Disable
  Coa-zero-lease                : No
  User MSIDSN name              : -
```

# show policy on interface

```
<c2-huawei>display traffic policy interface brief Eth-Trunk99
Interface                                        InboundPolicy                   OutboundPolicy
Eth-Trunk99                                      -                               TP_CONSENTIPOSTA
<c2-huawei>display traffic policy interface brief Eth-Trunk20
Interface                                        InboundPolicy                   OutboundPolicy
Eth-Trunk20                                      -                               TP_PROTEGGI10 
```

# display acl

```
<c2-huawei>display acl name  PROTEGGI10
Advanced Name ACL PROTEGGI10, 6 rules
ACL's step is 5
 rule 5 permit ip source-pool MICSONOC destination 10.0.0.0 0.255.255.255 (0 times matched)
 rule 6 permit ip source-pool VPNHOME destination 10.0.0.0 0.255.255.255 (0 times matched)
 rule 7 permit ip source 10.0.112.2 0 destination 10.0.0.0 0.255.255.255 (0 times matched)
 rule 8 permit ip source 192.168.35.0 0.0.0.255 destination 10.0.0.0 0.255.255.255 (0 times matched)
 rule 10 deny ip destination 10.0.0.0 0.255.255.255 (0 times matched)
 rule 15 permit ip (0 times matched)
```

# show interface errors

```
<c1-huawei>d int bri
PHY: Physical
*down: administratively down
^down: standby
(l): loopback
(s): spoofing
(E): E-Trunk down
(b): BFD down
(B): Bit-error-detection down
(e): ETHOAM down
(d): Dampening Suppressed
(p): port alarm down
(ld): loop-detect trigger down
(td): transceiver unmatch down
(mf): mac-flapping blocked
(c): CFM down
(sd): STP instance discarding
InUti/OutUti: input utility/output utility
Interface                   PHY   Protocol  InUti OutUti   inErrors  outErrors
100GE0/3/0(100M)            *down down         0%     0%          0          0
100GE0/3/1(100M)            *down down         0%     0%          0          0
100GE0/3/2(100M)            *down down         0%     0%          0          0
100GE0/3/3(100M)            *down down         0%     0%          0          0
Eth-Trunk20                 up    up        1.94% 14.44%       1596          0
  GigabitEthernet0/3/6(10G) up    up        1.68% 15.12%          0          0
  GigabitEthernet0/3/7(10G) up    up        2.20% 13.75%       1596          0
Eth-Trunk99                 up    up       14.44%  1.70%          0          0
  GigabitEthernet0/3/12(10G) up    up       13.96%  1.65%          0          0
  GigabitEthernet0/3/13(10G) up    up       14.92%  1.75%          0          0
GigabitEthernet0/0/0        up    up        0.01%  0.01%          0          0
GigabitEthernet0/3/4(100M)  *down down         0%     0%          0          0
GigabitEthernet0/3/5(100M)  *down down         0%     0%          0          0
GigabitEthernet0/3/8(100M)  *down down         0%     0%          0          0
GigabitEthernet0/3/9(100M)  *down down         0%     0%          0          0

