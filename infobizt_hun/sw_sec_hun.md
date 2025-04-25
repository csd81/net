# Switch port security
# STP = Spanning Tree Protocol

```bash
S1> en, conf t
S1(config)# int range fa0/3-24, gi0/2
S1(config-if-range)# shutdown
S1(config-if-range)# exit
S1(config)# spanning-tree vlan 1,10,20,50,100 root primary
S1(config)# int range fa0/1-2, gi0/1
S1(config-if-range)# switchport trunk native vlan 100
S1(config-if-range)# exit

S2> en, conf t
S2(config)# int range fa0/2-21, gi0/1-2
S2(config-if-range)# shutdown
S2(config-if-range)# exit
S2(config)# spanning-tree vlan 1,10,20,50,100 root secondary
S2(config)# int range fa0/22-24, fa0/1
S2(config-if-range)# switchport trunk native vlan 100
S2(config-if-range)# exit

S3> en, conf t
S3(config)# int range fa0/1, fa0/3-21, gi0/1-2
S3(config-if-range)# shutdown
S3(config-if-range)# exit
S3(config)# int range fa0/2, fa0/22-24
S3(config-if-range)# switchport trunk native vlan 100
S3(config-if-range)# exit

S4> en, conf t
S4(config)# int range fa0/2-21, fa0/24,  gi0/1-2
S4(config-if-range)# shutdown
S4(config-if-range)# exit
S4(config)# int fa0/1
S4(config-if)# switchport port-security
S4(config-if)# switchport port-security max 1
S4(config-if)# switchport port-security mac-address sticky
S4(config-if)# switchport port-security violation shutdown
S4(config-if)# spanning-tree portfast
S4(config-if)# spanning-tree bpduguard enable
S4(config-if)# exit
S4(config)# int range fa0/23-24
S4(config-if-range)# switchport trunk native vlan 100
S4(config-if-range)# exit

S5> en
S5# configure term
S5(config)# int range fa0/3-21, fa0/24,  gi0/1-2
S5(config-if-range)# shutdown
S5(config-if-range)# exit
S5(config)# int range fa0/1-2
S5(config-if-range)# switchport port-security
S5(config-if-range)# switchport port-security max 1
S5(config-if-range)# switchport port-security mac-address sticky
S5(config-if-range)# switchport port-security violation shutdown
S5(config-if-range)# spanning-tree portfast
S5(config-if-range)# spanning-tree bpduguard enable
S5(config-if-range)# exit
S5(config)# int range fa0/22-23
S5(config-if-range)# switchport trunk native vlan 100
S5(config-if-range)# exit
```