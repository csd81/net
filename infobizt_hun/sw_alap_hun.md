# switched network

Switch> en
Switch# conf t
Switch(config)# hostname S1
S1(config)# vlan 10
S1(config-vlan)# vlan 20
S1(config-vlan)# vlan 50
S1(config-vlan)# vlan 100
S1(config-vlan)# exit
S1(config)# 
S1(config)# int range fa0/1-2, gi0/1
S1(config-if-range)# switchport mode trunk
S1(config-if-range)# switchport nonegotiate 
S1(config-if-range)# exit
S1(config)# 


Switch> en
Switch# conf t
Switch(config)# hostname S2
S2(config)#  vlan 10
S2(config-vlan)# vlan 20
S2(config-vlan)# vlan 50
S2(config-vlan)# vlan 100
S2(config-vlan)# exit
S2(config)#
S2(config)# int range fa0/1, fa0/22-24
S2(config-if-range)# switchport mode trunk
S2(config-if-range)# switchport nonegotiate 
S2(config-if-range)# exit
S2(config)#


Switch> en
Switch# conf t
Switch(config)# hostname S3
S3(config)# vlan 10
S3(config-vlan)# vlan 20
S3(config-vlan)# vlan 50
S3(config-vlan)# vlan 100
S3(config-vlan)# exit
S3(config)#
S3(config)# int range fa0/2, fa0/22-24 
S3(config-if-range)# switchport mode trunk
S3(config-if-range)# switchport nonegotiate 
S3(config-if-range)# exit
S3(config)#

Switch> en
Switch# conf t
Switch(config)# hostname S4
S4(config)# vlan 10
S4(config-vlan)# vlan 20
S4(config-vlan)# vlan 50
S4(config-vlan)# vlan 100
S4(config-vlan)# exit
S4(config)#
S4(config)# int range fa0/22-23 
S4(config-if-range)# switchport mode trunk
S4(config-if-range)# switchport nonegotiate 
S4(config-if-range)# exit
S4(config)# 
S4(config)# int fa0/1
S4(config-if)# switchport mode access
S4(config-if)# switchport access vlan 50
S4(config-if)# exit
S4(config)#


Switch> en
Switch# conf t
Switch(config)# hostname S5
S5(config)# vlan 10
S5(config-vlan)# vlan 20
S5(config-vlan)# vlan 50
S5(config-vlan)# vlan 100
S5(config-vlan)# exit
S5(config)#
S5(config)# int range fa0/22-23 
S5(config-if-range)# switchport mode trunk
S5(config-if-range)# switchport nonegotiate 
S5(config-if-range)# exit
S5(config)#
S5(config)# int fa0/1
S5(config-if)# switchport mode access
S5(config-if)# switchport access vlan 20
S5(config-if)# exit
S5(config)#
S5(config)# int fa0/2
S5(config-if)# switchport mode access
S5(config-if)# switchport access vlan 10
S5(config-if)# exit
S5(config)#

Router 1:
User: Admin1
Password Admin123

R1> en
R1# configure terminal
R1(config)# router ospf 1
R1(config-router)# network 192.168.3.0 0.0.0.255 area 0
R1(config-router)# network 192.168.4.0 0.0.0.255 area 0
R1(config-router)# no passive gi0/1
R1(config-router)# exit
R1(config)#
R1(config)# int gi0/1.10
R1(config-subif)# encapsulation dot1q 10
R1(config-subif)# ip address  192.168.4.1 255.255.255.0
R1(config-subif)# exit
R1(config)#
R1(config)# int gi0/1.20
R1(config-subif)# encapsulation dot1q 20
R1(config-subif)# ip address  192.168.3.1 255.255.255.0
R1(config-subif)# exit
R1(config)#
R1(config)# int gi0/1.50
R1(config-subif)# encapsulation dot1q 50
R1(config-subif)# ip address  192.168.1.1 255.255.255.0
R1(config-subif)# exit

! ping from PC1 to SRV1 192.168.1.7
! ping from PC1 to SRV2 192.168.4.8
! ping from PC1 to PC2 192.168.2.10
! ping from PC1 to SRV3 192.168.2.11