# switched network
# R3: Router on a stick


S1:
Switch> en
Switch# conf t
Switch(config)# hostname S1
S1(config)# vlan 10
S1(config-vlan)# name tizes
S1(config-vlan)# exit
S1(config)# vlan 50
S1(config-vlan)# name otvenes
S1(config-vlan)# exit
S1(config)# vlan 100
S1(config-vlan)# name szazas
S1(config-vlan)# exit
S1(config)#
S1(config)# int fa0/1
S1(config-if)# switchport mode access 
S1(config-if)# switchport access  vlan 50
S1(config-if)# exit
S1(config)#
S1(config)# int range fa0/24,g0/1-2
S1(config-if-range)# switchport mode trunk
S1(config-if)# exit
S1(config)#
S1(config)# int vlan 50
S1(config-if)# ip address 192.168.1.163 255.255.255.248
S1(config-if)# exit
S1(config)# ip default-gateway 192.168.1.161



S2:
Switch> en
Switch# conf t
Switch(config)# hostname S2
S2(config)# vlan 10
S2(config-vlan)# name tizes
S2(config-vlan)# exit
S2(config)# vlan 50
S2(config-vlan)# name otvenes
S2(config-vlan)# exit
S2(config)# vlan 100
S2(config-vlan)# name szazas
S2(config-vlan)# exit
S2(config)#
S2(config)# int range fa0/1-2
S2(config-if-range)# switchport mode access 
S2(config-if-range)# switchport access  vlan 10
S2(config-if-range)# exit
S2(config)#
S2(config)# int range g0/1,fa0/24
S2(config-if-range)# switchport mode trunk
S2(config-if-range)# exit
S2(config)#
S2(config)# int vlan 50
S2(config-if)# ip address 192.168.1.164 255.255.255.248
S2(config-if)# exit
S2(config)# ip default-gateway 192.168.1.161


S3:
Switch> en
Switch# conf t
Switch(config)# hostname S3
S3(config)# 
S3(config)# int range fa0/24
S3(config-if-range)# switchport mode trunk
S3(config-if-range)# exit
S3(config)# 
S3(config)# vlan 10
S3(config-vlan)# name tizes
S3(config-vlan)# exit
S3(config)#
S3(config)# vlan 50
S3(config-vlan)# name otvenes
S3(config-vlan)# exit
S3(config)#
S3(config)# vlan 100
S3(config-vlan)# name szazas
S3(config-vlan)# exit
S3(config)#
S3(config)# int range fa0/1-2
S3(config-if-range)# switchport mode access
S3(config-if-range)# switchport access vlan 100
S3(config-if-range)# exit
S3(config)#
S2(config)# int vlan 50
S2(config-if)# ip address 192.168.1.165 255.255.255.248
S2(config-if)# exit
S2(config)# ip default-gateway 192.168.1.161



R3> en
R3# conf t
R3(config)# int g0/1
R3(config-if)# no shut
R3(config-if)# exit
R3(config)# 
R3(config)# int gi0/1.10 
R3(config-subif)# 
R3(config-subif)# encapsulation dot1q 10
R3(config-subif)# ip address 192.168.1.65 255.255.255.192
R3(config-subif)#  exit
R3(config)# 
R3(config)# int gi0/1.50 
R3(config-subif)# 
R3(config-subif)# encapsulation dot1q 50
R3(config-subif)# ip address 192.168.1.161  255.255.255.248
R3(config-subif)#  exit
R3(config)# 
R3(config)# int gi0/1.100 
R3(config-subif)# 
R3(config-subif)# encapsulation dot1q 100
R3(config-subif)# ip address 192.168.1.129  255.255.255.224
R3(config-subif)#  exit
R3(config)# 
