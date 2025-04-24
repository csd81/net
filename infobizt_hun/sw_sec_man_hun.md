#  allow management access on Switch

S1> en
S1# conf t
S1(config)# int vlan 50
S1(config-if)# ip add 192.168.1.2   255.255.255.0
S1(config-if)# exit
S1(config)# 
S1(config)# line vty 0 4
S1(config-line)# password cisco 
S1(config-line)# exit
S1(config)# 

S2> en
S2# conf t
S2(config)# int vlan 50
S2(config-if)# ip add 192.168.1.3   255.255.255.0
S2(config-if)# exit
S2(config)# 
S2(config)# line vty 0 4
S2(config-line)# password cisco 
S2(config-line)# exit
S2(config)# 

S3> en
S3# conf t
S3(config)# int vlan 50
S3(config-if)# ip add 192.168.1.4   255.255.255.0
S3(config-if)# exit
S3(config)# 
S3(config)# line vty 0 4
S3(config-line)# password cisco 
S3(config-line)# exit
S3(config)# 

S4> en
S4# conf t
S4(config)# int vlan 50
S4(config-if)# ip add 192.168.1.5   255.255.255.0
S4(config-if)# exit
S4(config)# 
S4(config)# line vty 0 4
S4(config-line)# password cisco 
S4(config-line)# exit
S4(config)# 

S5> en
S5# conf t
S5(config)# int vlan 50
S5(config-if)# ip add 192.168.1.6   255.255.255.0
S5(config-if)# exit
S5(config)# 
S5(config)# line vty 0 4
S5(config-line)# password cisco 
S5(config-line)# exit
S5(config)# 

R1> Admin1 pass: Admin123
R1> en
R1# show running-config
R1# configure terminal
R1(config)# accest-list 100 permit ip host 192.168.1.10 any
R1(config)# line vty 
R1(config)# line vty 0 4
R1(config-line)# accest-class 100 in
R1(config-line)# exit
R1(config)# 

! try to SSH from PC1 to R1




