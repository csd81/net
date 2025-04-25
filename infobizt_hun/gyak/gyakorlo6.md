# Router OSPF MD5

# R1
R1(config)# router ospf 1
R1(config-router)# network 192.168.1.168 0.0.0.3 area 0
R1(config-router)# default-information originate
R1(config-router)# redistribute static
R1(config-router)# passive s0/0/0 
R1(config-router)# passive gi0/1
R1(config-router)#  
R1(config-router)#  exit 
R1(config)# do show ip route
R1(config)#
R1(config)# router ospf 1
R1(config-router)# area 0 authentication message-digest
R1(config-router)# exit
R1(config)#
R1(config)# int s0/0/1
R1(config-if)# ip ospf message-digest-key 1 md5 t1t0k12
R1(config-if)# exit
R1(config)#

# R2
R2(config)# router ospf 1
R2(config-router)# network 192.168.1.168  0.0.0.3 area 0
R2(config-router)# network 192.168.1.172  0.0.0.3 area 0
R2(config-router)# network 192.168.1.0    0.0.0.63 area 0
R2(config-router)# passive gi0/1
R2(config-router)# 
R2(config-router)#  exit 
R2(config)# do show ip route
R2(config)#
R2(config)# router ospf 1
R2(config-router)# area 0 authentication message-digest
R2(config-router)#  exit
R2(config)# 
R2(config)# int s0/0/1
R2(config-if)# ip ospf message-digest-key 1 md5 t1t0k12
R2(config-if)# exit
R2(config)# 
R2(config)# int s0/0/0
R2(config-if)# ip ospf message-digest-key 1 md5 t1t0k12
R2(config-if)# exit
R3(config)#

# R3
R3(config)# router ospf 1
R3(config-router)# network 192.168.1.172  0.0.0.3 area 0
R3(config-router)# network 192.168.1.64  0.0.0.63 area 0
R3(config-router)# network 192.168.1.128  0.0.0.31 area 0
R3(config-router)# network 192.168.1.160  0.0.0.7 area 0
R3(config-router)# passive gi0/1.10
R3(config-router)# passive gi0/1.50
R3(config-router)# passive gi0/1.100
R3(config-router)#  exit 
R3(config)# do show ip route
R3(config)#
R3(config)# router ospf 1
R3(config-router)# area 0 authentication message-digest
R3(config-router)# exit 
R3(config)#
R3(config)# int s0/0/0
R3(config-if)# ip ospf message-digest-key 1 md5 t1t0k12
R3(config-if)# exit
R3(config)#