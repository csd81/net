#OSPF - routing protocol

R1> en
R1# conf t
R1(config)# router ospf 1
R1(config-router)# network   192.168.1.0     0.0.0.255 area 0
R1(config-router)# network   10.0.0.0        0.0.0.3   area 0
R1(config-router)# passive gi0/1

R2> en
R2# conf t
R2(config)# router ospf 1
R2(config-router)# network   10.0.0.0        0.0.0.3   area 0
R2(config-router)# network   10.0.0.4        0.0.0.3   area 0

R3> en
R3# conf t
R3(config)# router ospf 1
R3(config-router)# network   10.0.0.4        0.0.0.3   area 0
R3(config-router)# passive s0/0/0
R3(config-router)# exit
R3(config)# do show ip route 
R3(config)# ip route 0.0.0.0 0.0.0.0 s0/0/0
R3(config)# router ospf 1
R3(config-router)# default-information originate
R3(config-router)# redistribute static
R3(config-router)# exit
R3(config)# 

! test
R1(config)# do show ip route 
R2(config)# do show ip route 

R4> en
R4# conf t
R4(config)# hostname ISP
ISP(config)# ip route 0.0.0.0 0.0.0.0 s0/0/0
ISP(config)# 