# OSPF - MD5

```bash
R1>
R1# conf t
R1(config)# router ospf 1
R1(config-router)# area 0 authentication message-digest
R1(config-router)# exit
R1(config)# int s0/0/0
R1(config-if)# ip ospf message-digest-key 1 md5 cisco123
R1(config-if)# exit


R2>
R2# conf t
R2(config)# router ospf 1
R2(config-router)# area 0 authentication message-digest
R2(config-router)# exit
R2(config)# int s0/0/0
R2(config-if)# 
R2(config-if)# ip ospf message-digest-key 1 md5 cisco123
R2(config-if)# exit
R2(config)# 
R2(config)# int s0/0/1
R2(config-if)# 
R2(config-if)# ip ospf message-digest-key 1 md5 cisco123
R2(config-if)# exit
R3(config)# 

R3> en
R3# conf t
R3(config)# router ospf 1
R3(config-router)# area 0 authentication message-digest
R3(config-router)# exit
R3(config)# int s0/0/1
R3(config-if)# ip ospf message-digest-key 1 md5 cisco123
R3(config-if)# exit
R3(config)# 
```