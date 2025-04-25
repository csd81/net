#SSH



```bash
R1> en
R1# conf t
R1(config)# 
R1(config)# ip domain-name cisco.com
R1(config)# username cisco privilege 15 secret cisco
R1(config)# crypto key zeroize rsa
R1(config)# crypto key generate rsa
    modulus [512]:     1024
R1(config)# ip ssh version 2
R1(config)# ip ssh time-out 60
R1(config)# ip ssh authentication-retries 2
R1(config)# line vty 0 4
R1(config-line)# 
R1(config-line)# login local
R1(config-line)# transport input ssh
R1(config-line)# privilege level 15
R1(config-line)# exit
R1(config)# 


Switch>
Switch#
Switch(config)# 
Switch(config)# hostname S1
S1(config)# 
S1(config)# ip domain-name cisco.com
S1(config)# crypto key zeroize rsa
S1(config)# crypto key generate rsa
    modulus [512]:     1024
S1(config)# ip ssh version 2
S1(config)# ip ssh time-out 60
S1(config)# ip ssh authentication-retries 2
S1(config)# username cisco privilege 15 secret cisco
S1(config)# 
S1(config)# line vty 0 15
S1(config-line)# 
S1(config-line)#  login local
S1(config-line)# transport input ssh
S1(config-line)# privilege level 15
S1(config-line)# exit
S1(config)# 
S1(config)# int vlan 1
S1(config-if)# ip address 192.168.1.2 255.255.255.0
S1(config-if)# no shutdown
S1(config-if)# exit
S1(config)#  ip default-gateway 192.168.1.1

! test: ssh -l cisco 192.168.1.1 (router)  from PC1
! test: ssh -l cisco 192.168.1.2  (switch) from PC1
```