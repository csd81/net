# Switch security

# S2:
S2(config)# int range fa0/1-2
S2(config-if-range)#
S2(config-if-range)# swithport port-security
S2(config-if-range)# swithport port-security maximum 1
S2(config-if-range)# swithport port-security mac-address sticky
S2(config-if-range)# swithport port-security violation restrict 
S2(config-if-range)# exit
S2(config)# 
S2(config)# int range fa0/3-23, gi0/2
S2(config-if-range)# shutdown
S2(config-if-range)# exit
S2(config)# 
S2(config)# ip domain-name cisco.com
S2(config)#  username cisco secret C1sc0us3r
S2(config)# crypto key generate rsa
    [1024]
S2(config)#  ip ssh version 2 
S2(config)#
S2(config)# line vty 0 15
S2(config-line)# login  local 
S2(config-line)# transport input ssh
S2(config-line)# exit
S2(config)# enable secret  t1tk0s12


# S3:
S3(config)# int range fa0/1-2
S3(config-if-range)#
S3(config-if-range)# swithport port-security
S3(config-if-range)# swithport port-security maximum 1
S3(config-if-range)# swithport port-security mac-address sticky
S3(config-if-range)# swithport port-security violation restrict 
S3(config-if-range)# exit
S3(config)# 
S3(config)# int range fa0/3-23, gi0/1
S3(config-if-range)# shutdown
S3(config-if-range)# exit
S3(config)# 
S3(config)#  ip domain-name cisco.com
S3(config)#  username cisco secret c1sc0us3r
S3(config)# crypto key generate rsa
    [1024]
S3(config)#  ip ssh version 2 
S3(config)#  line vty 0 15
S3(config-line)# login  local 
S3(config-line)# transport input ssh
S3(config-line)# exit
S3(config)# enable secret  t1tk0s12

# S1:
S1(config)# 
S1(config)#  ip domain-name cisco.com
S1(config)#  username cisco secret c1sc0us3r
S1(config)# crypto key generate rsa
    [1024]
S1(config)#  ip ssh version 2 
S1(config)#  line vty 0 15
S1(config-line)# login  local 
S1(config-line)# transport input ssh
S1(config-line)# exit
S1(config)# enable secret  t1tk0s12

# R3: 
R3(config)# 
R3(config)#  ip domain-name cisco.com
R3(config)#  username cisco secret c1sc0us3r
R3(config)# crypto key generate rsa
    [1024]
R3(config)# ip ssh version 2  
R3(config)# line vty 0 4
R3(config-line)# login  local 
R3(config-line)# transport input ssh
R3(config-line)# exit
R3(config)# enable secret  t1tk0s12
R3(config)# 
R3(config)# access-list 1 permit host 192.168.1.162 
! implicit deny all other
R3(config)# 
R3(config)# line vty 0 4
R3(config-line)# access-class 1 in 
R3(config-line)# exit
R3(config)# 

