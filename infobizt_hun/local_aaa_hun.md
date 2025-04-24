# local AAA

R3> en
R3# conf t
R3(config)# username Admin3 secret admin123
R3(config)# 
R3(config)# aaa new-model
R3(config)# aaa authentication login default local 
R3(config)# aaa authentication login default local-case  ! case sensitive
R3(config)# aaa authentication login default group ! Server-group
R3(config)# line console 0 
R3(config-line)# login authentication default 
R3(config-line)# exit
R3(config)# 
R3(config)# ip domain-name cisco.com
R3(config)# crypto key generate rsa
    modulus: 1025
R3(config)# 
R3(config)# aaa authentication login SSH-LOGIN local
R3(config)# line vty 0 4 
R3(config-line)# login authentication SSH-LOGIN  
R3(config-line)# transport input ssh
R3(config-line)# exit 


