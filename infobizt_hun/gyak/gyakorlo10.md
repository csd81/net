# Site-2-Site VPN R1 <--> R3


R1> en
R1# conf t
R1(config)# access-list 100 permit ip 80.90.10.0  0.0.0.7     192.168.1.64   0.0.0.63
R1(config)# access-list 100 permit ip 80.90.10.0  0.0.0.7     192.168.1.128  0.0.0.31
R1(config)# access-list 100 permit ip 80.90.10.0  0.0.0.7     192.168.1.160  0.0.0.7
R1(config)#
R1(config)# access-list 100 permit ip 193.6.46.0  0.0.0.15     192.168.1.64   0.0.0.63
R1(config)# access-list 100 permit ip 193.6.46.0  0.0.0.15     192.168.1.128  0.0.0.31
R1(config)# access-list 100 permit ip 193.6.46.0  0.0.0.15     192.168.1.160  0.0.0.7
R1(config)#
R1(config)# crypto isakmp policy 1
R1(config-isakmp)# encryption aes 256 
R1(config-isakmp)# authentication  pre-share
R1(config-isakmp)# group 5 
R1(config-isakmp)# hash sha 
R1(config-isakmp)# lifetime 86400  
R1(config-isakmp)# exit 
R1(config)#
R1(config)# crypto isakmp key t1tk0s12 address 192.168.1.173
R1(config)#
R1(config)# crypto ipsec transform-set VPN-SET esp-aes esp-sha-hmac 
R1(config)# crypto map VPN-MAP 1 ipsec-isakmp
R3(config-crypto-map)# set peer 192.168.1.173
R1(config-crypto-map)# set transform-set VPN-SET 
R1(config-crypto-map)# match address 100 
R1(config-crypto-map)# exit 
R1(config)# 
R1(config)# int s0/0/1
R1(config-if)#
R1(config-if)# crypto map VPN-MAP
R1(config-if)# exit 
R1(config)#  exit
R1# show crypto ipsec  sa

R3> en
pw: t1tk0s12
R3# conf t
R3(config)#  access-list 100 permit ip  192.168.1.64  0.0.0.63   80.90.10.0  0.0.0.7
R3(config)#  access-list 100 permit ip  192.168.1.64  0.0.0.63   193.6.46.0  0.0.0.15
R3(config)#
R3(config)#  access-list 100 permit ip 192.168.1.128  0.0.0.31   80.90.10.0  0.0.0.7
R3(config)#  access-list 100 permit ip 192.168.1.128  0.0.0.31   193.6.46.0  0.0.0.15
R3(config)#
R3(config)#  access-list 100 permit ip 192.168.1.160  0.0.0.7    80.90.10.0  0.0.0.7
R3(config)#  access-list 100 permit ip 192.168.1.160  0.0.0.7    193.6.46.0  0.0.0.15
R3(config)#
R1(config)#
R3(config)# crypto isakmp policy 1
R3(config-isakmp)# encryption aes 256 
R3(config-isakmp)# authentication  pre-share
R3(config-isakmp)# group 5 
R3(config-isakmp)# hash sha 
R3(config-isakmp)# lifetime 86400  
R3(config-isakmp)# exit 
R3(config)#
R3(config)# crypto isakmp key t1tk0s12 address 192.168.1.169
R3(config)#
R3(config)# crypto ipsec transform-set VPN-SET esp-aes esp-sha-hmac 
R3(config)# crypto map VPN-MAP 1 ipsec-isakmp
R3(config-crypto-map)# set peer 192.168.1.169
R3(config-crypto-map)# set transform-set VPN-SET 
R3(config-crypto-map)# match address 100 
R3(config-crypto-map)# exit 
R3(config)# 
R3(config)# int s0/0/0
R3(config-if)#
R3(config-if)# crypto map VPN-MAP
R3(config-if)# exit 
R3(config)# 
R3(config)#  exit
R3# show crypto ipsec  sa



