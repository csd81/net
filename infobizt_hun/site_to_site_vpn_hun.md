# Site-2-Site IPsec VPN

# parameters (R1-R3)
- policy number: 10
- KMP:           ISAKMP
- crypto:        AES-256
- hash:          SHA-1
- auth type:     pre-share
- DH group:      5
- shared key:    t5nn3l

# parameters        R1              R3
transform-set       VPN-SET         VPN-SET
allowed on 100 ACL  1,3,4 networks  80.90.10.0/28
crypto map          VPN-MAP         VPN-MAP
SA on crypto map    ipsec-isakmp    ipsec-isakmp

! license boot module needed.

R1> enable
R1# conf t
R1(config)# crypto isakmp policy 10
R1(config-isakmp)# hash sha
R1(config-isakmp)# authentication pre-share
R1(config-isakmp)# group 5
R1(config-isakmp)# lifetime 86400
R1(config-isakmp)# encryption aes 256
R1(config-isakmp)# exit
R1(config)# 
R1(config)# crypto isakmp key t5nn3l address 10.0.0.5
R1(config)# 
R1(config)# crypto ipsec transform-set VPN-SET esp-aes esp-sha-hmac
R1(config)# crypto map VPN-MAP 10 ipsec-isakmp
R1(config-crypto-map)# 
R1(config-crypto-map)# set peer  10.0.0.5
R1(config-crypto-map)# set transform-set VPN-SET
R1(config-crypto-map)# match address 100
R1(config-crypto-map)# exit
R1(config)# 
R1(config)# access-list 100 permit ip 192.168.1.0   0.0.0.255    80.90.10.0   0.0.0.15
R1(config)# access-list 100 permit ip 192.168.3.0   0.0.0.255    80.90.10.0   0.0.0.15
R1(config)# access-list 100 permit ip 192.168.4.0   0.0.0.255    80.90.10.0   0.0.0.15
R1(config)# interface s0/0/0 
R1(config-if)# 
R1(config-if)#  crypto map  VPN-MAP
R1(config-if)# exit
R1(config)# 
R1(config)# do show crypto ipsec sa
R1(config)# exit
R1#  show crypto ipsec sa

R3> enable
R3# conf t
R3(config)# crypto isakmp policy 10
R3(config-isakmp)# hash sha
R3(config-isakmp)# authentication pre-share
R3(config-isakmp)# group 5
R3(config-isakmp)# lifetime 86400
R3(config-isakmp)# encryption aes 256
R3(config-isakmp)# exit
R3(config)# 
R3(config)# crypto isakmp key t5nn3l address 10.0.0.1
R3(config)# 
R3(config)# crypto ipsec transform-set VPN-SET esp-aes esp-sha-hmac
R3(config)# crypto map VPN-MAP 10 ipsec-isakmp
R3(config-crypto-map)# 
R3(config-crypto-map)# set peer  10.0.0.1
R3(config-crypto-map)# set transform-set VPN-SET
R3(config-crypto-map)# match address 100
R3(config-crypto-map)# exit
R3(config)# 
R3(config)# access-list 100 permit ip     80.90.10.0   0.0.0.15 192.168.1.0   0.0.0.255
R3(config)# access-list 100 permit ip     80.90.10.0   0.0.0.15 192.168.3.0   0.0.0.255
R3(config)# access-list 100 permit ip     80.90.10.0   0.0.0.15 192.168.4.0   0.0.0.255
R3(config)# interface s0/0/1
R3(config-if)# 
R3(config-if)#  crypto map  VPN-MAP
R3(config-if)# exit
R3(config)# 
R3(config)# access-list 100 permit ip     192.168.2.0   0.0.0.255 192.168.1.0   0.0.0.255
R3(config)# access-list 100 permit ip     192.168.2.0   0.0.0.255 192.168.3.0   0.0.0.255
R3(config)# access-list 100 permit ip     192.168.2.0   0.0.0.255 192.168.4.0   0.0.0.255
R3(config)# 
R3(config)# exit
R3#  show crypto ipsec sa