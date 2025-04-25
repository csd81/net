# ASA - Adaptive Security Appliance

- R3: outer net
- DMZ: SRV3
- PC2: inner net

- SSH
- mgmt access ACL

ciscoasa>
Pass: none
```bash
ciscoasa# conf t
ciscoasa(config)# hostname ASA
ASA(config)#
ASA(config)# domain-name cisco.com
ASA(config)# enable password cisco
ASA(config)# no dhcp enable inside
ASA(config)# no dhcp address 192.168.1.5 192.168.1.36 inside
ASA(config)# int vlan 1
ASA(config-if)#
ASA(config-if)# nameif inside
ASA(config-if)# ip address  192.168.2.1    255.255.255.0
ASA(config-if)# security-level 100
ASA(config-if)# exit
ASA(config)#
ASA(config)# int vlan 2
ASA(config-if)#
ASA(config-if)# nameif outside
ASA(config-if)#  ip address 80.90.10.2     255.255.255.0
ASA(config-if)# security-level 0
ASA(config-if)# exit 
ASA(config)#
ASA(config)# int e0/1
ASA(config-if)#
ASA(config-if)# switchport access vlan 1
ASA(config-if)# exit 
ASA(config)#
ASA(config)# exit 
ASA#
ASA# show switch vlan
ASA# conf t
ASA(config)#
ASA(config)# dhcp address 192.168.2.10-192.168.2.30 inside
ASA(config)# route outside 0.0.0.0 0.0.0.0 80.90.10.1
ASA(config)# object network inside-net
ASA(config-network-object)# 
ASA(config-network-object)# subnet  192.168.2.0    255.255.255.0
ASA(config-network-object)# nat (inside,outside) dynamic interface
ASA(config-network-object)#  exit 
ASA(config)# 
ASA(config)# class-map inspection_default  
ASA(config-cmap)# 
ASA(config-cmap)# match default-inspection-traffic
ASA(config-cmap)# exit 
ASA(config)# 
ASA(config)#  policy-map global_policy
ASA(config-pmap)# class   inspection_default  
ASA(config-pmap-c)# 
ASA(config-pmap-c)# inspect icmp 
ASA(config-pmap-c)# exit 
ASA(config)# 
ASA(config)# sevice-policy  global_policy global
!! configure SSH access
ASA(config)#  
ASA(config)# username Admin1 password Admin123
ASA(config)# aaa authentication ssh console LOCAL 
ASA(config)# crypto key generate rsa modulus 1024
ASA(config)#  ssh 192.168.2.0     255.255.255.0 inside
ASA(config)#  
ASA(config)#  no  ssh 192.168.1.0     255.255.255.0 outside
ASA(config)#  ssh 192.168.1.0     255.255.255.0 outside
ASA(config)#  ssh timeout 10
ASA(config)#  
!! DMZ
ASA(config)#  int vlan 3
ASA(config-if)#
ASA(config-if)# ip addr 192.168.5.1   255.255.255.0 
ASA(config-if)# no forward interface vlan 1
ASA(config-if)# nameif dmz
ASA(config-if)# security-level 50
ASA(config-if)# exit
ASA(config)#  
ASA(config)#   int e0/2
ASA(config-if)#
ASA(config-if)# switchport access vlan 3
ASA(config-if)# exit
ASA(config)#  object network dmz-server 
ASA(config-network-object)# 
ASA(config-network-object)# host 192.168.5.11
ASA(config-network-object)# nat (dmz,outside) static 80.90.10.11
ASA(config-network-object)# exit
ASA(config)#  
ASA(config)#  access-list OUTSIDE-DMZ permit icmp any host  192.168.5.11
ASA(config)#  access-list OUTSIDE-DMZ permit tcp any host  192.168.5.11 eq 80
ASA(config)#  access-group OUTSIDE-DMZ in interface outside 
ASA(config)#  
!!ping from PC1 to PC2 
!!ping from SRV3 to PC1
!!ssh from PC1 to 80.90.10.2
!!ssh from PC2 to 192.168.2.1
```