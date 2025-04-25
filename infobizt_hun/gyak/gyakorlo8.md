# ASA


ciscoasa>
ciscoasa>en
Password: none
ciscoasa# conf t
ciscoasa(config)# hostname ASA
ASA(config)# enable password t5zf4l12
ASA(config)# exit 
ASA# show running-config 
ASA# show switch vlan 
ASA# conf t
ASA(config)# route outside  0.0.0.0   0.0.0.0   100.100.100.1
ASA(config)# int vlan 3 
ASA(config-if)#  no forward interface vlan 1 
ASA(config-if)# nameif dmz
ASA(config-if)# ip add 192.168.2.1   255.255.255.0
ASA(config-if)# security-level 50 
ASA(config-if)# exit 
ASA(config)# int vlan 2
ASA(config-if)# ip addr 100.100.100.2 255.255.255.240
ASA(config-if)# exit 
ASA(config)# 