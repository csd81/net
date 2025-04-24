
# Zone-based policy firewall

! now we get license
ISP> en 
ISP# conf terminal
ISP(config)# license boot module c2900 technology-package security k9
    [yes] yes
ISP(config)# do copy running start
! reboot, now we have security features...

ISP(config)# do show version
    ... securityk9 evaluation

! now we configure ZPF

ISP(config)#
ISP(config)# zone security in-zone
ISP(config-sec-zone)# exit
ISP(config)# zone security out-zone
ISP(config-sec-zone)# exit
ISP(config)#
ISP(config)# access-list 100 permit ip 192.168.2.0  0.0.0.255 any
ISP(config)# class-map type inspect match-all in-net-class-map
ISP(config-cmap)# 
ISP(config-cmap)#  match access-group 100
ISP(config-cmap)# exit
ISP(config)# policy-map type inspect in-2-out-pmap 
ISP(config-pmap)# 
ISP(config-pmap)# class type inspect in-net-class-map
ISP(config-pmap-c)# 
ISP(config-pmap-c)# *inspect* / drop / pass 
ISP(config-pmap-c)# exit
ISP(config-pmap)# exit
ISP(config)# zone-pair security in-2-out-zpair source in-zone destination out-zone
ISP(config-sec-zone-pair)# 
ISP(config-sec-zone-pair)#  service-policy type inspect in-2-out-pmap 
ISP(config-sec-zone-pair)# exit
ISP(config)# int gi0/1
ISP(config-if)# 
ISP(config-if)# zone-member security in-zone
ISP(config-if)# exit
ISP(config)# int s0/0/0
ISP(config-if)# 
ISP(config-if)# zone-member security out-zone
ISP(config-if)# exit
ISP(config)#
ISP(config)# do show policy-map type inspect zone-pair sessions