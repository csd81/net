# ACL 

ISP> en
ISP# conf t
ISP(config)# access-list 100 permit tcp 192.168.1.64   0.0.0.63  host 193.6.46.2 eq 443
ISP(config)# access-list 100 permit tcp 192.168.1.64   0.0.0.63  host 193.6.46.3 eq 21
ISP(config)# access-list 100 permit icmp any any 
! implicit deny all others
ISP(config)# int gi0/1
ISP(config-if)# ip access-group 100 out 
ISP(config-if)# exit