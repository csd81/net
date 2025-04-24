management access acl - normal ACL

telnet vagy ssh kell



user Admin1
pass Admin123

show runnung-config

conf term


R1(config)# access-list 1 permit host 192.168.1.10
R1(config)# access-list 1 permit 192.168.2.0        0.0.0.255 !/24
R1(config)# line vty 0 4 
R1(config)# access-class 1 in

C:\> ssh -l Admin1 192.168.1.1 
# ? működik vagy nem?

named:


user Admin1
pass Admin123
R2> enable
R2# conf t
R1(config)# ip access-list standard R2acl 
R1(config-std-nacl)# permint host 192.168.1.10
R1(config-std-nacl)# exit
R1(config)# line vty 0 4
R1(config-line)#  access-class R2 in

ISP> enable
ISP# conf t 
ISP(config)# access-list 1 permit host 192.168.1.7
ISP(config)# access-list 1 permit host 192.168.1.8
ISP(config)# int gi0/1
ISP(config-if)# ip access-group 1 out
ISP(config-if)# exit