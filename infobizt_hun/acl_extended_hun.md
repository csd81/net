# extended ACL

can filter by source destination protocol

access-list 100 permit/deny tcp/udp/ip/icmp host/any/[source ip] host/any/[destination ip] eq [port number]80/443/20/21/22/.../www/dns/ftp

ISP> enable
ISP# configure terminal

ISP(config)# access-list 100 permit host ip host 192.168.1.10 host 192.168.2.11 
ISP(config)# access-list 100 permit tcp any host 192.168.2.11 eq 80
ISP(config)# access-list 100 permit tcp any host 192.168.2.11 eq 443

> implicit deny

ISP(config)# int gi0/1
ISP(config-if)# ip access-group 100 out
ISP(config-if)# exit
ISP(config)#
ISP(config)# no access-list 100
ISP(config)# int gi0/1
ISP(config-if)# no ip access-group 100 out

user Admin1
pass Admin123

R1> enable
R1# configure terminal
R1(config)#
R1(config)# access-list 100 permit tcp 192.168.2.0 0.0.0.255 host 192.168.1.7 eq 21
R1(config)# access-list 100 permit tcp 192.168.2.0 0.0.0.255 host 192.168.1.8 eq 443
R1(config)# int gi0/1
R1(config-if)# ip access-group 100 out
R1(config-if)# exit

