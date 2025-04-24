
# IPS = intrusion prevention system

R1> user Admin1 Admin123
en conf t

R1(config)#
R1(config)# do mkdir ipsdir
R1(config)# ip ips config location flash:ipsdir
R1(config)# ip ips name iosips
R1(config)# ip ips notify log
R1(config)# service timestamps log datetime msec
R1(config)# logging host 192.168.1.7
R1(config)#
R1(config)# ip ips signature-category
R1(config-ips-category)# category all
R1(config-ips-category-action)# retired true
R1(config-ips-category-action)# exit

R1(config-ips-category)# category ics_ips basic
R1(config-ips-category-action)# retired false
R1(config-ips-category-action)# exit
           [confirm]
R1(config)# int g0/1
R1(config-if)# ip ips iosips  out
R1(config-if)# exit

R1(config)# ip ips signature-definition 

R1(config-sigdef)# signature 2004 0
R1(config-sigdef-sig)# status
R1(config-sigdef-sig-status)# retired false
R1(config-sigdef-sig-status)# enable true
R1(config-sigdef-sig-status)# exit
R1(config-sigdef-sig)# engine
R1(config-sigdef-sig-engine)# event-action produce-alert
R1(config-sigdef-sig-engine)# event-action deny-packet-inline
R1(config-sigdef-sig-engine)# exit
R1(config-sigdef-sig)# exit
            [confirm]
R1(config)# 