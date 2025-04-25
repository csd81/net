

# IPS 
R2(config)#
R2(config)# license boot module c2900 technology-package securityk9
[yes]
! save running-config
! reboot IOS
R2(config)#
R2(config)# do mkdir ipsdir 
R2(config)# ip ips config location flash:ipsdir
R2(config)# ip ips name iosips
R2(config)# ip ips notify log
R2(config)# 
R2(config)# ip ips signature-category 
R2(config-ips-category)# category all 
R2(config-ips-category-action)# retired true
R2(config-ips-category-action)# exit 
R2(config-ips-category)#  category ios_ips basic
R2(config-ips-category-action)# retired false
R2(config-ips-category-action)# exit 
R2(config-ips-category)# exit 
R2(config)# 
R2(config)# int gi0/1
R2(config-if)# ip ips iosips out
R2(config-if)# exit
R2(config)# ip ips signature-definition
R2(config-sigdef)# signature 2004 0
R2(config-sigdef-sig)#
R2(config-sigdef-sig)# status 
R2(config-sigdef-sig-status)#
R2(config-sigdef-sig-status)#  retired false
R2(config-sigdef-sig-status)#  enabled true
R2(config-sigdef-sig-status)#  exit
R2(config-sigdef-sig)# engine 
R2(config-sigdef-sig-engine)# 
R2(config-sigdef-sig-engine)# event-action produce-alert
R2(config-sigdef-sig-engine)# event-action deny-packet-inline 
R2(config-sigdef-sig-engine)# exit
R2(config-sigdef-sig)# exit 
R2(config-sigdef)# exit 
R2(config)# 