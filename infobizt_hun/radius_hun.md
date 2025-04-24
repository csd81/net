# Radius
Server1: AAA 
key: Radius123



R2> enable
R2# conf t
R2(config)# 
R2(config)# username Admin1 secret Admin123
R2(config)# radius-server host 192.168.1.8
R2(config)# radius-server key Radius123
R2(config)# aaa new-model
R2(config)# aaa authentication login default group radius  local
R2(config)# 
R2(config)#  line console 0
R2(config-line)# login authentication default
R2(config-line)# exit


Test:
User: Admin1
pass: Admin123 
R2>