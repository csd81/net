# TACACS+

SRV1:
Services:AAA 
Key: Tacacs123
Client IP: 192.168.??

USERS:
Username: Admin2
Password: Admin123

```bash
R1> enable
R1# conf t
R1(config)# 
R1(config)# username Admin2 secet Admin123
R1(config)# aaa new-model
R1(config)# tacacs-server host 192.168.1.7
R1(config)# tacacs-server key Tacacs123
R1(config)# aaa authentication login default group tacacs+ local
R1(config)# line console 0
R1(config-line)# login authentication default
R1(config-line)# exit

test it: Username, Password
```