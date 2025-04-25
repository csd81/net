# NTP, Syslog server
SRV1: Syslog server 
SRV2: NTP server 192.168.1.8

```bash
! NTP
R1> enable
R1# configure terminal
R1(config)#
R1(config)# ntp server 192.168.1.8
R1(config)# do show clock
R1(config)# npt update-calendar
R1(config)# do show clock
R1(config)# 

! authentication

R1(config)# ntp authenticate 
R1(config)# ntp authentication-key 1 md5 Ntp123
R1(config)# ntp trusted-key 1

! syslog
R1(config)# logging 192.168.1.7
R1(config)# logging on
R1(config)# 
R1(config)# int s0/0/0

! test syslog service
R1(config-if)# shutdown
R1(config-if)# no shutdown
! check messages on syslog server

! finetuning
R1(config)# service timestamps log datetime msec
```