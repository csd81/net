 
# ✅ Checkpoint Exam: Monitoring and Managing Devices  
**Modules 5–7 – Network Security 1.0**  
*Multiple Choice Questions (formatted, no answers)*

---

### 1. Which privilege level is predefined for the privileged EXEC mode?
- a) level 0  
- b) level 1  
- c) level 15  
- d) level 16  

---

### 2. What is a requirement to use the Secure Copy Protocol feature?
- a) At least one user with privilege level 1 has to be configured for local authentication.  
- b) A command must be issued to enable the SCP server side functionality.  
- c) A transfer can only originate from SCP clients that are routers.  
- d) The Telnet protocol has to be configured on the SCP server side.  

---

### 3. Which three items are prompted for a user response during interactive AutoSecure setup? *(Choose three.)*
- a) IP addresses of interfaces  
- b) Content of a security banner  
- c) Enable secret password  
- d) Services to disable  
- e) Enable password  
- f) Interfaces to enable  

---

### 4. Which syslog message type is accessible only to an administrator and only via the Cisco CLI?
- a) errors  
- b) alerts  
- c) debugging  
- d) emergency  

---

### 5. Refer to the exhibit. 
```cisco
Router# show ntp status
Clock is synchronized, stratum 3, reference is 192.168.1.1
nominal freq is 250.0000 Hz, actual freq is 250.0000 Hz, precision is 2**24
reference time is DA27B091.83E37490 (12:09:53.515 UTC Fri Dec 25 2015)
clock offset is -1.5326 msec, root delay is 13.90 msec
root dispersion is 7941.16 msec, peer dispersion is 0.76 msec
loopfilter state is 'CTRL' (Normal Controlled Loop), drift is -0.000000130 s/s
system poll interval is 64, last update was 117 sec ago.
```
What two statements describe the NTP status of the router? *(Choose two.)*
- a) The router is serving as an authoritative time source.  
- b) The software clock must be configured with the `set clock` command.  
- c) The router is attached to a stratum 2 device.  
- d) The router is a time source for the device at 192.168.1.1.  
- e) The IP address of the time source is 192.168.1.1.  

---

### 6. Which privilege command is used to create a custom user account?
- a) `privilege exec level 15`  
- b) `privilege exec level 0`  
- c) `privilege exec level 1`  
- d) `privilege exec level 2`  

---

### 7. What features are supported by SNMPv3 but not SNMPv1 or v2c? *(Choose two.)*
- a) Message encryption  
- b) Community-based security  
- c) SNMP trap mechanism  
- d) Message source validation  
- e) Bulk retrieval of MIB information  

---

### 8. What are two attributes of TACACS+ authentication? *(Choose two.)*
- a) TCP port 40  
- b) Encryption for all communication  
- c) Single process for authentication and authorization  
- d) UDP port 1645  
- e) Encryption for only the password  
- f) Separate processes for authentication and authorization  

---

### 9. What are two characteristics of the RADIUS protocol? *(Choose two.)*
- a) Encrypts entire body  
- b) Encrypts password only  
- c) Uses UDP ports  
- d) Separates authentication and authorization  
- e) Uses TCP port 49  

---

### 10. What is a major difference between local AAA and the `login local` command?
- a) `login local` requires manual username/password configuration  
- b) Local AAA allows more than one user account  
- c) Local AAA provides backup authentication methods  
- d) `login local` does not use local credentials  

---

### 11. Which two UDP port numbers may be used for RADIUS authentication? *(Choose two.)*
- a) 1812  
- b) 1645  
- c) 1813  
- d) 1646  
- e) 49  

---

### 12. Which command moves `show access-lists` to privilege level 14?
- a) `privilege level 14 command show access-lists`  
- b) `privilege exec level 14 show access-lists`  
- c) `set privilege level 14 show access-lists`  
- d) `show access-lists privilege level 14`  

---

### 13. Which method stores credentials on the router and suits small networks?
- a) Server-based AAA over TACACS+  
- b) Local AAA over RADIUS  
- c) Server-based AAA  
- d) Local AAA over TACACS+  
- e) Local AAA  
- f) Server-based AAA over RADIUS  

---

### 14. What are characteristics of superviews in Cisco CLI? *(Choose three.)*
- a) `enable view superview-name` is used to enter it  
- b) Superviews configure commands inside views  
- c) Commands cannot be configured directly on a superview  
- d) Level 15 is required to create a superview  
- e) Deleting a superview does not delete the views  
- f) CLI views can be shared between multiple superviews  

---

### 15. What does `parser view TECH-view` do?
- a) Create a CLI view named TECH-view  
- b) Enter the superview TECH-view  
- c) Check CLI view setup  
- d) Enter TECH-view CLI view  

---

### 16. Refer to the exhibit. 
A student uses the show parser view all command to see a summary of all views configured on router R1. What is indicated by the symbol * next to JR-ADMIN?

```cisco
R1# enable view
Password:

R1# show parser view
Current view is 'root'

R1# show parser view all
Views/SuperViews Present in System:
 SHOWVIEW
 VERIFYVIEW
 REBOOTVIEW

 JR-ADMIN *
```


- a) Root view  
- b) CLI view without commands  
- c) Superview  
- d) CLI view  

---

### 17. What are two characteristics of Cisco IOS Resilient Configuration? *(Choose two.)*
- a) Mirrors config in RAM  
- b) Sends IOS image to TFTP  
- c) Saves secure image/config not removable by users  
- d) Minimizes recovery downtime  
- e) Available on all Cisco devices  

---

### 18. What IOS privilege levels are available for custom users?
- a) 1–15  
- b) 0, 1, and 15  
- c) 2–14  
- d) 0 and 1  

---

### 19. In a syslog message, what identifies the facility?
```cisco
*Mar  1 00:02:59.451: %OSPF-5-ADJCHG: Process 99, Nbr 172.16.10.5 on Serial0/0 from LOADING to FULL, Loading Done
```

- a) ADJCHG  
- b) Loading Done  
- c) OSPF  
- d) Level 5  

---

### 20. What is the biggest issue with local AAA implementation?
- a) Supports only TACACS+  
- b) Cannot provide secure authentication  
- c) Does not scale well  
- d) Supports only RADIUS  

---

### 21. What must be configured to encrypt ACS-to-router data?
- a) Same key on both server and router  
- b) Use `single-connection` keyword  
- c) Create VPN tunnel  
- d) Use identical ports  

---

### 22. Refer to the exhibit. Based on the output of the show running-config command, which type of view is SUPPORT?
```cisco
Router# show running-config

<output omitted>
!
Parser view SUPPORT superview
 secret 5 $1$Vp10$BBB1M68Z2ekr/aHlledts.
 view SHOWVIEW
 view VERIFYVIEW

- a) CLI view with SHOWVIEW and VERIFYVIEW  
- b) Superview with SHOWVIEW and VERIFYVIEW  
- c) Secret view (level 5 password)  
- d) Root view  
```
---

### 23. What command should be issued first to create a CLI view?
- a) `enable view`  
- b) `aaa new-model`  
- c) `enable view TECH-view`  
- d) `parser view TECH-view`  

---

### 24. What two commands configure OSPF authentication with password `1A2b3C` in Area 0? *(Choose two.)*
- a) `area 0 authentication message-digest`  
- b) `ip ospf message-digest-key 1 md5 1A2b3C`  
- c) `username OSPF password 1A2b3C`  
- d) `enable password 1A2b3C`  
- e) `area 1 authentication message-digest`  

---

### 25. A user can only access a server with FTP. Which AAA component handles this?
- a) Accessibility  
- b) Accounting  
- c) Auditing  
- d) Authentication  
- e) Authorization  

---

### 26. Which AAA component uses token cards?
- a) Accounting  
- b) Authorization  
- c) Auditing  
- d) Authentication  

---

### 27. What is the primary function of `aaa authorization`?
- a) Permit AAA server access to client services  
- b) Limit user access to client services  
- c) Permit user access to client services  
- d) Limit server access to client services  

---

Let me know if you'd like this exported as a `.md` file or turned into an interactive quiz or printable PDF!