# ASA - Adaptive Security Appliance

- R3: outer net
- DMZ: SRV3
- PC2: inner net

- SSH
- mgmt access ACL

ciscoasa>
Pass: none
```bash
ciscoasa# conf t
ciscoasa(config)# hostname ASA
ASA(config)#
ASA(config)# domain-name cisco.com
ASA(config)# enable password cisco
ASA(config)# no dhcp enable inside
ASA(config)# no dhcp address 192.168.1.5 192.168.1.36 inside
ASA(config)# int vlan 1
ASA(config-if)#
ASA(config-if)# nameif inside
ASA(config-if)# ip address  192.168.2.1    255.255.255.0
ASA(config-if)# security-level 100
ASA(config-if)# exit
ASA(config)#
ASA(config)# int vlan 2
ASA(config-if)#
ASA(config-if)# nameif outside
ASA(config-if)#  ip address 80.90.10.2     255.255.255.0
ASA(config-if)# security-level 0
ASA(config-if)# exit 
ASA(config)#
ASA(config)# int e0/1
ASA(config-if)#
ASA(config-if)# switchport access vlan 1
ASA(config-if)# exit 
ASA(config)#
ASA(config)# exit 
ASA#
ASA# show switch vlan
ASA# conf t
ASA(config)#
ASA(config)# dhcp address 192.168.2.10-192.168.2.30 inside
ASA(config)# route outside 0.0.0.0 0.0.0.0 80.90.10.1
ASA(config)# object network inside-net
ASA(config-network-object)# 
ASA(config-network-object)# subnet  192.168.2.0    255.255.255.0
ASA(config-network-object)# nat (inside,outside) dynamic interface
ASA(config-network-object)#  exit 
ASA(config)# 
ASA(config)# class-map inspection_default  
ASA(config-cmap)# 
ASA(config-cmap)# match default-inspection-traffic
ASA(config-cmap)# exit 
ASA(config)# 
ASA(config)#  policy-map global_policy
ASA(config-pmap)# class   inspection_default  
ASA(config-pmap-c)# 
ASA(config-pmap-c)# inspect icmp 
ASA(config-pmap-c)# exit 
ASA(config)# 
ASA(config)# sevice-policy  global_policy global
!! configure SSH access
ASA(config)#  
ASA(config)# username Admin1 password Admin123
ASA(config)# aaa authentication ssh console LOCAL 
ASA(config)# crypto key generate rsa modulus 1024
ASA(config)#  ssh 192.168.2.0     255.255.255.0 inside
ASA(config)#  
ASA(config)#  no  ssh 192.168.1.0     255.255.255.0 outside
ASA(config)#  ssh 192.168.1.0     255.255.255.0 outside
ASA(config)#  ssh timeout 10
ASA(config)#  
!! DMZ
ASA(config)#  int vlan 3
ASA(config-if)#
ASA(config-if)# ip addr 192.168.5.1   255.255.255.0 
ASA(config-if)# no forward interface vlan 1
ASA(config-if)# nameif dmz
ASA(config-if)# security-level 50
ASA(config-if)# exit
ASA(config)#  
ASA(config)#   int e0/2
ASA(config-if)#
ASA(config-if)# switchport access vlan 3
ASA(config-if)# exit
ASA(config)#  object network dmz-server 
ASA(config-network-object)# 
ASA(config-network-object)# host 192.168.5.11
ASA(config-network-object)# nat (dmz,outside) static 80.90.10.11
ASA(config-network-object)# exit
ASA(config)#  
ASA(config)#  access-list OUTSIDE-DMZ permit icmp any host  192.168.5.11
ASA(config)#  access-list OUTSIDE-DMZ permit tcp any host  192.168.5.11 eq 80
ASA(config)#  access-group OUTSIDE-DMZ in interface outside 
ASA(config)#  
!!ping from PC1 to PC2 
!!ping from SRV3 to PC1
!!ssh from PC1 to 80.90.10.2
!!ssh from PC2 to 192.168.2.1
```

Alright, let's break it all down carefully.  
You're configuring a **Cisco ASA firewall** to handle three zones:

- **Outside (Internet)** = R3 (outer net)
- **Inside** = PC2 (inner net)
- **DMZ** = SRV3 (publicly accessible server)

You're setting up:
- **SSH access** to manage the ASA.
- **Management access control list** (ACL) for restricting traffic.

---

### 1. **Basic ASA Setup**
```bash
ciscoasa# conf t
```
Go into configuration mode.

```bash
ciscoasa(config)# hostname ASA
```
Change device name to `ASA`.

```bash
ASA(config)# domain-name cisco.com
```
Set the domain name (used later for generating crypto keys).

```bash
ASA(config)# enable password cisco
```
Set the **enable** (privileged exec) password to `cisco`.

---

### 2. **Disable DHCP on Inside**
```bash
ASA(config)# no dhcp enable inside
ASA(config)# no dhcp address 192.168.1.5 192.168.1.36 inside
```
Make sure ASA is **not** acting as DHCP server on the **inside** interface anymore.

---

### 3. **Interface VLANs and IP Addresses**
**Inside:**
```bash
ASA(config)# int vlan 1
ASA(config-if)# nameif inside
ASA(config-if)# ip address 192.168.2.1 255.255.255.0
ASA(config-if)# security-level 100
```
- `vlan 1` = inside network (PC2's network)
- Highest security level (100 = most trusted)

**Outside:**
```bash
ASA(config)# int vlan 2
ASA(config-if)# nameif outside
ASA(config-if)# ip address 80.90.10.2 255.255.255.0
ASA(config-if)# security-level 0
```
- `vlan 2` = connection to outside/internet (R3)
- Lowest security level (0 = least trusted)

**Connecting Physical Ports to VLANs:**
```bash
ASA(config)# int e0/1
ASA(config-if)# switchport access vlan 1
```
- Connect physical port `e0/1` to `VLAN 1` (inside network).

---

### 4. **DHCP for Inside**
```bash
ASA(config)# dhcp address 192.168.2.10-192.168.2.30 inside
```
- ASA will give IPs from **192.168.2.10** to **192.168.2.30** to inside clients (like PC2).

---

### 5. **Routing and NAT**
**Default Route:**
```bash
ASA(config)# route outside 0.0.0.0 0.0.0.0 80.90.10.1
```
- All unknown traffic goes out via gateway **80.90.10.1**.

**NAT:**
```bash
ASA(config)# object network inside-net
ASA(config-network-object)# subnet 192.168.2.0 255.255.255.0
ASA(config-network-object)# nat (inside,outside) dynamic interface
```
- Inside clients are **NATed** to ASA’s outside IP address (80.90.10.2) when accessing the Internet.

---

### 6. **Inspection Policy**
```bash
ASA(config)# class-map inspection_default
ASA(config-cmap)# match default-inspection-traffic
```
- Match standard protocols for inspection (like ICMP, FTP, etc).

```bash
ASA(config)# policy-map global_policy
ASA(config-pmap)# class inspection_default
ASA(config-pmap-c)# inspect icmp
```
- Explicitly **allow ICMP** (ping) across ASA (by default, ASA drops ICMP without this).

```bash
ASA(config)# sevice-policy global_policy global
```
- Apply the policy globally.

---

### 7. **SSH Access Configuration**
**User creation:**
```bash
ASA(config)# username Admin1 password Admin123
```
- Local user `Admin1` with password `Admin123`.

**Authenticate SSH login with local users:**
```bash
ASA(config)# aaa authentication ssh console LOCAL
```

**Generate RSA keys (needed for SSH):**
```bash
ASA(config)# crypto key generate rsa modulus 1024
```

**Allow SSH from specific networks:**
```bash
ASA(config)# ssh 192.168.2.0 255.255.255.0 inside
ASA(config)# ssh 192.168.1.0 255.255.255.0 outside
```
- Allow SSH connections:
  - From **192.168.2.0/24** inside
  - From **192.168.1.0/24** outside

**SSH timeout setting:**
```bash
ASA(config)# ssh timeout 10
```
- SSH sessions timeout after 10 minutes of inactivity.

---

### 8. **DMZ Configuration**
**New VLAN for DMZ:**
```bash
ASA(config)# int vlan 3
ASA(config-if)# ip addr 192.168.5.1 255.255.255.0
ASA(config-if)# nameif dmz
ASA(config-if)# security-level 50
```
- Create `dmz` network
- Moderate security (50 between inside and outside)

**Don't forward packets directly from inside VLAN:**
```bash
ASA(config-if)# no forward interface vlan 1
```
- Important to prevent inside users directly reaching DMZ hosts without firewall check.

**Connect physical port `e0/2` to VLAN 3:**
```bash
ASA(config)# int e0/2
ASA(config-if)# switchport access vlan 3
```

**NAT for DMZ server:**
```bash
ASA(config)# object network dmz-server
ASA(config-network-object)# host 192.168.5.11
ASA(config-network-object)# nat (dmz,outside) static 80.90.10.11
```
- Make internal server **192.168.5.11** reachable from outside on **80.90.10.11**.

---

### 9. **ACL for DMZ Server**
Allow specific traffic:
```bash
ASA(config)# access-list OUTSIDE-DMZ permit icmp any host 192.168.5.11
ASA(config)# access-list OUTSIDE-DMZ permit tcp any host 192.168.5.11 eq 80
```
- Allow:
  - ICMP (ping)
  - TCP port 80 (HTTP)

Apply ACL to outside:
```bash
ASA(config)# access-group OUTSIDE-DMZ in interface outside
```
- Only traffic defined in `OUTSIDE-DMZ` ACL will be allowed **inbound** from outside.

---

### 10. **Testing Steps**
- **Ping from PC1 (outside) to PC2 (inside)** → tests NAT, routing.
- **Ping from SRV3 (DMZ) to PC1** → tests DMZ-outside connectivity.
- **SSH from PC1 to ASA’s outside IP (80.90.10.2)** → tests external SSH access.
- **SSH from PC2 to ASA’s inside IP (192.168.2.1)** → tests internal SSH access.

---

### TL;DR (Summary)
You are:
- Setting up interfaces (inside, outside, dmz).
- Enabling NAT for inside network.
- Allowing SSH access to manage ASA from inside and outside.
- Creating DMZ and NATting DMZ server to public IP.
- Allowing specific traffic (ICMP, HTTP) to DMZ server via ACL.
- Configuring security policies and DHCP.

---

Would you like me to also draw a simple **network diagram** based on this setup? 🎯  
It might help you visualize it even better! 🚀