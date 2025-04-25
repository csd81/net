# switched network

```bash
Switch> en
Switch# conf t
Switch(config)# hostname S1
S1(config)# vlan 10
S1(config-vlan)# vlan 20
S1(config-vlan)# vlan 50
S1(config-vlan)# vlan 100
S1(config-vlan)# exit
S1(config)# 
S1(config)# int range fa0/1-2, gi0/1
S1(config-if-range)# switchport mode trunk
S1(config-if-range)# switchport nonegotiate 
S1(config-if-range)# exit
S1(config)# 


Switch> en
Switch# conf t
Switch(config)# hostname S2
S2(config)#  vlan 10
S2(config-vlan)# vlan 20
S2(config-vlan)# vlan 50
S2(config-vlan)# vlan 100
S2(config-vlan)# exit
S2(config)#
S2(config)# int range fa0/1, fa0/22-24
S2(config-if-range)# switchport mode trunk
S2(config-if-range)# switchport nonegotiate 
S2(config-if-range)# exit
S2(config)#


Switch> en
Switch# conf t
Switch(config)# hostname S3
S3(config)# vlan 10
S3(config-vlan)# vlan 20
S3(config-vlan)# vlan 50
S3(config-vlan)# vlan 100
S3(config-vlan)# exit
S3(config)#
S3(config)# int range fa0/2, fa0/22-24 
S3(config-if-range)# switchport mode trunk
S3(config-if-range)# switchport nonegotiate 
S3(config-if-range)# exit
S3(config)#

Switch> en
Switch# conf t
Switch(config)# hostname S4
S4(config)# vlan 10
S4(config-vlan)# vlan 20
S4(config-vlan)# vlan 50
S4(config-vlan)# vlan 100
S4(config-vlan)# exit
S4(config)#
S4(config)# int range fa0/22-23 
S4(config-if-range)# switchport mode trunk
S4(config-if-range)# switchport nonegotiate 
S4(config-if-range)# exit
S4(config)# 
S4(config)# int fa0/1
S4(config-if)# switchport mode access
S4(config-if)# switchport access vlan 50
S4(config-if)# exit
S4(config)#


Switch> en
Switch# conf t
Switch(config)# hostname S5
S5(config)# vlan 10
S5(config-vlan)# vlan 20
S5(config-vlan)# vlan 50
S5(config-vlan)# vlan 100
S5(config-vlan)# exit
S5(config)#
S5(config)# int range fa0/22-23 
S5(config-if-range)# switchport mode trunk
S5(config-if-range)# switchport nonegotiate 
S5(config-if-range)# exit
S5(config)#
S5(config)# int fa0/1
S5(config-if)# switchport mode access
S5(config-if)# switchport access vlan 20
S5(config-if)# exit
S5(config)#
S5(config)# int fa0/2
S5(config-if)# switchport mode access
S5(config-if)# switchport access vlan 10
S5(config-if)# exit
S5(config)#

Router 1:
User: Admin1
Password Admin123

R1> en
R1# configure terminal
R1(config)# router ospf 1
R1(config-router)# network 192.168.3.0 0.0.0.255 area 0
R1(config-router)# network 192.168.4.0 0.0.0.255 area 0
R1(config-router)# no passive gi0/1
R1(config-router)# exit
R1(config)#
R1(config)# int gi0/1.10
R1(config-subif)# encapsulation dot1q 10
R1(config-subif)# ip address  192.168.4.1 255.255.255.0
R1(config-subif)# exit
R1(config)#
R1(config)# int gi0/1.20
R1(config-subif)# encapsulation dot1q 20
R1(config-subif)# ip address  192.168.3.1 255.255.255.0
R1(config-subif)# exit
R1(config)#
R1(config)# int gi0/1.50
R1(config-subif)# encapsulation dot1q 50
R1(config-subif)# ip address  192.168.1.1 255.255.255.0
R1(config-subif)# exit

! ping from PC1 to SRV1 192.168.1.7
! ping from PC1 to SRV2 192.168.4.8
! ping from PC1 to PC2 192.168.2.10
! ping from PC1 to SRV3 192.168.2.11
```

Alright, you’ve set up a **switched network** with **5 switches (S1–S5)** and **one router (R1)** doing **Router-on-a-Stick** for VLAN routing. Here's a summary and quick verification of your config:

---

**1. VLANs created on all switches:**
- VLAN 10
- VLAN 20
- VLAN 50
- VLAN 100

---

**2. Trunk Ports:**
- S1: `fa0/1-2, gi0/1`
- S2: `fa0/1, fa0/22-24`
- S3: `fa0/2, fa0/22-24`
- S4: `fa0/22-23`
- S5: `fa0/22-23`

  > `switchport mode trunk` + `switchport nonegotiate` used correctly to force trunking.

---

**3. Access Ports:**
- S4 `fa0/1` ➔ VLAN 50
- S5 `fa0/1` ➔ VLAN 20
- S5 `fa0/2` ➔ VLAN 10

---

**4. Router R1:**
- OSPF 1 enabled for:
  - 192.168.3.0/24 (VLAN 20)
  - 192.168.4.0/24 (VLAN 10)
- Router Subinterfaces (Router-on-a-Stick):
  - `gi0/1.10` ➔ VLAN 10 ➔ IP `192.168.4.1/24`
  - `gi0/1.20` ➔ VLAN 20 ➔ IP `192.168.3.1/24`
  - `gi0/1.50` ➔ VLAN 50 ➔ IP `192.168.1.1/24`

---

**5. Pings you want to test:**
- PC1 to SRV1 (192.168.1.7) — VLAN 50
- PC1 to SRV2 (192.168.4.8) — VLAN 10
- PC1 to PC2 (192.168.2.10) — *(Wait: VLAN 2? Not mentioned)*
- PC1 to SRV3 (192.168.2.11) — *(Again: VLAN 2? Not configured yet)*

---

**⚠️ Attention needed:**
- **VLAN 2** is not configured anywhere yet, but you have pings for `192.168.2.x` (PC2, SRV3).  
  ➔ You should **create VLAN 2** and **configure a subinterface** on R1 for it, like:
  ```bash
  interface gi0/1.2
    encapsulation dot1q 2
    ip address 192.168.2.1 255.255.255.0
  ```
  ➔ And make sure ports for PC2 and SRV3 are access ports assigned to VLAN 2.

- **OSPF**: You haven't included the `192.168.2.0` network yet either.

---

**Would you like me to show you the corrected configuration you could add to finish the setup properly?** 🚀  
(Only about 5-6 more lines and you’ll be fully done!)


Of course! Let’s break down your commands **one by one** carefully so you really understand what's happening:

---

# 🛠 **Switch Commands**

### 1.  
```bash
Switch> en
```
- "en" = `enable`
- Moves you from **user mode** (`Switch>`) to **privileged exec mode** (`Switch#`).
- Now you can enter configuration mode and run important commands.

---

### 2.  
```bash
Switch# conf t
```
- "conf t" = `configure terminal`
- Puts you into **global configuration mode** (`Switch(config)#`).
- You can now configure settings like hostname, VLANs, interfaces.

---

### 3.  
```bash
Switch(config)# hostname S1
```
- Changes the device's **name** from "Switch" to "S1".
- This makes the command line prompt change too (helps identify devices).

---

### 4.  
```bash
Switch(config)# vlan 10
```
- Creates a **VLAN** (Virtual LAN) with ID **10**.
- Puts you into VLAN configuration mode (`Switch(config-vlan)#`).

---
  
### 5.  
```bash
Switch(config-vlan)# exit
```
- Exits from VLAN configuration mode back to **global configuration** mode.

---

### 6.  
```bash
Switch(config)# int range fa0/1-2, gi0/1
```
- Selects **multiple interfaces** at once:
  - FastEthernet ports **0/1 to 0/2**
  - GigabitEthernet port **0/1**

---

### 7.  
```bash
Switch(config-if-range)# switchport mode trunk
```
- Sets the selected ports to **trunk mode**.
- Trunk ports **carry traffic from multiple VLANs** between switches and routers.

---

### 8.  
```bash
Switch(config-if-range)# switchport nonegotiate
```
- **Disables DTP (Dynamic Trunking Protocol)** negotiation.
- Forces the port to behave as a trunk immediately (no auto negotiation).

---

# 🛠 **Router Commands**

### 1.  
```bash
R1> en
```
- Same as on the switch: move to **privileged exec mode**.

---

### 2.  
```bash
R1# configure terminal
```
- Go into **global config mode** on the router.

---

### 3.  
```bash
R1(config)# router ospf 1
```
- Start configuring **OSPF** (Open Shortest Path First) routing process number **1**.
- OSPF helps routers **find the best path** to different networks.

---

### 4.  
```bash
R1(config-router)# network 192.168.3.0 0.0.0.255 area 0
```
- Tell OSPF: "**Hey! Advertise the 192.168.3.0/24 network!**"
- `area 0` = backbone area for OSPF.

---

### 5.  
```bash
R1(config-router)# network 192.168.4.0 0.0.0.255 area 0
```
- Same, but now tell OSPF about the **192.168.4.0/24** network.

---

### 6.  
```bash
R1(config-router)# no passive gi0/1
```
- By default, OSPF **won't send hello packets** out interfaces (passive).
- `no passive` = **activate** OSPF on the interface `gi0/1` so it can form neighbor relationships.

---

### 7.  
```bash
R1(config)# int gi0/1.10
```
- Configure a **subinterface** on `gi0/1`.
- The `.10` means it's linked to **VLAN 10**.

---

### 8.  
```bash
R1(config-subif)# encapsulation dot1q 10
```
- **Enable 802.1Q tagging** on this subinterface for **VLAN 10**.
- Allows the router to **understand VLAN traffic** from the switch.

---

### 9.  
```bash
R1(config-subif)# ip address 192.168.4.1 255.255.255.0
```
- Give this subinterface an **IP address** so it can **route** for VLAN 10 devices.

---

*(Same pattern for VLAN 20 and VLAN 50: create subinterfaces, set VLAN tag, assign IP address.)*

---

# 🛠 **Extra Commands you Mentioned**

### 10. 
```bash
! ping from PC1 to SRV1
```
- You are checking **connectivity** between devices across VLANs via router routing.

---

# 🎯 **Summary of what you are building:**
- **Switches** are connected with **trunks** to carry VLANs.
- **Access ports** connect end devices to specific VLANs.
- **Router** uses **Router-on-a-Stick** (subinterfaces + dot1q) to route between VLANs.
- **OSPF** is set up for dynamic routing.

---

Would you also like me to show you **a diagram** (network map) of your setup based on this config? 🎨  
I can make a quick visual for you if you want! 🚀


