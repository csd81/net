#OSPF - routing protocol

```bash
R1> en
R1# conf t
R1(config)# router ospf 1
R1(config-router)# network   192.168.1.0     0.0.0.255 area 0
R1(config-router)# network   10.0.0.0        0.0.0.3   area 0
R1(config-router)# passive gi0/1

R2> en
R2# conf t
R2(config)# router ospf 1
R2(config-router)# network   10.0.0.0        0.0.0.3   area 0
R2(config-router)# network   10.0.0.4        0.0.0.3   area 0

R3> en
R3# conf t
R3(config)# router ospf 1
R3(config-router)# network   10.0.0.4        0.0.0.3   area 0
R3(config-router)# passive s0/0/0
R3(config-router)# exit
R3(config)# do show ip route 
R3(config)# ip route 0.0.0.0 0.0.0.0 s0/0/0
R3(config)# router ospf 1
R3(config-router)# default-information originate
R3(config-router)# redistribute static
R3(config-router)# exit
R3(config)# 

! test
R1(config)# do show ip route 
R2(config)# do show ip route 

R4> en
R4# conf t
R4(config)# hostname ISP
ISP(config)# ip route 0.0.0.0 0.0.0.0 s0/0/0
ISP(config)# 
```

Alright! Let’s break this down carefully:

---

### Step-by-Step Explanation:

#### **R1 Configuration:**
```bash
R1> en
```
- `en` = short for `enable`. It moves you from *user mode* (>) to *privileged mode* (#).

```bash
R1# conf t
```
- `conf t` = *configure terminal*. Enters global configuration mode where you can change settings.

```bash
R1(config)# router ospf 1
```
- Tells the router you are configuring OSPF (Open Shortest Path First) instance **1**.

```bash
R1(config-router)# network 192.168.1.0 0.0.0.255 area 0
```
- Adds the network `192.168.1.0/24` into **OSPF Area 0** (backbone area).  
- The `0.0.0.255` is a **wildcard mask**, meaning "match any address from 192.168.1.0 to 192.168.1.255".

```bash
R1(config-router)# network 10.0.0.0 0.0.0.3 area 0
```
- Adds the `10.0.0.0/30` network into **OSPF Area 0**. (Wildcard `0.0.0.3` means /30.)

```bash
R1(config-router)# passive gi0/1
```
- Makes the interface `GigabitEthernet0/1` **passive**:  
  - OSPF will advertise this network but **won't send or receive OSPF Hello packets** (no neighbor formation).

---

#### **R2 Configuration:**
```bash
R2> en
R2# conf t
R2(config)# router ospf 1
```
- Same steps: enabling OSPF process 1.

```bash
R2(config-router)# network 10.0.0.0 0.0.0.3 area 0
R2(config-router)# network 10.0.0.4 0.0.0.3 area 0
```
- Adds two `/30` networks:
  - `10.0.0.0/30`
  - `10.0.0.4/30`
- R2 will be a neighbor both to R1 and R3 over these subnets.

---

#### **R3 Configuration:**
```bash
R3> en
R3# conf t
R3(config)# router ospf 1
```
- OSPF instance 1 on R3.

```bash
R3(config-router)# network 10.0.0.4 0.0.0.3 area 0
```
- Joins the 10.0.0.4/30 network.

```bash
R3(config-router)# passive s0/0/0
```
- Makes serial interface `s0/0/0` passive — no OSPF neighbor formation on it.

```bash
R3(config-router)# exit
R3(config)# do show ip route 
```
- `do show ip route` lets you view the routing table **even inside config mode**.

```bash
R3(config)# ip route 0.0.0.0 0.0.0.0 s0/0/0
```
- Adds a **static default route** (`0.0.0.0/0`) pointing to serial interface `s0/0/0`.

```bash
R3(config)# router ospf 1
R3(config-router)# default-information originate
```
- Tells R3 to **advertise** the default route into OSPF.

```bash
R3(config-router)# redistribute static
```
- Injects **static routes** (like the default route) into OSPF so others learn it.

---

#### **Testing on R1 and R2:**
```bash
! test
R1(config)# do show ip route 
R2(config)# do show ip route 
```
- You check that R1 and R2 have learned routes via OSPF.

---

#### **R4 (renamed ISP) Configuration:**
```bash
R4> en
R4# conf t
R4(config)# hostname ISP
```
- Changes the router name from `R4` to `ISP`.

```bash
ISP(config)# ip route 0.0.0.0 0.0.0.0 s0/0/0
```
- ISP router adds a static default route pointing out of serial 0/0/0.

---
### **Summary of What This Does:**
- R1, R2, and R3 form an OSPF Area 0.
- R3 learns a default route from ISP and redistributes it into OSPF.
- R1 and R2 can now reach "the internet" via R3.
- Passive interfaces are set to prevent unnecessary OSPF traffic on certain interfaces.

---

Would you like me to also draw a quick **network diagram** showing the topology this creates? 🚀  
It'll make it even clearer!