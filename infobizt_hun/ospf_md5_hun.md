# OSPF - MD5

```bash
R1>
R1# conf t
R1(config)# router ospf 1
R1(config-router)# area 0 authentication message-digest
R1(config-router)# exit
R1(config)# int s0/0/0
R1(config-if)# ip ospf message-digest-key 1 md5 cisco123
R1(config-if)# exit

R2>
R2# conf t
R2(config)# router ospf 1
R2(config-router)# area 0 authentication message-digest
R2(config-router)# exit
R2(config)# int s0/0/0
R2(config-if)# 
R2(config-if)# ip ospf message-digest-key 1 md5 cisco123
R2(config-if)# exit
R2(config)# 
R2(config)# int s0/0/1
R2(config-if)# 
R2(config-if)# ip ospf message-digest-key 1 md5 cisco123
R2(config-if)# exit
R3(config)# 

R3> en
R3# conf t
R3(config)# router ospf 1
R3(config-router)# area 0 authentication message-digest
R3(config-router)# exit
R3(config)# int s0/0/1
R3(config-if)# ip ospf message-digest-key 1 md5 cisco123
R3(config-if)# exit
R3(config)# 
```

Alright, you're setting up **OSPF with MD5 authentication** here — nice work!  
Let’s walk through exactly what’s happening:

---

### **Explanation:**

#### **Step-by-step per Router:**

---

### **On R1:**
```bash
R1> 
R1# conf t
R1(config)# router ospf 1
```
- Enters OSPF process 1 configuration.

```bash
R1(config-router)# area 0 authentication message-digest
```
- Enables **MD5 authentication** for all interfaces in **Area 0**.

```bash
R1(config-router)# exit
R1(config)# int s0/0/0
R1(config-if)# ip ospf message-digest-key 1 md5 cisco123
```
- On interface `Serial0/0/0`, sets:
  - **Key ID:** `1`
  - **Algorithm:** `MD5`
  - **Password:** `cisco123`
- OSPF neighbors must have the same key ID and password to form a neighbor relationship.

---

### **On R2:**
```bash
R2> 
R2# conf t
R2(config)# router ospf 1
R2(config-router)# area 0 authentication message-digest
```
- Same: OSPF instance 1, MD5 auth in Area 0.

```bash
R2(config-router)# exit
R2(config)# int s0/0/0
R2(config-if)# ip ospf message-digest-key 1 md5 cisco123
```
- Configures MD5 key on interface `s0/0/0`.

```bash
R2(config)# int s0/0/1
R2(config-if)# ip ospf message-digest-key 1 md5 cisco123
```
- Also configures MD5 key on interface `s0/0/1`.
- This way, R2 can authenticate with both R1 and R3.

---

### **On R3:**
```bash
R3> en
R3# conf t
R3(config)# router ospf 1
R3(config-router)# area 0 authentication message-digest
```
- Same: OSPF process 1, Area 0, MD5 authentication.

```bash
R3(config-router)# exit
R3(config)# int s0/0/1
R3(config-if)# ip ospf message-digest-key 1 md5 cisco123
```
- Sets up MD5 authentication on `s0/0/1` (which connects back to R2).

---

### **Summary of What This Achieves:**
- OSPF between R1, R2, and R3 is **secured with MD5 hashing**.
- **Neighbors will not form** unless the MD5 password matches on both ends of each link.
- MD5 ensures:
  - Neighbor authenticity (no fake routers).
  - Integrity (no tampering of OSPF packets).

---

✅ **Important:**  
- The **key number** (here `1`) must match on each side of a link.
- The **password** must match exactly (case-sensitive).

---

Would you also like me to show how to **verify** that the authentication is working correctly (with commands like `show ip ospf neighbor`, `debug ip ospf adj`)? 🔍  
It’s super useful to confirm everything's good!