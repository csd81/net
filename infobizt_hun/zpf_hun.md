
# Zone-based policy firewall
```bash
! now we get license
ISP> en 
ISP# conf terminal
ISP(config)# license boot module c2900 technology-package security k9
    [yes] yes
ISP(config)# do copy running start
! reboot, now we have security features...

ISP(config)# do show version
    ... securityk9 evaluation

! now we configure ZPF

```bash
ISP(config)#
ISP(config)# zone security in-zone
ISP(config-sec-zone)# exit
ISP(config)# zone security out-zone
ISP(config-sec-zone)# exit
ISP(config)#
ISP(config)# access-list 100 permit ip 192.168.2.0  0.0.0.255 any
ISP(config)# class-map type inspect match-all in-net-class-map
ISP(config-cmap)# 
ISP(config-cmap)#  match access-group 100
ISP(config-cmap)# exit
ISP(config)# policy-map type inspect in-2-out-pmap 
ISP(config-pmap)# 
ISP(config-pmap)# class type inspect in-net-class-map
ISP(config-pmap-c)# 
ISP(config-pmap-c)# *inspect* / drop / pass 
ISP(config-pmap-c)# exit
ISP(config-pmap)# exit
ISP(config)# zone-pair security in-2-out-zpair source in-zone destination out-zone
ISP(config-sec-zone-pair)# 
ISP(config-sec-zone-pair)#  service-policy type inspect in-2-out-pmap 
ISP(config-sec-zone-pair)# exit
ISP(config)# int gi0/1
ISP(config-if)# 
ISP(config-if)# zone-member security in-zone
ISP(config-if)# exit
ISP(config)# int s0/0/0
ISP(config-if)# 
ISP(config-if)# zone-member security out-zone
ISP(config-if)# exit
ISP(config)#
ISP(config)# do show policy-map type inspect zone-pair sessions
```

You're doing an excellent job setting up a **Zone-Based Policy Firewall (ZPF)** on the Cisco router! Here's a quick breakdown of what you did step-by-step, and a small clarification in case you want even more control or troubleshooting:

---

### 1. **Enable Security License**
```bash
license boot module c2900 technology-package securityk9
```
- You enabled the **Security Technology Package** on the router.
- After a reload, `show version` confirms `securityk9 evaluation`.

---

### 2. **Create Zones**
```bash
zone security in-zone
zone security out-zone
```
- Defined two zones: `in-zone` for LAN (inside) and `out-zone` for WAN (outside).

---

### 3. **Create ACL for Traffic**
```bash
access-list 100 permit ip 192.168.2.0 0.0.0.255 any
```
- Allows traffic from the inside subnet (192.168.2.0/24) to anywhere.

---

### 4. **Class Map**
```bash
class-map type inspect match-all in-net-class-map
 match access-group 100
```
- Creates a class map that matches the traffic permitted by ACL 100.

---

### 5. **Policy Map**
```bash
policy-map type inspect in-2-out-pmap
 class type inspect in-net-class-map
  inspect
```
- Applies the `inspect` action (allow stateful inspection) for matching traffic.
- `inspect` ensures return traffic is allowed dynamically.

---

### 6. **Zone-Pair**
```bash
zone-pair security in-2-out-zpair source in-zone destination out-zone
 service-policy type inspect in-2-out-pmap
```
- Defines a zone-pair between `in-zone` and `out-zone`.
- Associates the policy map with the zone-pair.

---

### 7. **Assign Interfaces to Zones**
```bash
int gi0/1
 zone-member security in-zone

int s0/0/0
 zone-member security out-zone
```
- LAN interface (gi0/1) assigned to `in-zone`.
- WAN interface (s0/0/0) assigned to `out-zone`.

---

### 8. **Verify Active Sessions**
```bash
do show policy-map type inspect zone-pair sessions
```
- Displays active sessions matched and allowed by the inspection policy.

---

## ⚡ Small Tip
- If you want to allow outside-initiated traffic (like VPNs or hosting services), you would need an **additional zone-pair** from `out-zone → in-zone` with its own inspection/pass rules or at least passive ACLs.
- Also, remember: **by default**, traffic **not explicitly allowed between zones is dropped**.

---

Would you also like me to show you an example of how to **add return rules** (like allowing outside VPN connections to the inside), or **how to make logging better** for troubleshooting ZBFW? 🚀  
(It's very useful if you're studying or simulating real-world setups!)