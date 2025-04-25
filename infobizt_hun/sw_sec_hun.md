# Switch port security
# STP = Spanning Tree Protocol

```bash
S1> en, conf t
S1(config)# int range fa0/3-24, gi0/2
S1(config-if-range)# shutdown
S1(config-if-range)# exit
S1(config)# spanning-tree vlan 1,10,20,50,100 root primary
S1(config)# int range fa0/1-2, gi0/1
S1(config-if-range)# switchport trunk native vlan 100
S1(config-if-range)# exit

S2> en, conf t
S2(config)# int range fa0/2-21, gi0/1-2
S2(config-if-range)# shutdown
S2(config-if-range)# exit
S2(config)# spanning-tree vlan 1,10,20,50,100 root secondary
S2(config)# int range fa0/22-24, fa0/1
S2(config-if-range)# switchport trunk native vlan 100
S2(config-if-range)# exit

S3> en, conf t
S3(config)# int range fa0/1, fa0/3-21, gi0/1-2
S3(config-if-range)# shutdown
S3(config-if-range)# exit
S3(config)# int range fa0/2, fa0/22-24
S3(config-if-range)# switchport trunk native vlan 100
S3(config-if-range)# exit

S4> en, conf t
S4(config)# int range fa0/2-21, fa0/24,  gi0/1-2
S4(config-if-range)# shutdown
S4(config-if-range)# exit
S4(config)# int fa0/1
S4(config-if)# switchport port-security
S4(config-if)# switchport port-security max 1
S4(config-if)# switchport port-security mac-address sticky
S4(config-if)# switchport port-security violation shutdown
S4(config-if)# spanning-tree portfast
S4(config-if)# spanning-tree bpduguard enable
S4(config-if)# exit
S4(config)# int range fa0/23-24
S4(config-if-range)# switchport trunk native vlan 100
S4(config-if-range)# exit

S5> en
S5# configure term
S5(config)# int range fa0/3-21, fa0/24,  gi0/1-2
S5(config-if-range)# shutdown
S5(config-if-range)# exit
S5(config)# int range fa0/1-2
S5(config-if-range)# switchport port-security
S5(config-if-range)# switchport port-security max 1
S5(config-if-range)# switchport port-security mac-address sticky
S5(config-if-range)# switchport port-security violation shutdown
S5(config-if-range)# spanning-tree portfast
S5(config-if-range)# spanning-tree bpduguard enable
S5(config-if-range)# exit
S5(config)# int range fa0/22-23
S5(config-if-range)# switchport trunk native vlan 100
S5(config-if-range)# exit
```

Got it — you want me to **explain** these commands! Let’s go carefully, device by device. I'll keep it clean and logical:

---

### General concepts:
- **Port Security**: Protects access ports by limiting and learning MAC addresses.
- **STP (Spanning Tree Protocol)**: Prevents loops in a switching network.
- **Native VLAN**: The VLAN that is **untagged** on a trunk port.

---

# **S1 configuration:**

```bash
S1> en, conf t
```
- `en`: Enable privileged exec mode.
- `conf t`: Enter global configuration mode.

```bash
S1(config)# int range fa0/3-24, gi0/2
S1(config-if-range)# shutdown
```
- Select FastEthernet 0/3 to 0/24 and GigabitEthernet 0/2 interfaces.
- **Shutdown** (disable) these ports to control which ports are active.

```bash
S1(config)# spanning-tree vlan 1,10,20,50,100 root primary
```
- This switch will become the **primary Root Bridge** for VLANs 1,10,20,50,100 (lowest bridge priority).

```bash
S1(config)# int range fa0/1-2, gi0/1
S1(config-if-range)# switchport trunk native vlan 100
```
- Configure ports fa0/1-2 and gi0/1 as trunks.
- **Native VLAN is 100** (untagged VLAN traffic on trunks).

---

# **S2 configuration:**

```bash
S2> en, conf t
S2(config)# int range fa0/2-21, gi0/1-2
S2(config-if-range)# shutdown
```
- Shutdown access ports fa0/2 to fa0/21 and gigabit ports gi0/1-2.

```bash
S2(config)# spanning-tree vlan 1,10,20,50,100 root secondary
```
- Make this switch the **secondary Root Bridge** (used if primary switch fails).

```bash
S2(config)# int range fa0/22-24, fa0/1
S2(config-if-range)# switchport trunk native vlan 100
```
- Set these ports to trunking with native VLAN 100.

---

# **S3 configuration:**

```bash
S3> en, conf t
S3(config)# int range fa0/1, fa0/3-21, gi0/1-2
S3(config-if-range)# shutdown
```
- Shutdown these access ports.

```bash
S3(config)# int range fa0/2, fa0/22-24
S3(config-if-range)# switchport trunk native vlan 100
```
- Configure trunks with native VLAN 100.

---

# **S4 configuration:**

```bash
S4> en, conf t
S4(config)# int range fa0/2-21, fa0/24, gi0/1-2
S4(config-if-range)# shutdown
```
- Shutdown unnecessary ports.

```bash
S4(config)# int fa0/1
```
- Configure access port fa0/1 specifically:

```bash
S4(config-if)# switchport port-security
```
- Enable **port security** on fa0/1.

```bash
S4(config-if)# switchport port-security max 1
```
- Allow only **1 MAC address** on this port.

```bash
S4(config-if)# switchport port-security mac-address sticky
```
- **Learn** and **stick** (save) the first MAC address automatically.

```bash
S4(config-if)# switchport port-security violation shutdown
```
- If a security violation occurs (another MAC detected), **shutdown the port**.

```bash
S4(config-if)# spanning-tree portfast
```
- Enable **PortFast**: immediately transition port to forwarding (no STP delay).

```bash
S4(config-if)# spanning-tree bpduguard enable
```
- If this port receives a **BPDU** (bridge protocol data unit), **error-disable** the port (because it's supposed to connect to an end device, not a switch).

```bash
S4(config)# int range fa0/23-24
S4(config-if-range)# switchport trunk native vlan 100
```
- Configure trunks for VLAN 100.

---

# **S5 configuration:**

```bash
S5> en
S5# configure term
S5(config)# int range fa0/3-21, fa0/24, gi0/1-2
S5(config-if-range)# shutdown
```
- Shutdown access ports.

```bash
S5(config)# int range fa0/1-2
```
- Configure fa0/1 and fa0/2:

```bash
S5(config-if-range)# switchport port-security
S5(config-if-range)# switchport port-security max 1
S5(config-if-range)# switchport port-security mac-address sticky
S5(config-if-range)# switchport port-security violation shutdown
S5(config-if-range)# spanning-tree portfast
S5(config-if-range)# spanning-tree bpduguard enable
```
- **Same** port-security and STP settings as on S4 fa0/1.

```bash
S5(config)# int range fa0/22-23
S5(config-if-range)# switchport trunk native vlan 100
```
- Configure trunks with native VLAN 100.

---

# **Summary Table:**

| Command | Meaning |
|:---|:---|
| `shutdown` | Disable interface |
| `switchport trunk native vlan 100` | Set VLAN 100 as native VLAN for trunk |
| `spanning-tree vlan X root primary` | Set switch as root bridge |
| `spanning-tree vlan X root secondary` | Backup root bridge |
| `switchport port-security` | Enable port security |
| `switchport port-security max 1` | Only one device allowed |
| `switchport port-security mac-address sticky` | Auto-learn MAC address |
| `switchport port-security violation shutdown` | Shutdown on violation |
| `spanning-tree portfast` | Skip STP states (for hosts) |
| `spanning-tree bpduguard enable` | Disable port if BPDU is received |

---

Would you also like me to **draw a simple diagram** of how these switches are likely connected based on this config? 📈  
(If yes, it'll make the big picture even easier to see.)
