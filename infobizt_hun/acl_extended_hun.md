# extended ACL

```bash
can filter by source destination protocol

access-list 100 permit/deny tcp/udp/ip/icmp host/any/[source ip] host/any/[destination ip] eq [port number]80/443/20/21/22/.../www/dns/ftp

ISP> enable
ISP# configure terminal

ISP(config)# access-list 100 permit host ip host 192.168.1.10 host 192.168.2.11 
ISP(config)# access-list 100 permit tcp any host 192.168.2.11 eq 80
ISP(config)# access-list 100 permit tcp any host 192.168.2.11 eq 443

> implicit deny

ISP(config)# int gi0/1
ISP(config-if)# ip access-group 100 out
ISP(config-if)# exit
ISP(config)#
ISP(config)# no access-list 100
ISP(config)# int gi0/1
ISP(config-if)# no ip access-group 100 out

user Admin1
pass Admin123

R1> enable
R1# configure terminal
R1(config)#
R1(config)# access-list 100 permit tcp 192.168.2.0 0.0.0.255 host 192.168.1.7 eq 21
R1(config)# access-list 100 permit tcp 192.168.2.0 0.0.0.255 host 192.168.1.8 eq 443
R1(config)# int gi0/1
R1(config-if)# ip access-group 100 out
R1(config-if)# exit

```

Alright! Let's break down your **extended ACL example** — super important stuff for real network control.  
I'll explain your commands **line-by-line** and in **simple English**:

---

# 🔥 Extended ACL Basics
- **Can filter:**  
  ➔ **Source IP**  
  ➔ **Destination IP**  
  ➔ **Protocol** (TCP, UDP, ICMP, IP)  
  ➔ **Ports** (like 80, 443, 21, 22, DNS, FTP)  
- **More control** than standard ACLs.

---

# 🧠 Commands Explained

## 📌 Setup on **ISP Router**

```bash
ISP> enable
ISP# configure terminal
```
➡️ Go into privileged exec mode (`enable`) and then into global config mode (`configure terminal`).

---

```bash
ISP(config)# access-list 100 permit ip host 192.168.1.10 host 192.168.2.11
```
✅ **Meaning:**  
- Permit **any IP protocol** traffic (not just TCP/UDP) from **192.168.1.10** to **192.168.2.11**.

---

```bash
ISP(config)# access-list 100 permit tcp any host 192.168.2.11 eq 80
ISP(config)# access-list 100 permit tcp any host 192.168.2.11 eq 443
```
✅ **Meaning:**  
- Allow **TCP** traffic from **any source** to **192.168.2.11** if destination port is:
  - **80** (HTTP)
  - **443** (HTTPS)

---

```bash
> implicit deny
```
✅ **Reminder:**  
- After your rules, there's **always an invisible** `deny all` at the end.
- So if something is not matched by these rules, it gets **blocked**.

---

```bash
ISP(config)# int gi0/1
ISP(config-if)# ip access-group 100 out
```
✅ **Meaning:**  
- Apply ACL 100 to interface **GigabitEthernet0/1**, **outbound** (traffic leaving this interface).

---

### 💥 Deleting ACLs

```bash
ISP(config)# no access-list 100
ISP(config)# int gi0/1
ISP(config-if)# no ip access-group 100 out
```
✅ **Meaning:**  
- **Delete ACL 100**.
- **Remove** the ACL application from interface Gi0/1.

---

## 📌 Setup on **R1 Router**

```bash
user Admin1
pass Admin123
```
➡️ You log into R1 as Admin1.

```bash
R1> enable
R1# configure terminal
```
➡️ Enable mode, then global config mode.

---

```bash
R1(config)# access-list 100 permit tcp 192.168.2.0 0.0.0.255 host 192.168.1.7 eq 21
```
✅ **Meaning:**  
- Permit **TCP** traffic from **192.168.2.0/24** network to **host 192.168.1.7**, only for **port 21** (FTP control).

---

```bash
R1(config)# access-list 100 permit tcp 192.168.2.0 0.0.0.255 host 192.168.1.8 eq 443
```
✅ **Meaning:**  
- Permit **TCP** traffic from **192.168.2.0/24** to **host 192.168.1.8**, only for **port 443** (HTTPS).

---

```bash
R1(config)# int gi0/1
R1(config-if)# ip access-group 100 out
```
✅ **Meaning:**  
- Apply ACL 100 outbound on R1’s GigabitEthernet0/1.

---

# ✨ Summary Table

| Command | Purpose |
|:---|:---|
| `access-list 100 permit ip/tcp/udp ...` | Create extended ACL rules |
| `ip access-group 100 [in/out]` | Apply ACL on an interface |
| `no access-list 100` | Delete ACL |
| `no ip access-group 100 [in/out]` | Remove ACL from interface |
| **implicit deny** | Unmatched traffic is automatically denied |

---

# 🧩 Visual Quick Map

```
[Clients 192.168.2.0/24]
       |
      (R1)
       |
 [Allowed FTP (port 21) to 192.168.1.7]
 [Allowed HTTPS (port 443) to 192.168.1.8]
       |
    [Internet/Other network]
```

---

Would you like a **tiny mini-lab exercise** you can try in Packet Tracer based on this? 🚀 (to practice extended ACLs even deeper!)  
(only 3–5 commands, really fun)