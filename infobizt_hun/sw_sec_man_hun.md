#  allow management access on Switch

```bash
S1> en
S1# conf t
S1(config)# int vlan 50
S1(config-if)# ip add 192.168.1.2   255.255.255.0
S1(config-if)# exit
S1(config)# 
S1(config)# line vty 0 4
S1(config-line)# password cisco 
S1(config-line)# exit
S1(config)# 

S2> en
S2# conf t
S2(config)# int vlan 50
S2(config-if)# ip add 192.168.1.3   255.255.255.0
S2(config-if)# exit
S2(config)# 
S2(config)# line vty 0 4
S2(config-line)# password cisco 
S2(config-line)# exit
S2(config)# 

S3> en
S3# conf t
S3(config)# int vlan 50
S3(config-if)# ip add 192.168.1.4   255.255.255.0
S3(config-if)# exit
S3(config)# 
S3(config)# line vty 0 4
S3(config-line)# password cisco 
S3(config-line)# exit
S3(config)# 

S4> en
S4# conf t
S4(config)# int vlan 50
S4(config-if)# ip add 192.168.1.5   255.255.255.0
S4(config-if)# exit
S4(config)# 
S4(config)# line vty 0 4
S4(config-line)# password cisco 
S4(config-line)# exit
S4(config)# 

S5> en
S5# conf t
S5(config)# int vlan 50
S5(config-if)# ip add 192.168.1.6   255.255.255.0
S5(config-if)# exit
S5(config)# 
S5(config)# line vty 0 4
S5(config-line)# password cisco 
S5(config-line)# exit
S5(config)# 

R1> Admin1 pass: Admin123
R1> en
R1# show running-config
R1# configure terminal
R1(config)# accest-list 100 permit ip host 192.168.1.10 any
R1(config)# line vty 
R1(config)# line vty 0 4
R1(config-line)# accest-class 100 in
R1(config-line)# exit
R1(config)# 

! try to SSH from PC1 to R1
```



Alright, this set of commands is about **allowing management access** to the switches (S1–S5) **and** setting up **remote access control** on the router (R1). Let's explain it clearly:

---

# **What you're doing on each switch (S1–S5):**

```bash
S1(config)# int vlan 50
S1(config-if)# ip address 192.168.1.2 255.255.255.0
```
- Create and configure **SVI (Switched Virtual Interface)** for **VLAN 50**.
- Assign it an IP address (e.g., 192.168.1.2 for S1).
- This makes the switch **reachable** on the network for **management** (like Telnet or SSH).

```bash
S1(config)# line vty 0 4
S1(config-line)# password cisco 
```
- Configure **VTY lines** 0 to 4 (virtual terminal lines for remote access).
- Set a password (`cisco`) for Telnet/SSH login.

✅ **Now you can remotely connect (Telnet) to the switch** using its VLAN 50 IP address.

---

# **What you’re doing on the router (R1):**

```bash
R1> Admin1 pass: Admin123
R1> en
R1# show running-config
```
- Logging in and checking the running configuration.

```bash
R1# configure terminal
R1(config)# access-list 100 permit ip host 192.168.1.10 any
```
- Create **Access Control List 100**:
  - **Permit** traffic from **host 192.168.1.10** (PC1) to **any destination**.

```bash
R1(config)# line vty 0 4
R1(config-line)# access-class 100 in
```
- Apply that **ACL 100** **to incoming connections** on VTY lines.
- **Result**: Only 192.168.1.10 (PC1) can **remote-access** (Telnet/SSH) to R1.

---

# **Summary Table:**

| Device | Configuration Purpose |
|:---|:---|
| Switches (S1–S5) | Management IP address via VLAN 50 and set VTY password |
| Router (R1) | Restrict remote access (VTY) only to PC1 (192.168.1.10) |

---

# **About your last comment:**
> try to SSH from PC1 to R1

✅ **If configured correctly**, PC1 should be able to SSH to R1 because it is allowed by the ACL.

But:
- You **must enable SSH** on R1 first (you didn’t show SSH setup yet).
- R1 needs a hostname, domain-name, local username/password, and generate RSA keys.

Example SSH setup on R1:
```bash
R1(config)# hostname R1
R1(config)# ip domain-name example.com
R1(config)# username Admin1 password Admin123
R1(config)# crypto key generate rsa
R1(config)# line vty 0 4
R1(config-line)# login local
R1(config-line)# transport input ssh
```

Otherwise, if you didn’t configure SSH yet, R1 will still only accept **Telnet** connections — **not SSH**.

---

Would you like me to also show **a full working setup to enable SSH** on R1 so it’s ready for the PC to connect? 🚀  
(It's just a few extra lines you can paste in.)









