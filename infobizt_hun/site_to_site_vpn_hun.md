# Site-2-Site IPsec VPN

# parameters (R1-R3)
- policy number: 10
- KMP:           ISAKMP
- crypto:        AES-256
- hash:          SHA-1
- auth type:     pre-share
- DH group:      5
- shared key:    t5nn3l

# parameters        R1              R3
transform-set       VPN-SET         VPN-SET
allowed on 100 ACL  1,3,4 networks  80.90.10.0/28
crypto map          VPN-MAP         VPN-MAP
SA on crypto map    ipsec-isakmp    ipsec-isakmp

```bash
! license boot module needed.

R1> enable
R1# conf t
R1(config)# crypto isakmp policy 10
R1(config-isakmp)# hash sha
R1(config-isakmp)# authentication pre-share
R1(config-isakmp)# group 5
R1(config-isakmp)# lifetime 86400
R1(config-isakmp)# encryption aes 256
R1(config-isakmp)# exit
R1(config)# 
R1(config)# crypto isakmp key t5nn3l address 10.0.0.5
R1(config)# 
R1(config)# crypto ipsec transform-set VPN-SET esp-aes esp-sha-hmac
R1(config)# crypto map VPN-MAP 10 ipsec-isakmp
R1(config-crypto-map)# 
R1(config-crypto-map)# set peer  10.0.0.5
R1(config-crypto-map)# set transform-set VPN-SET
R1(config-crypto-map)# match address 100
R1(config-crypto-map)# exit
R1(config)# 
R1(config)# access-list 100 permit ip 192.168.1.0   0.0.0.255    80.90.10.0   0.0.0.15
R1(config)# access-list 100 permit ip 192.168.3.0   0.0.0.255    80.90.10.0   0.0.0.15
R1(config)# access-list 100 permit ip 192.168.4.0   0.0.0.255    80.90.10.0   0.0.0.15
R1(config)# interface s0/0/0 
R1(config-if)# 
R1(config-if)#  crypto map  VPN-MAP
R1(config-if)# exit
R1(config)# 
R1(config)# do show crypto ipsec sa
R1(config)# exit
R1#  show crypto ipsec sa

R3> enable
R3# conf t
R3(config)# crypto isakmp policy 10
R3(config-isakmp)# hash sha
R3(config-isakmp)# authentication pre-share
R3(config-isakmp)# group 5
R3(config-isakmp)# lifetime 86400
R3(config-isakmp)# encryption aes 256
R3(config-isakmp)# exit
R3(config)# 
R3(config)# crypto isakmp key t5nn3l address 10.0.0.1
R3(config)# 
R3(config)# crypto ipsec transform-set VPN-SET esp-aes esp-sha-hmac
R3(config)# crypto map VPN-MAP 10 ipsec-isakmp
R3(config-crypto-map)# 
R3(config-crypto-map)# set peer  10.0.0.1
R3(config-crypto-map)# set transform-set VPN-SET
R3(config-crypto-map)# match address 100
R3(config-crypto-map)# exit
R3(config)# 
R3(config)# access-list 100 permit ip     80.90.10.0   0.0.0.15 192.168.1.0   0.0.0.255
R3(config)# access-list 100 permit ip     80.90.10.0   0.0.0.15 192.168.3.0   0.0.0.255
R3(config)# access-list 100 permit ip     80.90.10.0   0.0.0.15 192.168.4.0   0.0.0.255
R3(config)# interface s0/0/1
R3(config-if)# 
R3(config-if)#  crypto map  VPN-MAP
R3(config-if)# exit
R3(config)# 
R3(config)# access-list 100 permit ip     192.168.2.0   0.0.0.255 192.168.1.0   0.0.0.255
R3(config)# access-list 100 permit ip     192.168.2.0   0.0.0.255 192.168.3.0   0.0.0.255
R3(config)# access-list 100 permit ip     192.168.2.0   0.0.0.255 192.168.4.0   0.0.0.255
R3(config)# 
R3(config)# exit
R3#  show crypto ipsec sa
```

Sure! Let’s break this down carefully.

You are configuring a **Site-to-Site IPsec VPN** between **R1** and **R3**, based on this plan:

| Parameter      | Value |
|----------------|-------|
| ISAKMP policy  | 10    |
| Encryption     | AES-256 |
| Hash algorithm | SHA-1 |
| Authentication | Pre-shared key (`t5nn3l`) |
| DH Group       | Group 5 (1536-bit MODP group) |
| Transform-set  | `VPN-SET` (ESP with AES and SHA HMAC) |
| Crypto map     | `VPN-MAP` |
| Traffic ACL    | 100 (defines which traffic gets encrypted) |
| Lifetime       | 86400 seconds (1 day) |

---

### **Step-by-step explanation:**

---

**On R1:**

```bash
R1> enable
R1# conf t
```
- Go into privileged EXEC and then global configuration mode.

```bash
crypto isakmp policy 10
```
- Create **ISAKMP policy** 10 (Phase 1 parameters for key exchange).

```bash
hash sha
authentication pre-share
group 5
lifetime 86400
encryption aes 256
```
- Configure:
  - Hashing with SHA-1,
  - Authentication using a pre-shared key,
  - Diffie-Hellman group 5 for key exchange,
  - Lifetime of 86400 seconds,
  - AES-256 encryption.

```bash
crypto isakmp key t5nn3l address 10.0.0.5
```
- Set the **pre-shared key** `t5nn3l` for peer IP `10.0.0.5` (R3).

---

```bash
crypto ipsec transform-set VPN-SET esp-aes esp-sha-hmac
```
- Define **IPsec transform set** named `VPN-SET` using:
  - ESP (Encapsulating Security Payload) with AES encryption,
  - ESP with SHA-1 for HMAC integrity.

```bash
crypto map VPN-MAP 10 ipsec-isakmp
set peer 10.0.0.5
set transform-set VPN-SET
match address 100
```
- Create a **crypto map**:
  - Numbered `10`, type `ipsec-isakmp`,
  - Peer IP set to 10.0.0.5 (R3),
  - Use the transform set `VPN-SET`,
  - Match interesting traffic based on **ACL 100**.

---

```bash
access-list 100 permit ip 192.168.1.0 0.0.0.255 80.90.10.0 0.0.0.15
access-list 100 permit ip 192.168.3.0 0.0.0.255 80.90.10.0 0.0.0.15
access-list 100 permit ip 192.168.4.0 0.0.0.255 80.90.10.0 0.0.0.15
```
- ACL 100 specifies the traffic to encrypt:
  - From internal networks (192.168.1.0/24, 192.168.3.0/24, 192.168.4.0/24),
  - To the 80.90.10.0/28 network (the remote site network behind R3).

---

```bash
interface s0/0/0
crypto map VPN-MAP
```
- Apply the **crypto map** to the serial interface `s0/0/0` (the interface that faces the WAN/internet).

---

```bash
do show crypto ipsec sa
```
- Check the **IPsec Security Associations (SAs)** to verify the tunnel status.

---

**On R3:**

Same logic, but "flipped" sides:

```bash
R3> enable
R3# conf t
```
- Go into privileged EXEC and global configuration mode.

```bash
crypto isakmp policy 10
hash sha
authentication pre-share
group 5
lifetime 86400
encryption aes 256
```
- Same ISAKMP policy settings.

```bash
crypto isakmp key t5nn3l address 10.0.0.1
```
- Set the **pre-shared key** for the peer **10.0.0.1** (R1).

---

```bash
crypto ipsec transform-set VPN-SET esp-aes esp-sha-hmac
crypto map VPN-MAP 10 ipsec-isakmp
set peer 10.0.0.1
set transform-set VPN-SET
match address 100
```
- Create crypto map, set peer (R1's public IP 10.0.0.1), and match interesting traffic.

---

```bash
access-list 100 permit ip 80.90.10.0 0.0.0.15 192.168.1.0 0.0.0.255
access-list 100 permit ip 80.90.10.0 0.0.0.15 192.168.3.0 0.0.0.255
access-list 100 permit ip 80.90.10.0 0.0.0.15 192.168.4.0 0.0.0.255
```
- ACL 100 on R3: traffic from **its own network** (80.90.10.0/28) going to R1’s internal networks.

```bash
interface s0/0/1
crypto map VPN-MAP
```
- Apply the crypto map to R3's WAN-facing interface `s0/0/1`.

---

```bash
access-list 100 permit ip 192.168.2.0 0.0.0.255 192.168.1.0 0.0.0.255
access-list 100 permit ip 192.168.2.0 0.0.0.255 192.168.3.0 0.0.0.255
access-list 100 permit ip 192.168.2.0 0.0.0.255 192.168.4.0 0.0.0.255
```
- Additional ACL entries, allowing R3's internal network (192.168.2.0/24) to reach R1’s internal networks. (This suggests that behind R3, 80.90.10.0/28 and 192.168.2.0/24 are both used.)

---

```bash
show crypto ipsec sa
```
- View the Security Associations on R3.

---

### **Summary Diagram of the Setup**

```
 [192.168.1.0/24]     [R1] ------- IPsec VPN Tunnel ------- [R3]    [80.90.10.0/28, 192.168.2.0/24]
 [192.168.3.0/24]  (10.0.0.1)                            (10.0.0.5) [Internal networks]
 [192.168.4.0/24]
```

- VPN protected traffic: internal subnets via WAN (public addresses 10.0.0.1 ↔ 10.0.0.5).

---

Would you also like a simple packet flow walkthrough (how the VPN gets established when a packet is sent)? 🚀  
It really helps understand the process fully!