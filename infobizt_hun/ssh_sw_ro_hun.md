# SSH on R and SW



```bash
R1> en
R1# conf t
R1(config)# 
R1(config)# ip domain-name cisco.com
R1(config)# username cisco privilege 15 secret cisco
R1(config)# crypto key zeroize rsa
R1(config)# crypto key generate rsa
    modulus [512]:     1024
R1(config)# ip ssh version 2
R1(config)# ip ssh time-out 60
R1(config)# ip ssh authentication-retries 2
R1(config)# line vty 0 4
R1(config-line)# 
R1(config-line)# login local
R1(config-line)# transport input ssh
R1(config-line)# privilege level 15
R1(config-line)# exit
R1(config)# 


Switch>
Switch#
Switch(config)# 
Switch(config)# hostname S1
S1(config)# 
S1(config)# ip domain-name cisco.com
S1(config)# crypto key zeroize rsa
S1(config)# crypto key generate rsa
    modulus [512]:     1024
S1(config)# ip ssh version 2
S1(config)# ip ssh time-out 60
S1(config)# ip ssh authentication-retries 2
S1(config)# username cisco privilege 15 secret cisco
S1(config)# 
S1(config)# line vty 0 15
S1(config-line)# 
S1(config-line)#  login local
S1(config-line)# transport input ssh
S1(config-line)# privilege level 15
S1(config-line)# exit
S1(config)# 
S1(config)# int vlan 1
S1(config-if)# ip address 192.168.1.2 255.255.255.0
S1(config-if)# no shutdown
S1(config-if)# exit
S1(config)#  ip default-gateway 192.168.1.1

! test: ssh -l cisco 192.168.1.1 (router)  from PC1
! test: ssh -l cisco 192.168.1.2  (switch) from PC1
```

Perfect — you're doing **everything correctly**! Here's a full explanation of this new block:

---

# 🔥 What you configured:

## **On R1 (Router):**
```bash
R1(config)# ip domain-name cisco.com
```
- Set domain name needed for SSH key generation.

```bash
R1(config)# username cisco privilege 15 secret cisco
```
- Create a **local user** `cisco` with **privilege level 15** (full admin rights) and a secret (encrypted) password `cisco`.

```bash
R1(config)# crypto key zeroize rsa
R1(config)# crypto key generate rsa
    modulus [512]: 1024
```
- **Delete** any existing RSA keys (good practice when reconfiguring).
- **Generate new RSA keys** (1024 bits) for SSH encryption.

```bash
R1(config)# ip ssh version 2
R1(config)# ip ssh time-out 60
R1(config)# ip ssh authentication-retries 2
```
- Force using **SSH version 2** (more secure).
- Set **timeout** for SSH sessions to 60 seconds.
- Allow **only 2 retries** for login attempts.

```bash
R1(config)# line vty 0 4
R1(config-line)# login local
R1(config-line)# transport input ssh
R1(config-line)# privilege level 15
```
- Configure the VTY lines:
  - Use **local usernames/passwords**.
  - Only **SSH** allowed (no Telnet).
  - Logged-in users get **full privileges** immediately.

---

## **On S1 (Switch):**
```bash
Switch(config)# hostname S1
```
- Set the switch name to S1.

```bash
S1(config)# ip domain-name cisco.com
S1(config)# crypto key zeroize rsa
S1(config)# crypto key generate rsa
    modulus [512]: 1024
S1(config)# ip ssh version 2
S1(config)# ip ssh time-out 60
S1(config)# ip ssh authentication-retries 2
```
- **Same SSH settings** like on R1.

```bash
S1(config)# username cisco privilege 15 secret cisco
```
- Create user for SSH login.

```bash
S1(config)# line vty 0 15
S1(config-line)# login local
S1(config-line)# transport input ssh
S1(config-line)# privilege level 15
```
- Configure VTY lines 0–15 for SSH access only (notice: **0-15**, so 16 lines available).

```bash
S1(config)# int vlan 1
S1(config-if)# ip address 192.168.1.2 255.255.255.0
S1(config-if)# no shutdown
```
- Assign management IP to VLAN 1 (you had VLAN 50 earlier — this could be a small difference depending on your plan).
- Enable the interface.

```bash
S1(config)# ip default-gateway 192.168.1.1
```
- Set **default gateway** so the switch can reach devices outside its subnet.

---

# 🧠 **Tests you plan:**

- SSH **from PC1 to R1**:
  ```bash
  ssh -l cisco 192.168.1.1
  ```
- SSH **from PC1 to S1**:
  ```bash
  ssh -l cisco 192.168.1.2
  ```

✅ If everything is right, you should get prompted for a password (`cisco`), and after successful login, you land in privileged mode (#).

---

# **Quick tips:**
- If you configured **VLAN 50** earlier for management, consider putting the switch IP on **VLAN 50** instead of VLAN 1, to match your plan.
- On switches, **VLAN 1** is default, but best practice is to use a **dedicated management VLAN** (like VLAN 50).

Example:
```bash
S1(config)# int vlan 50
S1(config-if)# ip address 192.168.1.2 255.255.255.0
S1(config-if)# no shutdown
S1(config)# ip default-gateway 192.168.1.1
```

---

# **Summary:**
- You enabled **SSH remote management** with **high security**.
- You secured **VTY lines** to only allow **SSH login**.
- You made sure **proper user accounts** and **encryption keys** are in place.

---

Would you also want me to show you a **small checklist** you can always use for "Quick SSH Setup on any Cisco device"? 🚀 (Could be super useful for labs and exams!)  
If yes, I'll make you a 10-step bullet-point version! 🎯