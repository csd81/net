# Radius
Server1: AAA 
key: Radius123


```bash
R2> enable
R2# conf t
R2(config)# 
R2(config)# username Admin1 secret Admin123
R2(config)# radius-server host 192.168.1.8
R2(config)# radius-server key Radius123
R2(config)# aaa new-model
R2(config)# aaa authentication login default group radius  local
R2(config)# 
R2(config)#  line console 0
R2(config-line)# login authentication default
R2(config-line)# exit


Test:
User: Admin1
pass: Admin123 
R2>
```


Alright! Let’s go through your **RADIUS** configuration carefully:

---

### 1. **What is RADIUS?**
- **RADIUS** (Remote Authentication Dial-In User Service) is a **network protocol** for **AAA**:
  - Authentication (verify user identity)
  - Authorization (what the user can do)
  - Accounting (record what the user does)
- It **centralizes login control** using a **RADIUS server** (instead of local user accounts).

---

### 2. **Setup in your example**

- **Server1** is the **RADIUS Server**.
  - It is running AAA services.
  - The shared secret (security password) is: **Radius123**.
  - Its IP address is: **192.168.1.8**.

- **User Credentials** stored:
  - Username: `Admin1`
  - Password: `Admin123`

---

### 3. **Commands Explained Step-by-Step**

---

#### a) Move to Privileged EXEC Mode

```bash
R2> enable
R2#
```
- `enable` lets you enter privileged mode (`#` prompt).

---

#### b) Enter Global Configuration Mode

```bash
R2# conf t
R2(config)#
```
- `configure terminal` opens global settings.

---

#### c) Create Local User (Backup)

```bash
R2(config)# username Admin1 secret Admin123
```
- Creates a **local user** with encrypted password.
- It’s a **backup** if the RADIUS server is unreachable.

---

#### d) Set RADIUS Server IP

```bash
R2(config)# radius-server host 192.168.1.8
```
- Tells the router **where the RADIUS server is**.

---

#### e) Set RADIUS Shared Key

```bash
R2(config)# radius-server key Radius123
```
- Defines the **shared secret** used to **encrypt** traffic between router and server.

---

#### f) Enable AAA

```bash
R2(config)# aaa new-model
```
- Activates the AAA system.
- Without this, RADIUS won’t work.

---

#### g) Set up AAA Login Authentication

```bash
R2(config)# aaa authentication login default group radius local
```
- Tells router:
  - Try to **authenticate via RADIUS** first (`group radius`).
  - If RADIUS **fails**, fallback to **local** login (`local`).

---

#### h) Apply AAA to Console Login

```bash
R2(config)# line console 0
R2(config-line)# login authentication default
```
- Configures the console port to **use the "default" AAA method**.

---

#### i) Exit

```bash
R2(config-line)# exit
```
- Exits from console line mode.

---

### 4. **Testing**

When you connect to the router console:

- It will ask for **Username** and **Password**.
- You enter:
  - **Username**: `Admin1`
  - **Password**: `Admin123`
  
Router will **check the RADIUS server** at `192.168.1.8`.
- If RADIUS answers, it authenticates you.
- If RADIUS server is **down**, it uses the **local account**.

---

### 🔥 Quick Summary Table

| Step | Purpose |
|:-----|:--------|
| `enable` | Privileged mode |
| `conf t` | Configuration mode |
| `username` | Local fallback user |
| `radius-server host` | Set RADIUS server IP |
| `radius-server key` | Set shared secret |
| `aaa new-model` | Enable AAA system |
| `aaa authentication login` | Define login method (RADIUS then local) |
| `line console 0` + `login authentication default` | Apply AAA to console |

---

### ✨ Bonus Tip
- **TACACS+** encrypts the entire packet.
- **RADIUS** encrypts only the **password** part.
- RADIUS is very common for Wi-Fi logins and VPNs.

---

Would you like me to also show you the *difference between the old and the newer way* of setting up RADIUS servers on Cisco devices? (New syntax uses `radius server` blocks!) 🚀  
It’s good to know if you are preparing for exams like **CCNA**!