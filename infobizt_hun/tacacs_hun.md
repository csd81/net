# TACACS+

SRV1:
Services:AAA 
Key: Tacacs123
Client IP: 192.168.??

USERS:
Username: Admin2
Password: Admin123

```bash
R1> enable
R1# conf t
R1(config)# 
R1(config)# username Admin2 secet Admin123
R1(config)# aaa new-model
R1(config)# tacacs-server host 192.168.1.7
R1(config)# tacacs-server key Tacacs123
R1(config)# aaa authentication login default group tacacs+ local
R1(config)# line console 0
R1(config-line)# login authentication default
R1(config-line)# exit

test it: Username, Password
```


Sure! Let me explain everything clearly:

---

### 1. **What is TACACS+?**
TACACS+ (Terminal Access Controller Access-Control System Plus) is a **network protocol** used for **AAA**:  
- **Authentication** (verify user identity)  
- **Authorization** (control what they can do)  
- **Accounting** (track what they do)  

It **centralizes** user management on a **TACACS+ server** instead of configuring usernames/passwords on each device.

---

### 2. **Setup in Your Example**

- **SRV1** is the **TACACS+ Server**.  
  - Services running: **AAA** (Authentication, Authorization, Accounting).
  - Server key (shared secret): **Tacacs123**.
  - Server IP address: **192.168.??** (the question mark probably should be filled, like `192.168.1.7`).

- **USERS** configured in TACACS+ server:
  - Username: `Admin2`
  - Password: `Admin123`

---

### 3. **Router Configuration (R1)**

Let's walk through the commands:

| Command | Meaning |
|:--------|:--------|
| `username Admin2 secret Admin123` | (local) user fallback (optional) if TACACS+ fails. |
| `aaa new-model` | Enable the new **AAA** system. |
| `tacacs-server host 192.168.1.7` | Tell the router the IP of the TACACS+ server. |
| `tacacs-server key Tacacs123` | Set the shared secret to match the server’s key. |
| `aaa authentication login default group tacacs+ local` | Set **authentication**: first try **TACACS+**, fallback to **local** if server fails. |
| `line console 0` | Enter console line settings. |
| `login authentication default` | Tell console login to use the **default AAA method**. |

---

### 4. **How to Test**

- Go to console access (connect to R1 physically or in Packet Tracer).
- It will now **ask for a Username and Password**.
- Enter:
  - **Username**: `Admin2`
  - **Password**: `Admin123`
  
The router will contact the TACACS+ server at `192.168.1.7`.  
If successful, you are authenticated!

---

### 5. **Important notes:**
- If TACACS+ server is unreachable, the router falls back to **local** authentication (`username Admin2 secret Admin123` command).
- `tacacs-server host` and `tacacs-server key` are **old-style syntax** (fine for learning). Newer IOS versions use `tacacs server` configuration blocks.

---

Would you also like me to show you a simple diagram of how the router talks to the TACACS+ server? 📈  
(It might make it even easier to visualize!)

Of course! Let's break it down properly:

When you configure Cisco devices (like routers and switches), you interact with **Cisco IOS (Internetwork Operating System)** using **commands**.

Commands are typed into the device's **CLI (Command Line Interface)**.

---

### There are 3 main command *modes* you work with:

| Mode | Prompt | What you can do |
|:-----|:-------|:----------------|
| **User EXEC Mode** | `>` | Basic commands (like `show`) but **no config**. |
| **Privileged EXEC Mode** | `#` | Full access to all commands, including configuration. |
| **Global Configuration Mode** | `(config)#` | Change device settings. |

---

### Now step-by-step for your commands:

---

#### 1. **`enable`**
- Moves from **User EXEC mode** (`>`) to **Privileged EXEC mode** (`#`).
- You get full access.

```bash
R1> enable
R1#
```

---

#### 2. **`conf t`** (short for `configure terminal`)
- Enters **Global Configuration Mode** to **start configuring the device**.

```bash
R1# configure terminal
R1(config)#
```

---

#### 3. **`username Admin2 secret Admin123`**
- Creates a **local** user account on the router.
- `secret` encrypts the password (stronger than `password` keyword).
- Example:

```bash
R1(config)# username Admin2 secret Admin123
```

---

#### 4. **`aaa new-model`**
- Turns on **AAA** (Authentication, Authorization, Accounting).
- Needed for centralized authentication like TACACS+.

```bash
R1(config)# aaa new-model
```

---

#### 5. **`tacacs-server host 192.168.1.7`**
- Tells the router **where** to find the TACACS+ server.
- (Note: in newer IOS versions it's configured a little differently.)

```bash
R1(config)# tacacs-server host 192.168.1.7
```

---

#### 6. **`tacacs-server key Tacacs123`**
- Sets a **shared secret** between router and TACACS+ server.
- It **secures** their communication.

```bash
R1(config)# tacacs-server key Tacacs123
```

---

#### 7. **`aaa authentication login default group tacacs+ local`**
- Configures **how login authentication happens**.
- `default` means it applies everywhere unless otherwise specified.
- `group tacacs+` tries TACACS+ server first.
- If that fails, fallback to **local** users.

```bash
R1(config)# aaa authentication login default group tacacs+ local
```

---

#### 8. **`line console 0`**
- Accesses **console line** configuration.
- (Console = physical port you connect to directly.)

```bash
R1(config)# line console 0
R1(config-line)#
```

---

#### 9. **`login authentication default`**
- Apply the AAA **authentication method** (`default`) to **console login**.

```bash
R1(config-line)# login authentication default
```

---

#### 10. **`exit`**
- Exit back to previous mode.

```bash
R1(config-line)# exit
```

---

### 🔥 Quick Summary Flow:

| Step | Purpose |
|:-----|:--------|
| `enable` | Privileged mode access |
| `conf t` | Enter configuration |
| Create local user | Backup login |
| `aaa new-model` | Enable AAA |
| Define TACACS+ server | IP and key |
| Setup login authentication | Use TACACS+ first, local second |
| Apply AAA to console login | Require username/password |

---

Would you also like a **real-world tip** on **troubleshooting** if TACACS+ login fails?  
(It’s super useful when working with Cisco routers!) 🚀