# local AAA
```bash
R3> en
R3# conf t
R3(config)# username Admin3 secret admin123
R3(config)# 
R3(config)# aaa new-model
R3(config)# aaa authentication login default local 
R3(config)# aaa authentication login default local-case  ! case sensitive
R3(config)# aaa authentication login default group ! Server-group
R3(config)# line console 0 
R3(config-line)# login authentication default 
R3(config-line)# exit
R3(config)# 
R3(config)# ip domain-name cisco.com
R3(config)# crypto key generate rsa
    modulus: 1025
R3(config)# 
R3(config)# aaa authentication login SSH-LOGIN local
R3(config)# line vty 0 4 
R3(config-line)# login authentication SSH-LOGIN  
R3(config-line)# transport input ssh
R3(config-line)# exit 
```

Let's break it down carefully, because it's a really important AAA (Authentication, Authorization, Accounting) and SSH configuration script on a router (like Cisco IOS):

---

### Step-by-Step Explanation:

**1. Enter enable mode (`en`) and then global configuration mode (`conf t`):**
```bash
R3> en
R3# conf t
```
- `en`: Move from user mode (`>`) to privileged exec mode (`#`).
- `conf t`: Enter global configuration mode.

---

**2. Create a local user account:**
```bash
R3(config)# username Admin3 secret admin123
```
- `username Admin3 secret admin123`: Create a local user called `Admin3` with encrypted password `admin123`.
- `secret` encrypts the password using a stronger MD5 hash, more secure than `password`.

---

**3. Enable AAA:**
```bash
R3(config)# aaa new-model
```
- **`aaa new-model`**: Activates the AAA security model, which is required for advanced authentication methods.

---

**4. Configure default login authentication:**
```bash
R3(config)# aaa authentication login default local 
```
- `default`: Apply to all login methods unless specified otherwise.
- `local`: Use the local user database (like the `Admin3` user created).

---

**5. Make local authentication case-sensitive:**
```bash
R3(config)# aaa authentication login default local-case
```
- `local-case`: Enforces **case sensitivity** on usernames/passwords (e.g., `Admin3` ≠ `admin3`).

---

**6. (Mistake / Unfinished Line)** 
```bash
R3(config)# aaa authentication login default group 
```
- `group` requires a server group name (like `radius` or `tacacs+`) **after** it.  
- This line is incomplete — it would cause an error if you press Enter without specifying a server group.

---

**7. Apply the AAA authentication to console login:**
```bash
R3(config)# line console 0 
R3(config-line)# login authentication default 
R3(config-line)# exit
```
- `line console 0`: Enter the console line configuration.
- `login authentication default`: Use the AAA method list `default` (i.e., local user).

---

**8. Set domain name (required for SSH key generation):**
```bash
R3(config)# ip domain-name cisco.com
```
- `ip domain-name`: Sets the domain name, needed for generating the RSA key.

---

**9. Generate RSA keys (for SSH):**
```bash
R3(config)# crypto key generate rsa
```
- `crypto key generate rsa`: Creates RSA keys for SSH encryption.
- modulus: 1025 bits (recommended is 2048+ nowadays, but 1024+ is minimal).

---

**10. Create a separate AAA list for SSH login:**
```bash
R3(config)# aaa authentication login SSH-LOGIN local
```
- `SSH-LOGIN`: Name of a **new** method list for SSH logins only.
- `local`: Use the local username database.

---

**11. Configure vty (virtual terminal lines 0–4) for SSH access:**
```bash
R3(config)# line vty 0 4 
R3(config-line)# login authentication SSH-LOGIN  
R3(config-line)# transport input ssh
R3(config-line)# exit 
```
- `line vty 0 4`: Configure remote access lines (telnet/ssh).
- `login authentication SSH-LOGIN`: Use the custom AAA list `SSH-LOGIN` for authentication.
- `transport input ssh`: **Allow only SSH** (block insecure Telnet access).

---

### Quick Summary:

| Purpose                         | Commands Used                          |
|----------------------------------|----------------------------------------|
| Create a user                   | `username Admin3 secret admin123`      |
| Enable AAA                      | `aaa new-model`                        |
| Default login via local users    | `aaa authentication login default local` |
| Enforce case-sensitivity         | `aaa authentication login default local-case` |
| Bind authentication to console  | `line console 0 -> login authentication default` |
| Prepare for SSH                 | `ip domain-name`, `crypto key generate rsa` |
| Separate SSH login policy       | `aaa authentication login SSH-LOGIN local` |
| Lock vty lines to SSH only       | `line vty 0 4 -> login authentication SSH-LOGIN; transport input ssh` |

---

Would you also like me to show you a "cleaned up" corrected version of this config?  
(There’s a small mistake with the `aaa authentication login default group` line.) 🚀


