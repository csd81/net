
# IPS = intrusion prevention system

R1> user Admin1 Admin123
en conf t
```bash
R1(config)#
R1(config)# do mkdir ipsdir
R1(config)# ip ips config location flash:ipsdir
R1(config)# ip ips name iosips
R1(config)# ip ips notify log
R1(config)# service timestamps log datetime msec
R1(config)# logging host 192.168.1.7
R1(config)#
R1(config)# ip ips signature-category
R1(config-ips-category)# category all
R1(config-ips-category-action)# retired true
R1(config-ips-category-action)# exit

R1(config-ips-category)# category ics_ips basic
R1(config-ips-category-action)# retired false
R1(config-ips-category-action)# exit
           [confirm]
R1(config)# int g0/1
R1(config-if)# ip ips iosips  out
R1(config-if)# exit

R1(config)# ip ips signature-definition 

R1(config-sigdef)# signature 2004 0
R1(config-sigdef-sig)# status
R1(config-sigdef-sig-status)# retired false
R1(config-sigdef-sig-status)# enable true
R1(config-sigdef-sig-status)# exit
R1(config-sigdef-sig)# engine
R1(config-sigdef-sig-engine)# event-action produce-alert
R1(config-sigdef-sig-engine)# event-action deny-packet-inline
R1(config-sigdef-sig-engine)# exit
R1(config-sigdef-sig)# exit
            [confirm]
R1(config)# 
```

Of course! Let’s walk through your commands carefully — you are configuring **Cisco IOS IPS (Intrusion Prevention System)** on a router (`R1`). I'll explain each block step-by-step:

---

### 1. **Initial steps: access and preparation**
```bash
R1> user Admin1 Admin123
```
- (This line looks like a login or user setup, but not a real Cisco IOS command directly. Might be just an environment note.)
  
```bash
en
conf t
```
- `en`: enter **privileged EXEC mode** (enable mode).
- `conf t`: enter **global configuration mode** to make system-wide changes.

---

### 2. **Create a directory for IPS**
```bash
do mkdir ipsdir
```
- `do` allows running EXEC-mode commands from config mode.
- `mkdir ipsdir`: **create a directory** called `ipsdir` inside the router's flash storage.  
  (IPS needs a location to store signatures and configurations.)

---

### 3. **Configure IPS base settings**
```bash
ip ips config location flash:ipsdir
```
- Tells the router **where to store the IPS configuration** files: in the `flash:ipsdir` directory.

```bash
ip ips name iosips
```
- Creates an **IPS rule set** named `iosips`.

```bash
ip ips notify log
```
- Tells the router to **log IPS events**.

```bash
service timestamps log datetime msec
```
- Adds **timestamps with milliseconds** to all logs — very useful for detailed IPS event tracking.

```bash
logging host 192.168.1.7
```
- **Sends logs** to a Syslog server at `192.168.1.7` — so external logging is set up.

---

### 4. **Signature category configuration**
```bash
ip ips signature-category
```
- Enters the IPS **signature category configuration** mode — managing groups of signatures.

```bash
category all
retired true
exit
```
- Selects **all signatures** and **retires** them (meaning disables them).  
  (You first disable everything.)

```bash
category ics_ips basic
retired false
exit
```
- Specifically **un-retires** (activates) the signatures in the **ICS basic** category (Industrial Control Systems basic signatures).  
  (You only activate a minimal, selected set.)

---
**[confirm]** — Cisco sometimes asks for confirmation when making significant changes (especially in IPS signature settings).

---

### 5. **Apply IPS to interface**
```bash
int g0/1
ip ips iosips out
exit
```
- Go into **interface GigabitEthernet0/1**.
- Apply the IPS policy (`iosips`) **on outbound traffic** (`out` direction).
- `exit` — leave interface config mode.

---

### 6. **Create a custom signature**
```bash
ip ips signature-definition
```
- Enter signature **definition mode** — allows you to manually create or tweak IPS signatures.

```bash
signature 2004 0
```
- Create or modify signature with **ID 2004** (revision 0).

```bash
status
retired false
enable true
exit
```
- Activate (un-retire) the custom signature and **enable** it.

```bash
engine
event-action produce-alert
event-action deny-packet-inline
exit
exit
```
- Inside the engine:
  - `produce-alert`: generate a log alert when this signature is triggered.
  - `deny-packet-inline`: **drop the malicious packet immediately** in real-time (not just alerting).

**[confirm]** — Again, confirming changes.

---

### Final result:  
You have:
- IPS logging configured.
- A selected IPS signature set (`ics_ips basic`) activated.
- An IPS policy (`iosips`) applied to interface G0/1 for outbound traffic.
- One custom signature (`2004 0`) created, alerting and blocking malicious traffic inline.

---

Would you also like me to draw a small flow diagram showing how the traffic passes through this IPS setup on the router? 📈  
It might make the logic even clearer. 🚀