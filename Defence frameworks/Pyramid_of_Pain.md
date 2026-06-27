# 🏔️ Pyramid of Pain

<p align="center">
<img src="https://img.shields.io/badge/MITRE-CTID-red?style=for-the-badge">
<img src="https://img.shields.io/badge/Threat%20Intelligence-Pyramid%20of%20Pain-blue?style=for-the-badge">
<img src="https://img.shields.io/badge/Cybersecurity-Detection%20Engineering-success?style=for-the-badge">
</p>

---

# 📖 What is the Pyramid of Pain?

The **Pyramid of Pain** is a cybersecurity model developed by **David J. Bianco** that illustrates how difficult it is for attackers to evade different types of detections.

The higher defenders move up the pyramid, the more costly and disruptive it becomes for attackers to continue their operations.

Instead of relying solely on **Indicators of Compromise (IOCs)** such as hashes or IP addresses, defenders should focus on **attacker behaviors (TTPs)** that are much harder to modify.

---

# 🏔️ Pyramid Levels

```
                 TTPs
              ───────────
                 Tools
            ───────────────
        Network / Host Artifacts
      ───────────────────────────
              Domain Names
        ─────────────────────
              IP Addresses
      ─────────────────────────
             Hash Values
```

---

# 1️⃣ Hash Values

### Description

A cryptographic fingerprint uniquely identifying a file.

### Examples

```text
SHA256
MD5
SHA1
```

### Detection Example

```text
Block file with SHA256:
3f5d8d4b...
```

### Advantages

* Extremely accurate
* Very low false positives

### Weakness

Attackers only need to:

* Recompile malware
* Add one byte
* Change metadata

The hash completely changes.

### Difficulty for Attackers

🟢 Very Easy

---

# 2️⃣ IP Addresses

### Description

Detect malicious IP addresses used by attackers.

### Detection Example

```text
154.35.10.113
```

### Advantages

Easy to block using:

* Firewalls
* IDS
* IPS
* EDR

### Weakness

Attackers can:

* Rent another VPS
* Use cloud providers
* Rotate infrastructure

### Difficulty for Attackers

🟢 Easy

---

# 3️⃣ Domain Names

### Description

Detect malicious domains used for C2 or phishing.

### Example

```text
evil-domain.com
```

### Detection Example

* DNS filtering
* Web proxy
* Secure Web Gateway

### Weakness

Attackers can:

* Register new domains
* Use DGAs (Domain Generation Algorithms)
* Abuse legitimate services

### Difficulty for Attackers

🟡 Moderate

---

# 4️⃣ Network / Host Artifacts

### Description

Artifacts left behind by malware execution.

### Examples

Network

```text
Regular C2 traffic
Beaconing
Specific ports
HTTP Headers
User-Agent
```

Host

```text
Registry Keys
Scheduled Tasks
Services
Dropped Files
Named Pipes
```

### Detection Example

```text
DisableRealtimeMonitoring = 1
```

### Advantages

Harder for attackers to remove without changing malware behavior.

### Difficulty for Attackers

🟠 Difficult

---

# 5️⃣ Tools

### Description

Software or frameworks attackers use during an intrusion.

### Examples

* Metasploit
* Cobalt Strike
* Mimikatz
* BloodHound
* PsExec

### Detection Example

Detect:

* Tool-specific behavior
* Command-line arguments
* Memory signatures
* Named pipes

### Weakness

Attackers must:

* Modify tools
* Develop custom malware
* Purchase alternative frameworks

### Difficulty for Attackers

🔴 Very Difficult

---

# 6️⃣ TTPs (Tactics, Techniques & Procedures)

### Description

The attacker's methodology.

Instead of detecting malware, detect **how attackers behave**.

### Examples

Discovery

```cmd
systeminfo
ipconfig /all
netstat
```

Credential Access

```text
LSASS dumping
```

Lateral Movement

```text
PsExec
Remote Service Creation
```

Persistence

```text
Registry Run Keys
Scheduled Tasks
```

Command & Control

```text
Periodic Beaconing
DNS Tunneling
HTTPS Callbacks
```

### Detection Example

* Sigma Rules
* Behavioral Analytics
* UEBA
* MITRE ATT&CK Mapping

### Advantages

Attackers must redesign their attack methodology.

Changing TTPs requires:

* New tooling
* New training
* New procedures

### Difficulty for Attackers

🔴 Extremely Difficult

---

# 📊 Summary Table

| Level | Indicator               | Attacker Effort           | Example              |
| ----- | ----------------------- | ------------------------- | -------------------- |
| 1️⃣   | Hash                    | ⭐ Very Easy               | SHA256               |
| 2️⃣   | IP Address              | ⭐ Easy                    | 154.35.10.113        |
| 3️⃣   | Domain                  | ⭐⭐ Moderate               | evil.com             |
| 4️⃣   | Network / Host Artifact | ⭐⭐⭐ Difficult             | Registry Keys        |
| 5️⃣   | Tools                   | ⭐⭐⭐⭐ Very Difficult       | Metasploit           |
| 6️⃣   | TTPs                    | ⭐⭐⭐⭐⭐ Extremely Difficult | Discovery, Beaconing |

---

# 🛡️ Practical SOC Examples

| Detection                    | Pyramid Level    |
| ---------------------------- | ---------------- |
| Block SHA256                 | Hash             |
| Block IP                     | IP Address       |
| Block Domain                 | Domain           |
| Detect Registry Modification | Host Artifact    |
| Detect C2 Beaconing          | Network Artifact |
| Detect Mimikatz              | Tool             |
| Detect Discovery Commands    | TTP              |
| Detect Lateral Movement      | TTP              |
| Detect Credential Dumping    | TTP              |

---

# 🎯 Key Takeaways

* Hashes provide high-confidence detections but are easily bypassed.
* IP addresses and domains are infrastructure indicators that attackers can rotate.
* Host and network artifacts force attackers to modify malware behavior.
* Detecting attacker tools increases operational costs.
* **Behavior-based detections (TTPs)** provide the strongest long-term defense because they target how attackers operate rather than what they use.

---

# 💡 Final Thought

> **Don't chase malware. Chase attacker behavior.**

The higher you move up the Pyramid of Pain, the more expensive it becomes for attackers to evade your detections, making your defenses significantly more resilient.
