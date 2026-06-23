# Understanding Endpoint Detection and Response (EDR)

> **EDR helps security teams detect, investigate, and respond to threats that traditional antivirus solutions often miss.**

As organizations increasingly rely on digital devices and remote work environments, protecting endpoints has become more important than ever. Traditional antivirus software remains valuable, but modern cyber threats require deeper visibility and faster response capabilities.

This is where **Endpoint Detection and Response (EDR)** comes in.

---

# What is EDR?

**Endpoint Detection and Response (EDR)** is a security solution that continuously monitors endpoint devices such as:

- Laptops
- Desktops
- Servers
- Virtual Machines

Its primary goal is to:

✅ Detect suspicious activity  
✅ Provide visibility into endpoint behavior  
✅ Enable rapid incident response

Unlike traditional antivirus solutions that mainly rely on malware signatures, EDR focuses on:

- Behavioral analysis
- Process monitoring
- Threat hunting
- Incident investigation
- Response and containment

---

## Popular EDR Solutions

- CrowdStrike Falcon
- Microsoft Defender for Endpoint
- SentinelOne ActiveEDR
- Symantec EDR
- OpenEDR

---

# Why EDR Matters

Modern attackers increasingly use:

- Fileless malware
- Living-off-the-Land (LotL) techniques
- PowerShell abuse
- Multi-stage attack chains

Many of these techniques bypass traditional antivirus detection.

## Benefits of EDR

| Benefit | Description |
|----------|-------------|
| Continuous Monitoring | Real-time visibility into endpoint activity |
| Faster Detection | Identifies suspicious behavior quickly |
| Threat Investigation | Provides complete attack context |
| Rapid Response | Enables immediate containment actions |
| Threat Hunting | Search across all endpoints for indicators of compromise |

---

# The Three Pillars of EDR

## 1. Visibility

Visibility is one of the most powerful capabilities of EDR.

The EDR agent continuously collects telemetry from endpoints, including:

- Process executions
- Network connections
- Command-line activity
- File modifications
- Registry changes
- User actions

### Example Process Tree

```text
explorer.exe
└── winword.exe
    └── powershell.exe
```

This helps analysts identify suspicious parent-child process relationships.

### Why Visibility Matters

Without visibility:

- Attacks remain hidden
- Root cause analysis becomes difficult
- Threat investigations take longer

With visibility:

- Analysts can reconstruct attack timelines
- Understand attacker actions
- Identify affected systems

---

## 2. Detection

Detection is where EDR transforms telemetry into actionable alerts.

### Behavioral Detection

Instead of asking:

> "Is this file malicious?"

EDR asks:

> "Is this behavior suspicious?"

Example:

```text
winword.exe
└── powershell.exe
```

A Word document launching PowerShell is uncommon and often associated with malicious macros.

---

### Anomaly Detection

EDR learns normal system behavior and alerts on unusual activity.

Example:

```text
chrome.exe modifies startup registry keys
```

Since browsers rarely create persistence mechanisms, this activity may be suspicious.

---

### IOC Matching

EDR compares observed activity against known Indicators of Compromise (IOCs).

Examples:

- Malicious IP addresses
- Domains
- URLs
- File hashes

Example:

```text
Hash:
a1b2c3d4...
```

If the hash matches known malware, an alert is generated immediately.

---

### MITRE ATT&CK Mapping

One of the most valuable EDR capabilities is MITRE ATT&CK mapping.

Example:

```text
Tactic: Persistence
Technique: Scheduled Task/Job
```

This helps analysts understand:

- What happened
- Why it happened
- Where the attacker is in the attack lifecycle

---

### Machine Learning Detection

Modern EDR platforms use machine learning models trained on large volumes of endpoint data.

Example attack chain:

```text
Word Document
      ↓
PowerShell
      ↓
Payload Download
      ↓
Registry Modification
```

While individual actions may appear harmless, together they form a suspicious sequence.

Machine learning helps identify these complex multi-stage attacks.

---

## 3. Response

Detection alone is not enough.

Security teams must be able to contain threats before they spread.

Most EDR platforms allow analysts to:

- Isolate endpoints
- Terminate malicious processes
- Quarantine files
- Execute remote response actions
- Investigate hosts remotely

### Example Response Actions

| Action | Purpose |
|----------|----------|
| Host Isolation | Prevent lateral movement |
| Process Termination | Stop malicious execution |
| File Quarantine | Prevent malware execution |
| Remote Investigation | Gather evidence |
| Threat Hunting | Search for related activity |

---

# How EDR Actually Works

Most EDR platforms follow a four-stage workflow:

```text
Endpoint Activity
        ↓
Telemetry Collection
        ↓
Detection Engine
        ↓
Analyst Response
```

---

## Step 1: Telemetry Collection

The EDR agent continuously gathers endpoint telemetry.

### Collected Data

#### Process Activity

```text
explorer.exe
   └── winword.exe
         └── powershell.exe
```

#### Network Connections

```text
powershell.exe
      ↓
185.45.10.20:443
```

#### Command-Line Activity

```powershell
powershell.exe -enc SQBmACAA...
```

#### File Activity

- File creation
- File deletion
- File movement
- File renaming

#### Registry Activity

```registry
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

Often associated with persistence mechanisms.

---

## Step 2: Detection Engine

The Detection Engine analyzes collected telemetry using:

- Behavioral Analytics
- Anomaly Detection
- IOC Matching
- MITRE ATT&CK Correlation
- Machine Learning

This stage transforms raw data into meaningful security alerts.

---

## Step 3: Alert Generation & Investigation

When suspicious activity is detected, EDR generates an alert.

Typical alert details include:

- Hostname
- Username
- Severity
- Detection Time
- Process Tree
- Command Line Activity
- Network Connections
- MITRE ATT&CK Mapping
- Related IOCs

### Example Investigation

```text
explorer.exe
   └── winword.exe
         └── powershell.exe
               └── payload.exe
```

Questions analysts investigate:

- What initiated the activity?
- Was malware downloaded?
- Were registry keys modified?
- Was network communication observed?
- Did persistence occur?

---

## Step 4: Response & Containment

After confirming malicious activity, analysts can respond directly from the EDR console.

### Host Isolation

Disconnects the endpoint from the network while maintaining communication with the EDR platform.

Prevents:

- Data exfiltration
- Lateral movement
- Command-and-control communication

### Process Termination

```text
Terminate:
powershell.exe
```

Stops malicious execution immediately.

### File Quarantine

Moves malicious files to a secure location where they cannot execute.

### Threat Hunting

Search across all endpoints for:

- Malicious hashes
- Suspicious processes
- Malicious domains
- Known attacker IP addresses

This helps determine whether additional systems are affected.

---

# EDR vs Traditional Antivirus

| Antivirus | EDR |
|------------|------------|
| Signature-based detection | Behavior-based detection |
| Focuses on known malware | Detects unknown threats |
| Limited investigation | Deep investigation capabilities |
| Minimal visibility | Full endpoint visibility |
| Basic response | Advanced containment and remediation |

### Simple Analogy

**Antivirus asks:**

> "Is this file known to be malicious?"

**EDR asks:**

> "Is this behavior suspicious, even if I've never seen it before?"

---

# Key Takeaways

✅ Continuous endpoint visibility

✅ Behavioral threat detection

✅ MITRE ATT&CK mapping

✅ Faster incident response

✅ Threat hunting capabilities

✅ Protection against modern attack techniques

---

# Conclusion

Cyber threats have evolved far beyond traditional malware files. Modern attackers increasingly leverage legitimate tools, fileless techniques, and multi-stage attack chains to evade traditional defenses.

EDR addresses these challenges by combining:

- Visibility
- Detection
- Investigation
- Response

into a single security platform.

Whether you're a **SOC Analyst**, **Cybersecurity Student**, **Threat Hunter**, or **IT Professional**, understanding how EDR works provides valuable insight into how organizations detect, investigate, and respond to modern cyber threats.
