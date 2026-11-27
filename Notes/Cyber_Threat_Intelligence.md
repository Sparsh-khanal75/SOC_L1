# Cyber Threat Intelligence (CTI) Fundamentals

> **Threat intelligence** is evidence-based knowledge about threats that helps defenders make better decisions. Raw data becomes intelligence only after it is processed, analysed and given context.

---

## Data vs Information vs Intelligence

| Level | Example |
|-------|---------|
| **Data** | `185.220.101.45` |
| **Information** | `185.220.101.45` connected to our web server 300 times last night |
| **Intelligence** | `185.220.101.45` is a known Tor exit node used in a credential-stuffing campaign against our sector — block and review affected accounts |

---

## IOC vs IOA vs TTP

| Term | Meaning | Example | Lifespan |
|------|---------|---------|----------|
| **IOC** (Indicator of Compromise) | Evidence that an attack *already happened* | File hash, malicious IP, domain | Short — easy for attackers to change |
| **IOA** (Indicator of Attack) | Evidence that an attack *is happening* | Office spawning PowerShell, LSASS being accessed | Medium |
| **TTP** (Tactics, Techniques, Procedures) | *How* an attacker operates | Phishing → macro → credential dumping → lateral movement via PsExec | Long — hard for attackers to change |

This links directly to the **Pyramid of Pain**: detecting TTPs causes the attacker the most pain.

---

## Types of Threat Intelligence

| Type | Audience | Example |
|------|----------|---------|
| **Strategic** | Executives, management | "Ransomware groups are targeting healthcare in our region" |
| **Operational** | SOC leads, IR teams | Details of an active campaign — who, motivation, timing |
| **Tactical** | Detection engineers, analysts | TTPs mapped to MITRE ATT&CK |
| **Technical** | SOC analysts, tools (SIEM, firewall) | IOCs — hashes, IPs, domains, URLs |

---

## The Threat Intelligence Lifecycle

1. **Direction** — What do we need to know? What are our critical assets?
2. **Collection** — Gather data from feeds, logs, reports, OSINT.
3. **Processing** — Normalise, de-duplicate and enrich the data.
4. **Analysis** — Turn it into meaningful findings with context.
5. **Dissemination** — Share with the right people in the right format.
6. **Feedback** — Was it useful? Adjust the requirements.

---

## Useful Free Sources and Platforms

| Source | Use |
|--------|-----|
| **MITRE ATT&CK** | Framework of adversary tactics and techniques |
| **VirusTotal** | Check hashes, URLs, IPs, domains |
| **abuse.ch — URLhaus** | Malicious URLs used for malware distribution |
| **abuse.ch — MalwareBazaar** | Malware samples and hashes |
| **abuse.ch — ThreatFox** | IOCs linked to malware families |
| **AlienVault OTX** | Community threat "pulses" |
| **MISP** | Open-source platform to store and share threat intel |
| **OpenCTI** | Open-source platform to organise CTI and link it to ATT&CK |
| **AbuseIPDB** | Reputation of IP addresses |

---

## Traffic Light Protocol (TLP 2.0)

Used to mark how widely intelligence may be shared.

| Label | Sharing |
|-------|---------|
| **TLP:RED** | Named recipients only |
| **TLP:AMBER+STRICT** | Recipient's organisation only |
| **TLP:AMBER** | Recipient's organisation and its clients, on a need-to-know basis |
| **TLP:GREEN** | The wider community, but not public |
| **TLP:CLEAR** | No restrictions — public |

---

## The Diamond Model

Every intrusion event has four connected parts:

```
            Adversary
               /\
              /  \
   Capability ---- Infrastructure
              \  /
               \/
             Victim
```

If you know one corner (e.g. a C2 IP — infrastructure), you can pivot to the others (which malware uses it, which group runs it, who else it targets).

---

## How a SOC Analyst Uses CTI Day to Day

- **Enriching alerts** — check an IP or hash against VirusTotal / ThreatFox.
- **Hunting** — search the SIEM for IOCs from a new report.
- **Writing detections** — turn TTPs from reports into SIEM / Sigma rules.
- **Prioritising** — an alert linked to a known active campaign gets escalated faster.

---

## Key Takeaways

- Intelligence = data + context + relevance.
- IOCs are useful but short-lived; TTPs are more durable.
- Always check *who* the intelligence is for and *how* it can be shared (TLP).

> Notes written while working through the TryHackMe SOC Level 1 path.
