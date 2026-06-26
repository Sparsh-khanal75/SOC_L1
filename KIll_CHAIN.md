# Cyber Kill Chain & Unified Kill Chain Notes

## Overview

This repository contains my study notes from learning the **Cyber Kill Chain** and the **Unified Kill Chain** as part of my SOC Analyst learning journey on TryHackMe.

The Cyber Kill Chain helps defenders understand the lifecycle of a cyberattack and identify opportunities to detect, prevent, or disrupt an attack before it reaches its objective. The Unified Kill Chain expands on this concept by covering modern attack techniques such as lateral movement, credential theft, persistence, and data exfiltration.

## Cyber Kill Chain (7 Phases)

1. **Reconnaissance** – Gather information about the target.
2. **Weaponization** – Prepare malware, exploits, or payloads.
3. **Delivery** – Deliver the payload (phishing, USB, watering hole, etc.).
4. **Exploitation** – Execute malicious code by exploiting a vulnerability.
5. **Installation** – Install malware or persistence mechanisms.
6. **Command & Control (C2)** – Establish remote communication with the compromised system.
7. **Actions on Objectives** – Achieve the attacker's goal (data theft, ransomware, espionage, etc.).

## Unified Kill Chain (18 Phases)

### Initial Foothold

* Reconnaissance
* Resource Development
* Delivery
* Social Engineering
* Exploitation
* Persistence
* Defense Evasion
* Command & Control

### Network Propagation

* Pivoting
* Discovery
* Credential Access
* Lateral Movement
* Privilege Escalation
* Execution

### Actions on Objectives

* Collection
* Exfiltration
* Impact
* Objectives

## Key Takeaways

* Every cyberattack follows a sequence of stages.
* Detecting or stopping an attacker at **any phase** can break the attack chain.
* The Unified Kill Chain provides a more complete view of modern attacks than the traditional Cyber Kill Chain.
* Understanding these frameworks helps SOC analysts investigate incidents, map attacker behavior, and improve defensive strategies.

## Skills Practiced

* Cyber Kill Chain analysis
* Attack lifecycle understanding
* MITRE ATT&CK concept mapping
* Threat analysis
* Defensive security fundamentals

## Learning Outcome

After completing this module, I can:

* Explain each phase of the Cyber Kill Chain.
* Differentiate between the Cyber Kill Chain and the Unified Kill Chain.
* Identify attacker activities at each stage of an intrusion.
* Understand where defenders can detect or stop an attack before it reaches its objective.
