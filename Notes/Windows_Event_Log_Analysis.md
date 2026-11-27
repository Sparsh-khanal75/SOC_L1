# Windows Event Log Analysis for SOC Analysts

> Windows Event Logs are often the first place a SOC analyst looks when investigating a Windows host. Knowing the key Event IDs saves a lot of time during triage.

---

## Where the Logs Live

| Log | Path | What it records |
|-----|------|-----------------|
| Security | `C:\Windows\System32\winevt\Logs\Security.evtx` | Logons, account changes, privilege use, process creation (if audited) |
| System | `...\Logs\System.evtx` | Services, drivers, system start/stop |
| Application | `...\Logs\Application.evtx` | Application errors and events |
| PowerShell | `...\Logs\Microsoft-Windows-PowerShell%4Operational.evtx` | Script block logging (4104) |
| Sysmon | `...\Logs\Microsoft-Windows-Sysmon%4Operational.evtx` | Detailed process, network, file and registry activity |

---

## Key Security Event IDs

### Authentication

| Event ID | Meaning | Why it matters |
|----------|---------|----------------|
| 4624 | Successful logon | Check logon type, source IP, account |
| 4625 | Failed logon | Many in a short time = brute force / password spraying |
| 4634 / 4647 | Logoff | Helps build session timelines |
| 4648 | Logon with explicit credentials | `runas`, lateral movement |
| 4672 | Special privileges assigned | Admin-level logon |
| 4740 | Account locked out | Often follows brute force |
| 4768 / 4769 | Kerberos TGT / service ticket requested | Kerberoasting shows many 4769 with RC4 (0x17) encryption |
| 4776 | NTLM credential validation | Pass-the-hash investigations |

### Account and Group Changes

| Event ID | Meaning |
|----------|---------|
| 4720 | User account created |
| 4722 | User account enabled |
| 4724 | Password reset attempt |
| 4726 | User account deleted |
| 4728 / 4732 / 4756 | Member added to global / local / universal security group |

### Execution and Persistence

| Event ID | Log | Meaning |
|----------|-----|---------|
| 4688 | Security | New process created (enable command-line auditing to see arguments) |
| 4698 | Security | Scheduled task created |
| 4697 | Security | Service installed |
| 7045 | System | New service installed |
| 4104 | PowerShell | Script block logged — shows decoded PowerShell code |

### Defense Evasion

| Event ID | Log | Meaning |
|----------|-----|---------|
| 1102 | Security | Security audit log cleared |
| 104 | System | System log cleared |

> An attacker clearing logs is a high-priority alert by itself.

---

## Logon Types (Event 4624 / 4625)

| Type | Name | Example |
|------|------|---------|
| 2 | Interactive | Keyboard login at the machine |
| 3 | Network | SMB share access, PsExec |
| 4 | Batch | Scheduled tasks |
| 5 | Service | Service started by the Service Control Manager |
| 7 | Unlock | Workstation unlocked |
| 8 | NetworkCleartext | Credentials sent in clear text (e.g. IIS basic auth) |
| 9 | NewCredentials | `runas /netonly` |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Domain login using cached credentials |

---

## Common Investigation Patterns

### 1. Brute force followed by success
```
Many 4625 (same source IP)  →  4624 (same account, same IP)
```
Check the `Status / Sub Status` codes in 4625:
- `0xC000006A` — correct username, wrong password
- `0xC0000064` — username does not exist
- `0xC0000234` — account locked

### 2. New admin account (persistence)
```
4720 (user created)  →  4732 (added to Administrators)
```

### 3. Suspicious service installation
```
7045 / 4697 with a service path in %TEMP%, %APPDATA% or a cmd/powershell command line
```

### 4. RDP from an unusual source
```
4624 Logon Type 10 from an external or unexpected IP
```

---

## Useful Commands

**PowerShell — failed logons in the last 24 hours**
```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = (Get-Date).AddDays(-1)
} | Select-Object TimeCreated, Message
```

**PowerShell — read an exported .evtx file**
```powershell
Get-WinEvent -Path .\Security.evtx -FilterXPath "*[System[EventID=4720]]"
```

**wevtutil — query from cmd**
```cmd
wevtutil qe Security /q:"*[System[(EventID=1102)]]" /f:text /c:10
```

---

## Tools for EVTX Analysis

- **Event Viewer** — built in, good for quick checks
- **Get-WinEvent** — scripting and filtering
- **EvtxECmd** (Eric Zimmerman) — converts EVTX to CSV for Timeline Explorer
- **Chainsaw** and **Hayabusa** — fast hunting over EVTX with Sigma rules

---

## Key Takeaways

- Memorise the core IDs: **4624, 4625, 4672, 4688, 4720, 4732, 7045, 4104, 1102**.
- Logon type tells you *how* someone logged in.
- Single events are rarely enough — look for **sequences** that tell a story.

> Notes written while working through the TryHackMe SOC Level 1 path.
