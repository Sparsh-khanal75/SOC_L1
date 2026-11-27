# Threat Hunting with Sysmon

> Default Windows logging misses a lot. **Sysmon (System Monitor)** from Microsoft Sysinternals records detailed process, network, file and registry activity, which makes it one of the most useful free data sources for a SOC.

---

## Installing Sysmon

```cmd
sysmon64.exe -accepteula -i sysmonconfig.xml
```

Update the config later:
```cmd
sysmon64.exe -c sysmonconfig.xml
```

Popular community configs:
- **SwiftOnSecurity / sysmon-config** — good, low-noise starting point
- **Olaf Hartong / sysmon-modular** — modular, mapped to MITRE ATT&CK

Logs are written to:
`Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`

---

## Sysmon Event IDs

| ID | Event | Hunting use |
|----|-------|-------------|
| 1 | Process creation | Command lines, parent-child relationships, hashes |
| 2 | File creation time changed | Timestomping |
| 3 | Network connection | Process making outbound connections (C2) |
| 5 | Process terminated | Timeline building |
| 6 | Driver loaded | Malicious or vulnerable drivers |
| 7 | Image (DLL) loaded | DLL side-loading |
| 8 | CreateRemoteThread | Process injection |
| 10 | Process access | Credential dumping (access to `lsass.exe`) |
| 11 | File created | Dropped payloads |
| 12 / 13 / 14 | Registry create/delete, value set, rename | Persistence via Run keys |
| 15 | File stream created | Alternate Data Streams, Mark-of-the-Web |
| 17 / 18 | Named pipe created / connected | Cobalt Strike and other C2 frameworks |
| 22 | DNS query | Process-level DNS — find which process resolved a bad domain |
| 23 / 26 | File delete (archived / logged) | Attacker clean-up |
| 25 | Process tampering | Process hollowing / herpaderping |

---

## Hunting Ideas

### 1. Office applications spawning shells (phishing payloads)
**Event ID 1** where:
- `ParentImage` ends with `winword.exe`, `excel.exe` or `outlook.exe`
- `Image` ends with `cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`

Word should almost never start PowerShell.

### 2. Credential dumping from LSASS
**Event ID 10** where:
- `TargetImage` is `C:\Windows\System32\lsass.exe`
- `SourceImage` is not a known security tool
- `GrantedAccess` such as `0x1010`, `0x1410` or `0x1FFFFF`

This pattern is typical of Mimikatz and similar tools.

### 3. Encoded PowerShell
**Event ID 1** where `CommandLine` contains `-enc`, `-EncodedCommand` or `FromBase64String`.

### 4. Registry Run key persistence
**Event ID 13** where `TargetObject` contains:
```
\Software\Microsoft\Windows\CurrentVersion\Run
\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

### 5. Unusual processes making network connections
**Event ID 3** from processes that rarely talk to the internet: `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `notepad.exe`.

### 6. Executables dropped in user-writable folders
**Event ID 11** with `TargetFilename` in `\AppData\`, `\Temp\` or `\Users\Public\` ending in `.exe`, `.dll`, `.ps1`, `.vbs`.

---

## Querying Sysmon with PowerShell

**Find all process creations with encoded PowerShell**
```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=1]]" |
    Where-Object { $_.Message -match '-enc' } |
    Select-Object TimeCreated, Message
```

**Find access to LSASS in an exported log**
```powershell
Get-WinEvent -Path .\Sysmon.evtx -FilterXPath "*[System[EventID=10]] and *[EventData[Data[@Name='TargetImage']='C:\Windows\System32\lsass.exe']]"
```

---

## Building a Process Tree

Every Sysmon Event ID 1 contains a `ProcessGuid` and a `ParentProcessGuid`. Linking these lets you rebuild the full attack chain, for example:

```
outlook.exe
 └── winword.exe
      └── cmd.exe
           └── powershell.exe -enc ...
                └── rundll32.exe  (Event 3: connects to external IP)
```

Use the GUIDs instead of PIDs — PIDs are reused, GUIDs are unique.

---

## Key Takeaways

- Sysmon fills the gaps that default Windows logging leaves.
- The most valuable IDs for hunting: **1, 3, 10, 11, 13, 22**.
- Hunt for **behaviour** (parent-child anomalies, LSASS access) rather than only file hashes — see the Pyramid of Pain notes.

> Notes written while working through the TryHackMe SOC Level 1 path.
