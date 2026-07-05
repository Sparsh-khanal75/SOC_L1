# Wireshark Crash Course: The Complete Cheat Sheet for SOC Analysts

Packet analysis is one of those skills that separates a SOC analyst who *reacts* from one who *understands*. This is my complete, consolidated set of notes from working through Wireshark-focused TryHackMe rooms — structured as a single reference you can use to actually learn the tool, or brush up fast before a SOC/blue-team interview. Every section includes the filters, commands, and examples you'd need to apply it in a real capture.

---

## 1. Interface & Fundamentals

Every Wireshark window is built from three linked panes:

| Pane | Shows | Use |
|---|---|---|
| Packet List | One row per packet — time, source, destination, protocol, info | Scan traffic at a glance, sort by column |
| Packet Details | Expandable protocol layers (Ethernet → IP → TCP → payload) for the selected packet | Drill into headers/fields |
| Hex Dump | Raw bytes of the selected packet | Verify exact byte values, spot hidden/encoded data |

**Core workflow:** capture or open a `.pcap`/`.pcapng` → apply a display filter to cut the noise → inspect individual packets → **Follow Stream** to reconstruct full conversations.

```bash
# Reading a pcap directly from the command line (tshark, Wireshark's CLI counterpart)
tshark -r capture.pcapng -Y "http.request"
```

---

## 2. Statistics: Getting the Big Picture First

Before filtering anything, the **Statistics** menu tells you what you're actually dealing with.

### Statistics → Summary
Gives capture duration, total packet count, average packet size/rate, and overall throughput. Useful for a 10-second sanity check: is this a quiet capture, or is something flooding the wire?

### Statistics → Protocol Hierarchy
Breaks the entire capture down by protocol stack as a percentage of total traffic.

| Signal in Protocol Hierarchy | Possible Meaning |
|---|---|
| Unusually high % of ICMP | Sweep/ping scan, or potential ICMP tunneling |
| Unexpected protocol present at all (e.g. Telnet, FTP on a "modern" network) | Legacy service, potential cleartext credential exposure |
| High DNS volume relative to traffic size | Possible DNS tunneling or beaconing |
| Skewed conversation between two hosts dominating the capture | Possible data exfiltration or MITM position |

**Interview tip:** always start an investigation with Protocol Hierarchy and Conversations (Statistics → Conversations) before you touch a single filter — it tells you *where* to look.

---

## 3. Packet Filtering Principles

Wireshark has two distinct filter types, and mixing them up is a common early mistake.

| Filter Type | When Applied | Syntax | Example |
|---|---|---|---|
| **Capture filter** | Before/during capture — decides what gets recorded at all | Berkeley Packet Filter (BPF) syntax | `host 192.168.1.10 and port 80` |
| **Display filter** | After capture — decides what you currently see from an already-recorded file | Wireshark's own filter language | `ip.addr==192.168.1.10 && tcp.port==80` |

Capture filters are lighter-weight (less disk/memory) but you can't get data back if you filtered it out at capture time. Display filters are non-destructive — you can always widen them back out.

### Comparison operators (display filters)

| Operator | Meaning | Example |
|---|---|---|
| `==` | Equal to | `ip.addr==10.0.0.5` |
| `!=` | Not equal to | `ip.addr!=10.0.0.5` |
| `>` `<` `>=` `<=` | Greater/less than | `frame.len>1000` |
| `contains` | Substring match | `http contains "password"` |
| `matches` | Regex match | `http.host matches "^admin"` |

---

## 4. Protocol Filters — Quick Reference

The fastest way to cut noise is filtering straight to the protocol you care about.

| Protocol | Filter | Notes |
|---|---|---|
| DNS | `dns` | Add `dns.qry.name contains "x"` to search queries |
| HTTP | `http` | Use `http.request` to isolate requests only |
| TCP | `tcp` | `tcp.port==443` for a specific port |
| UDP | `udp` | `udp.port==53` for DNS specifically |
| ARP | `arp` | Almost always worth a quick look for spoofing |
| ICMP | `icmp` | `icmp.type==8` (echo request) / `icmp.type==0` (echo reply) |
| FTP | `ftp` / `ftp-data` | Control vs. data channel |
| TLS/SSL | `tls` | Modern name; `ssl` still works in older captures |

---

## 5. Advanced Filtering — Chaining Logic

Real investigations need compound filters. Combine protocol and comparison filters with logical operators:

| Operator | Meaning | Example |
|---|---|---|
| `&&` (or `and`) | Both conditions true | `ip.src==10.0.0.5 && tcp.port==22` |
| `\|\|` (or `or`) | Either condition true | `tcp.port==80 \|\| tcp.port==443` |
| `!` (or `not`) | Negation | `!(ip.addr==10.0.0.5)` |

**Practical compound examples:**
```
tcp.flags.syn==1 && tcp.flags.ack==0          # Half-open connections (scan indicator)
http.request.method=="POST" && http contains "pass"   # Likely credential submission
ip.src==10.0.0.5 && !(tcp.port==443)          # Everything from a host except HTTPS
```

---

## 6. Host & Protocol Identification: DHCP, NetBIOS, Kerberos

| Protocol | Purpose | Port | Filter | What to Look For |
|---|---|---|---|---|
| DHCP | IP address leasing | UDP 67/68 | `bootp` or `dhcp` | The DORA sequence: **D**iscover → **O**ffer → **R**equest → **A**ck. Hostnames often leak in Option 12. |
| NetBIOS/NBNS | Legacy Windows name resolution | UDP 137 | `nbns` | Broadcast name queries revealing internal hostnames — useful for passive host enumeration |
| Kerberos | Windows domain authentication | TCP/UDP 88 | `kerberos` | AS-REQ/AS-REP and TGS-REQ/TGS-REP exchanges |

**Interview tip:** even though Kerberos tickets are encrypted, the *username* in an AS-REQ is sent in cleartext — this is exactly why AS-REP Roasting and Kerberoasting are viable attacks against weak service account passwords. Recognizing this exchange in a capture is a strong signal of domain authentication activity worth correlating with logs.

---

## 7. Recon Detection: Nmap Scans

Nmap scans leave distinct fingerprints depending on scan type.

| Scan Type | Nmap Command | Wireshark Signature | Display Filter |
|---|---|---|---|
| TCP Connect Scan | `nmap -sT <target>` | Full 3-way handshake per port, then immediate RST | `tcp.flags.syn==1 && tcp.flags.ack==0` |
| SYN (Stealth) Scan | `nmap -sS <target>` | SYN sent, handshake never completes | `tcp.flags.syn==1 && tcp.flags.ack==0` |
| UDP Scan | `nmap -sU <target>` | ICMP "port unreachable" replies for closed ports | `icmp.type==3 && icmp.code==3` |
| OS/Service Detection | `nmap -O -sV <target>` | Irregular/crafted packets, varied TTLs and flags | Inspect `ip.ttl` for anomalies |

**Interview tip:** the tell-tale sign of a scan versus normal traffic is a *single source IP* hitting *many destination ports* in rapid succession, usually with incomplete handshakes. Sort by source IP and time after applying the SYN filter above.

---

## 8. ARP Poisoning & Man-in-the-Middle

ARP has no built-in authentication, which lets an attacker force two hosts to route traffic through their own machine by lying about MAC-to-IP mappings.

**How to spot it:**

| Indicator | Filter |
|---|---|
| All ARP traffic | `arp` |
| Gratuitous ARP (unsolicited reply) | `arp.opcode==2 && arp.src.proto_ipv4==arp.dst.proto_ipv4` |
| Duplicate IP conflict | Watch for Wireshark's built-in *"Duplicate IP address configured"* expert info flag |

A single IP being claimed by two different MAC addresses in a short window is close to a smoking gun for ARP spoofing.

**Interview tip:** mitigations include Dynamic ARP Inspection (DAI) on managed switches, static ARP entries for critical hosts, and passive monitoring tools like `arpwatch`.

---

## 9. Tunneling Traffic: DNS and ICMP

DNS and ICMP are common covert channels because both are rarely blocked outbound by firewalls.

| Technique | Normal Behavior | Abuse Indicator | Filter |
|---|---|---|---|
| DNS Tunneling | Short queries, standard record types (A, AAAA, MX) | Abnormally long subdomains, high volume of TXT/NULL queries, high-entropy names | `dns.qry.name.len > 50` |
| ICMP Tunneling | Small, fixed-size Echo Request/Reply payloads (~32–64 bytes) | Oversized or irregular payloads carrying encoded data | `icmp && data.len > 64` |

**Interview tip:** the giveaway is almost always **payload size and entropy** — legitimate DNS/ICMP traffic is small and predictable; tunneled data is bulkier and often looks base32/base64-encoded under the hex dump.

---

## 10. Cleartext Protocol Analysis: FTP and HTTP

### FTP
FTP separates control (port 21) and data (port 20) channels, and by default transmits **everything in plaintext**, including credentials.

- Filter: `ftp` for control, `ftp-data` for transferred files
- Right-click → **Follow → TCP Stream** to reconstruct the session:

```
USER admin
PASS SuperSecret123
```

### HTTP
Same exposure, applied to web traffic.

| Filter | Purpose |
|---|---|
| `http.request` | All HTTP requests |
| `http.request.method=="POST"` | Likely login/form submissions |
| `http.authorization` | Basic Auth headers (base64-encoded, trivially decoded) |
| `http contains "password"` | Keyword search across HTTP traffic |

**Follow → HTTP Stream** reconstructs the full request/response, often revealing usernames and passwords directly in POST bodies or Authorization headers.

**Interview tip:** this is the textbook argument for *why cleartext protocols are a liability* — anyone with a network tap or MITM position (see Section 8) can trivially recover credentials.

---

## 11. Encrypted Protocol Analysis: Decrypting HTTPS

HTTPS is encrypted via TLS, so **Follow → TLS Stream** normally shows garbage — but Wireshark can decrypt it with the right key material.

**Two decryption methods:**

1. **RSA private key** — only works with older TLS versions/cipher suites lacking forward secrecy. Load via *Edit → Preferences → Protocols → TLS → RSA keys list*.
2. **Pre-Master Secret / SSLKEYLOGFILE** — the modern approach. If the browser/application logged session keys, point Wireshark at that file under *TLS → (Pre)-Master-Secret log filename*.

```bash
# Capture TLS session keys from a browser session
export SSLKEYLOGFILE=~/sslkeys.log
```

Once loaded, HTTPS traffic decrypts inline and filters/reads just like plain HTTP.

**Interview tip:** this is exactly how Wireshark and tools like Burp Suite are used together in authorized pentests — decrypting your *own* traffic for analysis, never someone else's without a legitimate key.

---

## 12. Credential Hunting Across a Capture

A consolidation technique: sweep the whole capture for credentials across every cleartext protocol present.

| Protocol | Filter |
|---|---|
| FTP | `ftp.request.command=="USER"` / `ftp.request.command=="PASS"` |
| HTTP | `http.request.method=="POST"` + Follow Stream |
| Telnet | `telnet` |
| Basic Auth | `http.authorization` |

**Blunt-force sweep** regardless of protocol: `frame contains "password"` or `frame contains "pass="`.

---

## 13. From Findings to Actionable Results

Anyone can spot an issue in a capture — the higher-value skill is turning it into a prioritized fix. This is the part interviewers actually probe for.

| Finding | Recommendation |
|---|---|
| ARP spoofing observed | Enable Dynamic ARP Inspection (DAI); use static ARP entries for critical assets |
| Cleartext FTP/HTTP credentials | Migrate to FTPS/SFTP and HTTPS-only; enforce HSTS |
| DNS/ICMP tunneling indicators | Deploy DNS query monitoring/logging; restrict outbound ICMP payload size |
| Weak Kerberos service accounts | Enforce strong/managed service account passwords to resist Kerberoasting |
| Unrestricted Nmap-style scanning succeeded | Add IDS/IPS rules for scan-pattern detection, segment the network |

---

## 14. Master Filter Cheat Sheet

A single table to keep open during practice or an exam:

| Goal | Filter |
|---|---|
| Isolate a host | `ip.addr==10.0.0.5` |
| Isolate a conversation | `ip.addr==10.0.0.5 && ip.addr==10.0.0.10` |
| Find half-open scans | `tcp.flags.syn==1 && tcp.flags.ack==0` |
| Find UDP closed-port replies | `icmp.type==3 && icmp.code==3` |
| Spot gratuitous ARP | `arp.opcode==2 && arp.src.proto_ipv4==arp.dst.proto_ipv4` |
| DHCP lease traffic | `bootp` |
| NetBIOS name queries | `nbns` |
| Kerberos exchanges | `kerberos` |
| Long/suspicious DNS queries | `dns.qry.name.len > 50` |
| Oversized ICMP payloads | `icmp && data.len > 64` |
| FTP credentials | `ftp.request.command=="USER" \|\| ftp.request.command=="PASS"` |
| HTTP POST (logins) | `http.request.method=="POST"` |
| Basic Auth headers | `http.authorization` |
| Keyword sweep | `frame contains "password"` |

---

## Closing Thoughts

This covers the full arc of practical Wireshark work: reading the interface and statistics, building filters from simple to compound, identifying hosts and protocols, recognizing recon and MITM activity, catching covert tunneling, harvesting cleartext credentials, decrypting HTTPS, and — critically — turning all of it into actionable remediation. It mirrors the real flow of an investigation, which makes it solid material to walk through directly in a "tell me about a time you analyzed a PCAP" interview answer.

---
*Part of an ongoing TryHackMe study series.*
