````md
# Network Traffic Analysis Summary

## Why do we analyze network traffic?

Logs only record **selected fields** of a packet (IP, ports, protocol, etc.).

A **packet capture (PCAP)** contains the **entire packet**, including all headers and payload, making it possible to detect attacks that logs alone cannot.

**Example:**
- **Firewall Log:** `User downloaded suspicious_package.zip`
- **PCAP:** Contains the entire ZIP file, allowing you to extract it and analyze the malware inside.

---

# TCP/IP Layers

## 1. Application Layer

### Contains

- **Application Headers** → `GET /login HTTP/1.1`, `POST /upload`
- **Actual Data (Payload)** → `username=admin&password=P@ssw0rd`, `invoice.pdf`

### Logs Show

- **URL** → `https://example.com/downloads/suspicious_package.zip`
- **HTTP Method** → `GET`
- **Status Code** → `200 OK`
- **User-Agent** → `Mozilla/5.0 (Windows NT 10.0; Win64; x64)`

### PCAP Also Shows

- **Downloaded Files** → `suspicious_package.zip`
- **Credentials** → `username=admin`, `password=P@ssw0rd`
- **Commands** → `POST /api/deleteUser`
- **Malware Payload** → Actual contents of `invoice.exe`

### Example Attack: Malware Delivery

1. User visits a malicious website.
2. User downloads `suspicious_package.zip`.
3. The ZIP contains `invoice.exe`.
4. The user executes it.
5. Malware infects the system.

**Logs:** Only show the download occurred.

**PCAP:** Lets you recover the ZIP and analyze the malware.

---

## 2. Transport Layer (TCP/UDP)

### Contains

- **Source Port** → `51432`
- **Destination Port** → `443 (HTTPS)`
- **TCP Flags** → `SYN`, `ACK`, `FIN`, `RST`
- **Sequence Number** → `Seq=1461`
- **Acknowledgment Number** → `Ack=2921`
- **Window Size** → `Win=64240`

### Logs Show

- **Source Port** → `51432`
- **Destination Port** → `443`
- **TCP Flags** → `SYN`

**Example Log**

```text
src=192.168.1.45
dst=172.217.22.14
sport=51432
dport=443
flags=SYN
```

### PCAP Also Shows

- **Sequence Number** → `Seq=1461`
- **ACK Number** → `Ack=2921`
- **Window Size** → `Win=64240`
- **Entire TCP Conversation**

### Example Attack: Session Hijacking

**Normal TCP Handshake**

```text
SYN → SYN-ACK → ACK
```

**Normal Communication**

```text
Seq=1
Seq=1461
Seq=2921
```

**Attacker Packet**

```text
Seq=34567232
```

A huge jump in the sequence number suggests an attacker is attempting to inject packets into an existing TCP session.

**Logs:** Only show ports and TCP flags.

**PCAP:** Reveals abnormal sequence numbers, making the attack visible.

---

## 3. Internet Layer (IP)

### Contains

- **Source IP** → `192.168.1.45`
- **Destination IP** → `172.217.22.14`
- **TTL (Time To Live)** → `64`
- **Fragment Offset** → `1480`
- **Fragment ID** → `0x1a2b`

### Logs Show

- **Source IP** → `192.168.1.45`
- **Destination IP** → `172.217.22.14`
- **TTL** → `64`

**Example Log**

```text
src=192.168.1.45
dst=172.217.22.14
ttl=64
```

### PCAP Also Shows

- **Fragment Offset** → `1480`
- **Fragment ID** → `0x1a2b`
- **More Fragments (MF) Flag** → `MF=1`
- **Total Length** → `1500 bytes`

### Example Attack: Fragmentation Attack

**Normal Fragments**

```text
Offset=0
Offset=1480
Offset=2960
```

**Malicious Fragments**

```text
Offset=0
Offset=1480
Offset=1480
```

The overlapping fragment causes the IDS and the destination host to reconstruct the packet differently.

**Result:** The IDS may think the traffic is harmless while the destination receives malicious data.

**Logs:** Don't record fragment offsets.

**PCAP:** Clearly shows overlapping fragments.

---

## 4. Link Layer (Ethernet)

### Contains

- **Source MAC Address** → `00:11:22:33:44:55`
- **Destination MAC Address** → `AA:BB:CC:DD:EE:FF`
- **ARP Information**

### Logs Show

- **Source MAC** → `00:11:22:33:44:55`
- **Destination MAC** → `AA:BB:CC:DD:EE:FF`

### PCAP Also Shows

- **ARP Request** → `Who has 192.168.1.1?`
- **ARP Reply** → `192.168.1.1 is at 00:11:22:33:44:55`
- **Gratuitous ARP Packets**
- **Conflicting ARP Replies**

### Example Attack: ARP Poisoning (MITM)

**Normal ARP**

```text
Who has 192.168.1.1?
192.168.1.1 is at 00:11:22:33:44:55
```

**Attacker Reply**

```text
192.168.1.1 is at AA:BB:CC:DD:EE:FF
```

The victim updates its ARP cache with the attacker's MAC address.

Traffic now flows:

```text
Victim
   ↓
Attacker
   ↓
Router
```

The attacker can:
- Intercept traffic
- Modify packets
- Capture credentials
- Forward traffic without the victim noticing

**Logs:** Only show MAC addresses.

**PCAP:** Reveals fake ARP replies and conflicting MAC addresses.

---

# Logs vs PCAP

| Layer | Logs Show | PCAP Shows |
|--------|-----------|------------|
| **Application** | URL (`/downloads/file.zip`), HTTP Method (`GET`), Status (`200 OK`) | Actual payload (`file.zip`), credentials, malware |
| **Transport** | Ports (`51432 → 443`), TCP Flags (`SYN`) | Sequence (`Seq=1461`), ACK (`Ack=2921`), Window Size (`Win=64240`), TCP stream |
| **Internet** | Source IP (`192.168.1.45`), Destination IP (`172.217.22.14`), TTL (`64`) | Fragment Offset (`1480`), Fragment ID (`0x1a2b`), MF Flag |
| **Link** | Source/Destination MAC (`00:11:22:33:44:55`) | Complete ARP traffic, Gratuitous ARP, MAC conflicts |

---

# Key Takeaways

- Every network packet passes through **Application → Transport → Internet → Link**.
- Each layer adds its own header before passing the packet to the next layer.
- **Logs provide only a summary** of packet information.
- **Packet captures (PCAPs) contain the complete packet**, including every header and payload.
- Many attacks **cannot be detected from logs alone** because the required fields are missing.
- Packet captures provide the evidence needed for deep investigations and forensic analysis.

---

# Attacks by Layer (Easy to Remember)

| Layer | Attack | Example |
|--------|--------|---------|
| **Application** | Malware Delivery | User downloads `suspicious_package.zip` containing `invoice.exe` |
| **Transport** | Session Hijacking | Fake packet injected with `Seq=34567232` |
| **Internet** | Fragmentation Attack | Overlapping fragments using `Offset=1480` twice |
| **Link** | ARP Poisoning (MITM) | Fake ARP reply: `192.168.1.1 is at AA:BB:CC:DD:EE:FF` |

---

# One-line Memory Trick

> **Logs tell you _what happened_; PCAP tells you _exactly how it happened_.**
````
