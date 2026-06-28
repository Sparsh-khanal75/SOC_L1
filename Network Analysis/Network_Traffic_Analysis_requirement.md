# 📡 Network Traffic Analysis Summary

> [!NOTE]
> **Logs tell you _what happened_; PCAP tells you _exactly how it happened_.**

## 🎯 Why do we analyze network traffic?

Logs only record **selected fields** of a packet (IP, ports, protocol, etc.).

A **Packet Capture (PCAP)** contains the **entire packet**, including all headers and payload, making it possible to detect attacks that logs alone cannot.

> [!TIP]
> **Example**
> - **Firewall Log:** `User downloaded suspicious_package.zip`
> - **PCAP:** Contains the complete ZIP file, allowing you to extract and analyze the malware.

---

# 🌐 TCP/IP Layers

## 1️⃣ Application Layer

### 📦 Contains

- **Application Headers** → `GET /login HTTP/1.1`, `POST /upload`
- **Actual Data (Payload)** → `username=admin&password=P@ssw0rd`, `invoice.pdf`

### 📋 Logs Show

- **URL** → `https://example.com/downloads/suspicious_package.zip`
- **HTTP Method** → `GET`
- **Status Code** → `200 OK`
- **User-Agent** → `Mozilla/5.0 (Windows NT 10.0; Win64; x64)`

### 📦 PCAP Also Shows

- **Downloaded Files** → `suspicious_package.zip`
- **Credentials** → `username=admin`, `password=P@ssw0rd`
- **Commands** → `POST /api/deleteUser`
- **Malware Payload** → Actual contents of `invoice.exe`

> [!WARNING]
> **Example Attack: Malware Delivery**
>
> 1. User visits a malicious website.
> 2. User downloads `suspicious_package.zip`.
> 3. The ZIP contains `invoice.exe`.
> 4. User executes it.
> 5. Malware infects the system.
>
> **Logs:** Only show the download occurred.
>
> **PCAP:** Lets you recover the ZIP and analyze the malware.

---

## 2️⃣ Transport Layer (TCP/UDP)

### 📦 Contains

- **Source Port** → `51432`
- **Destination Port** → `443 (HTTPS)`
- **TCP Flags** → `SYN`, `ACK`, `FIN`, `RST`
- **Sequence Number** → `Seq=1461`
- **Acknowledgment Number** → `Ack=2921`
- **Window Size** → `Win=64240`

### 📋 Logs Show

- **Source Port** → `51432`
- **Destination Port** → `443`
- **TCP Flags** → `SYN`

```text
src=192.168.1.45
dst=172.217.22.14
sport=51432
dport=443
flags=SYN
```

### 📦 PCAP Also Shows

- **Sequence Number** → `Seq=1461`
- **ACK Number** → `Ack=2921`
- **Window Size** → `Win=64240`
- **Entire TCP Conversation**

> [!WARNING]
> **Example Attack: Session Hijacking**
>
> Normal Handshake:
>
> ```text
> SYN → SYN-ACK → ACK
> ```
>
> Normal Sequence:
>
> ```text
> Seq=1
> Seq=1461
> Seq=2921
> ```
>
> Suspicious Packet:
>
> ```text
> Seq=34567232
> ```
>
> A sudden jump in the sequence number may indicate packet injection.
>
> **Logs:** Only show ports and flags.
>
> **PCAP:** Reveals abnormal sequence numbers.

---

## 3️⃣ Internet Layer (IP)

### 📦 Contains

- **Source IP** → `192.168.1.45`
- **Destination IP** → `172.217.22.14`
- **TTL** → `64`
- **Fragment Offset** → `1480`
- **Fragment ID** → `0x1a2b`

### 📋 Logs Show

- **Source IP** → `192.168.1.45`
- **Destination IP** → `172.217.22.14`
- **TTL** → `64`

```text
src=192.168.1.45
dst=172.217.22.14
ttl=64
```

### 📦 PCAP Also Shows

- **Fragment Offset** → `1480`
- **Fragment ID** → `0x1a2b`
- **MF Flag** → `MF=1`
- **Total Length** → `1500 bytes`

> [!WARNING]
> **Example Attack: Fragmentation Attack**
>
> Normal:
> ```text
> Offset=0
> Offset=1480
> Offset=2960
> ```
>
> Malicious:
> ```text
> Offset=0
> Offset=1480
> Offset=1480
> ```
>
> Overlapping fragments can cause an IDS and the destination host to reconstruct packets differently.
>
> **Logs:** Don't include fragment offsets.
>
> **PCAP:** Clearly reveals overlapping fragments.

---

## 4️⃣ Link Layer (Ethernet)

### 📦 Contains

- **Source MAC** → `00:11:22:33:44:55`
- **Destination MAC** → `AA:BB:CC:DD:EE:FF`
- **ARP Information**

### 📋 Logs Show

- **Source MAC** → `00:11:22:33:44:55`
- **Destination MAC** → `AA:BB:CC:DD:EE:FF`

### 📦 PCAP Also Shows

- **ARP Request** → `Who has 192.168.1.1?`
- **ARP Reply** → `192.168.1.1 is at 00:11:22:33:44:55`
- **Gratuitous ARP Packets**
- **Conflicting ARP Replies**

> [!WARNING]
> **Example Attack: ARP Poisoning (MITM)**
>
> Normal:
>
> ```text
> Who has 192.168.1.1?
> 192.168.1.1 is at 00:11:22:33:44:55
> ```
>
> Attacker:
>
> ```text
> 192.168.1.1 is at AA:BB:CC:DD:EE:FF
> ```
>
> Traffic Flow:
>
> ```text
> Victim
>    ↓
> Attacker
>    ↓
> Router
> ```
>
> The attacker can intercept, modify, or forward traffic.
>
> **Logs:** Only show MAC addresses.
>
> **PCAP:** Reveals fake ARP replies and MAC conflicts.

---

# 📊 Logs vs PCAP

| Layer | Logs Show | PCAP Shows |
|--------|-----------|------------|
| 🌐 Application | URL (`/downloads/file.zip`), HTTP Method (`GET`), Status (`200 OK`) | Actual payload (`file.zip`), credentials, malware |
| 🚚 Transport | Ports (`51432 → 443`), TCP Flags (`SYN`) | Sequence (`Seq=1461`), ACK (`Ack=2921`), Window Size (`Win=64240`), TCP Stream |
| 🌍 Internet | Source IP (`192.168.1.45`), Destination IP (`172.217.22.14`), TTL (`64`) | Fragment Offset (`1480`), Fragment ID (`0x1a2b`), MF Flag |
| 🔗 Link | Source/Destination MAC (`00:11:22:33:44:55`) | Complete ARP traffic, Gratuitous ARP, MAC conflicts |

---

# 🎯 Key Takeaways

- ✅ Every packet passes through **Application → Transport → Internet → Link**
- ✅ Every layer adds its own header.
- ✅ Logs provide only a **summary**.
- ✅ PCAP contains the **complete packet**.
- ✅ Many attacks require packet captures for proper investigation.

> [!IMPORTANT]
> Some attacks **cannot be detected from logs alone** because the required information exists only inside the complete packet.

---

# ⚔️ Attacks by Layer

| Layer | Attack | Example |
|--------|--------|---------|
| 🌐 Application | Malware Delivery | Downloading `suspicious_package.zip` containing `invoice.exe` |
| 🚚 Transport | Session Hijacking | Fake packet injected with `Seq=34567232` |
| 🌍 Internet | Fragmentation Attack | Overlapping fragments using `Offset=1480` twice |
| 🔗 Link | ARP Poisoning (MITM) | Fake ARP reply: `192.168.1.1 is at AA:BB:CC:DD:EE:FF` |

---

# 🧠 Memory Trick

> [!TIP]
> **Logs tell you _what happened_.**
>
> **PCAP tells you _exactly how it happened_.**
