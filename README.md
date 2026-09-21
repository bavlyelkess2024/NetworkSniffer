# Task 1 — Basic Network Sniffer
### CodeAlpha Cyber Security Internship

## 📌 Objective
Build a Python program that captures live network traffic, parses the
packets, and displays useful information — source/destination IP
addresses, protocol, ports, and payload — to understand how data flows
across a network.

## 🛠 Tools & Libraries
- **Python 3**
- **Scapy** — for packet capturing and parsing

## ⚙️ How It Works
1. The script opens a raw socket (via Scapy) on the chosen network
   interface and puts it into a capture loop.
2. Every captured packet is inspected layer by layer:
   - **Ethernet layer** — used to detect non-IP frames (e.g. ARP).
   - **Network layer** — identifies IPv4 vs IPv6 and extracts the
     source/destination addresses.
   - **Transport layer** — identifies TCP, UDP, or ICMP, and extracts
     ports (with common ports like 80/HTTP, 443/HTTPS, 53/DNS labeled).
   - **Application layer** — if a raw payload is present, a safe,
     truncated (64-byte) printable preview is shown.
3. Each packet is printed with a timestamp, and optionally appended to
   a log file for later review.

## ▶️ Usage
```bash
# Install dependency
pip install scapy

# Basic capture (needs admin/root privileges to open a raw socket)
sudo python3 network_sniffer.py

# Capture only on a specific interface
sudo python3 network_sniffer.py -i eth0

# Stop automatically after 50 packets
sudo python3 network_sniffer.py -c 50

# Apply a BPF filter (e.g. only HTTP traffic)
sudo python3 network_sniffer.py -f "tcp port 80"

# Save output to a log file as well as printing it
sudo python3 network_sniffer.py -o capture.log
```

## 📋 Sample Output
```
======================================================================
 CodeAlpha Task 1 - Basic Network Sniffer
 Interface : ALL
 Filter    : none
 Count     : unlimited (Ctrl+C to stop)
======================================================================
[*] Note: capturing raw traffic usually requires root/admin privileges.

[14:02:11.482] IPv4 TCP           192.168.1.10 -> 142.250.premise | Ports: 52344 -> 443 (HTTPS) | flags=PA
    Payload (517 bytes): "\x17\x03\x03\x02\x00..."
[14:02:11.501] IPv4 UDP           192.168.1.10 -> 192.168.1.1   | Ports: 55123 -> 53 (DNS)
    Payload (34 bytes): "\x00\x01\x01\x00\x00\x01..."
```

## 🧠 What This Teaches
- How packets are structured across the OSI/TCP-IP layers.
- The difference between connection-oriented (TCP) and connectionless
  (UDP) protocols.
- How common protocols map to well-known ports.
- Why unencrypted payloads (e.g. plain HTTP) are a security risk —
  you can literally see the data in transit, which is why HTTPS,
  encryption, and secure protocols matter.

## ⚠️ Ethical & Legal Notice
This tool must only be used on networks and devices you **own** or have
**explicit written permission** to monitor (e.g. your own home lab or a
sanctioned test environment). Capturing traffic on networks without
authorization is illegal in most jurisdictions and violates the ethics
expected of a cybersecurity professional. This project is submitted
purely for educational purposes as part of the CodeAlpha internship.

## 📤 Submission Checklist
- [x] Source code (`network_sniffer.py`)
- [x] README with explanation and usage instructions
- [ ] Push to GitHub repo named `CodeAlpha_NetworkSniffer`
- [ ] Record a short video walkthrough and post on LinkedIn (tag @CodeAlpha)
- [ ] Submit via the CodeAlpha submission form
