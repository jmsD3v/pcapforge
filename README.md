# 📡 PCAPForge — Network Forensics Investigator

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PCAP](https://img.shields.io/badge/PCAP-dpkt-0077b6?style=for-the-badge)
![Detectors](https://img.shields.io/badge/Detectors-3_Layers-6a0dad?style=for-the-badge)
![Gemini](https://img.shields.io/badge/Gemini_AI-Free_Tier-4285F4?style=for-the-badge&logo=google&logoColor=white)
![Portfolio](https://img.shields.io/badge/Portfolio-F--03_Forensics-8B0000?style=for-the-badge)

**PCAP/PCAPNG analysis — flow reconstruction, DNS/HTTP/TLS parsing, attack detection, AI incident narrative**

*F-03 of 9 · Cybersecurity Portfolio by [@jmsDev](https://www.linkedin.com/in/jmsilva83)*

</div>

---

## What it does

PCAPForge parses PCAP and PCAPNG captures using **dpkt** — reconstructing TCP/UDP flows, DNS queries, HTTP requests, and TLS sessions — then runs three detection modules (flow anomalies, DNS attacks, HTTP attacks) and feeds all findings to **Google Gemini** for incident narrative and kill chain reconstruction.

```bash
pcapforge analyze capture.pcap
pcapforge flows capture.pcap --top 20
pcapforge dns capture.pcap --suspicious
pcapforge demo
```

---

## Features

- **Full flow reconstruction** — bidirectional TCP/UDP flows with packet counts, bytes, duration
- **DNS parsing** — A/AAAA/MX/TXT/PTR queries + response IP extraction
- **HTTP parsing** — method, host, path, User-Agent, status code
- **TLS SNI extraction** — Server Name Indication from ClientHello (without decryption)
- **3 detection modules** — flow anomalies, DNS attacks, HTTP attacks — all pattern-matched
- **AI incident narrative** — Gemini reconstructs attack timeline, identifies threat actor type, maps kill chain
- **MITRE ATT&CK tagging** — every finding tagged with technique IDs
- **HTML report** — findings table, top flows, suspicious DNS, IOC list, AI kill chain
- **JSON export** — machine-readable for SIEM/pipeline integration

---

## Detection Modules

### Flow Detector
Network-level attack pattern recognition:

| Detection | Threshold | MITRE |
|---|---|---|
| **Port scan** | ≥ 20 unique ports from single src IP | T1046 |
| **C2 beaconing** | ≥ 5 periodic connections, CV < 0.3 | T1071, T1571 |
| **Lateral movement** | ≥ 3 internal hosts on admin ports (445, 3389, 135...) | T1021 |
| **Suspicious ports** | Any connection to 4444, 31337, 1337, 6667... | T1571 |
| **Large outbound transfer** | > 50 MB to external host | T1048, T1041 |
| **RDP brute force** | ≥ 10 external connections to port 3389 | T1110.001 |

### DNS Detector
DNS-based attack and covert channel detection:

| Detection | Method | MITRE |
|---|---|---|
| **DGA domains** | Shannon entropy + consonant ratio + vowel absence | T1568.002 |
| **DNS tunneling** | Long labels (> 50 chars), deep nesting (> 6 levels), encoded TXT | T1071.004 |
| **Fast-flux** | Single domain → ≥ 5 different IPs | T1568.001 |
| **NXDOMAIN storm** | ≥ 20 failed lookups from same src (DGA iteration) | T1568.002 |
| **Suspicious TLDs** | .tk, .ml, .ga, .xyz, .top, .pw and 10 more | T1071.004 |

### HTTP Detector
Web-layer attack detection:

| Detection | Patterns | MITRE |
|---|---|---|
| **SQL injection** | 15+ SQLi patterns (UNION SELECT, OR 1=1, xp_cmdshell...) | T1190 |
| **XSS** | Script tags, onerror, javascript:, document.cookie | T1059.007 |
| **Path traversal** | `../`, `%2e%2e/`, `/etc/passwd`, `/proc/self` | T1083 |
| **Webshell request** | cmd=, shell=, eval(, phpinfo, c99, r57 | T1505.003 |
| **Scanner User-Agent** | nikto, sqlmap, nmap, gobuster, ZAP, Burp, nuclei... | T1595 |
| **C2 User-Agent** | meterpreter, cobalt strike, empire, sliver strings | T1071.001 |
| **Sensitive paths** | /.env, /.git/, /wp-config.php, /admin/, /phpmyadmin/ | T1083 |
| **HTTP brute force** | ≥ 10 POSTs to login endpoints from same src | T1110.001 |

---

## Installation

```bash
git clone https://github.com/jmsdev83/pcapforge
cd pcapforge
pip install -e .

cp .env.example .env
# Add GEMINI_API_KEY for AI narrative (optional)
```

---

## Usage

```bash
# Full forensic analysis with AI
pcapforge analyze capture.pcap

# Analysis without AI
pcapforge analyze capture.pcap --no-ai

# Export HTML report
pcapforge analyze capture.pcap --output report.html

# Export JSON
pcapforge analyze capture.pcap --output findings.json --format json

# Show top 20 flows by bytes
pcapforge flows capture.pcap --top 20

# DNS analysis — show all queries
pcapforge dns capture.pcap

# DNS analysis — suspicious only
pcapforge dns capture.pcap --suspicious

# Demo with synthetic attack PCAP
pcapforge demo
```

---

## Architecture

```
pcapforge analyze <file>
        │
        ▼
  PcapReader (dpkt)           ← parse all packets → flows, DNS, HTTP, TLS
        │
        ▼
  Three detectors (parallel)
  ┌─────┴─────────────────────────────────────────┐
  │  FlowDetector    ← port scan, beaconing,       │
  │                     lateral movement, exfil    │
  │  DnsDetector     ← DGA, tunneling, fast-flux   │
  │  HttpDetector    ← SQLi, XSS, scanners, C2 UA  │
  └─────┬─────────────────────────────────────────┘
        │
        ▼
  GeminiAnalyzer              ← NARRATIVE + THREAT_ACTOR + KILL_CHAIN + MITRE
        │
        ▼
  Rich terminal + HTML report
```

---

## AI Kill Chain Output

```
╔══════════════════════════════════════════════════════════════╗
║  AI Incident Narrative                                       ║
║  Attacker at 192.168.1.100 began with a systematic port     ║
║  scan of 10.0.0.5, then established C2 communication via    ║
║  HTTP beacons to 198.51.100.10:4444. Following credential   ║
║  compromise, lateral movement to 6 internal hosts via SMB   ║
║  and RDP was observed, culminating in large data transfer   ║
║  to an external IP, suggesting exfiltration.                ║
╚══════════════════════════════════════════════════════════════╝

Threat Actor: APT — coordinated multi-stage attack with clear TTPs

Kill Chain:
  1. Reconnaissance — port scan of internal host
  2. Initial Access — exploitation via open C2 port
  3. Execution — HTTP beacon communication established
  4. Lateral Movement — SMB/RDP to 6 internal hosts
  5. Exfiltration — 70 MB transferred to external IP

MITRE: T1046, T1071, T1021, T1021.002, T1048, T1041
```

---

## Supported PCAP Formats

| Format | Notes |
|---|---|
| `.pcap` | Classic libpcap format |
| `.pcapng` | Next-generation capture format |
| Ethernet II | Standard Ethernet frames |
| IPv4 | TCP, UDP, ICMP |
| IPv6 | Supported via dpkt |

---

## Project Structure

```
pcapforge/
├── pcapforge/
│   ├── parsers/
│   │   └── pcap_reader.py       # dpkt PCAP parsing: flows, DNS, HTTP, TLS SNI
│   ├── detectors/
│   │   ├── flow_detector.py     # Port scan, beaconing, lateral movement, exfil
│   │   ├── dns_detector.py      # DGA, tunneling, fast-flux, NXDOMAIN storm
│   │   └── http_detector.py     # SQLi, XSS, traversal, scanner UAs, brute force
│   ├── core/
│   │   ├── analyzer.py          # Main analysis pipeline
│   │   └── ai_analyzer.py       # Gemini narrative + kill chain
│   ├── types/
│   │   └── network.py           # ConnectionFlow, DnsQuery, HttpRequest, ForensicFinding
│   ├── report/
│   │   ├── generator.py
│   │   └── template.html
│   └── cli/
│       └── main.py
└── pyproject.toml
```

---

## Environment Variables

```env
GEMINI_API_KEY=             # AI incident narrative + kill chain (optional)
```

---

## Portfolio

| # | Category | Project | Status |
|---|---|---|---|
| P-01 | Offensive | ReconAI — Recon Orchestrator | ✅ |
| P-02 | Offensive | WebHunter — OWASP Top 10 Scanner | ✅ |
| P-03 | Offensive | PhishSim — Red Team Phishing | ✅ |
| D-01 | Defensive | SOC-Lite — AI SIEM | ✅ |
| D-02 | Defensive | ThreatFeed — CTI Aggregator | ✅ |
| D-03 | Defensive | HoneyGrid — SSH/HTTP Honeypot | ✅ |
| F-01 | Forensics | DFIR-Auto — Forensic Triage | ✅ |
| F-02 | Forensics | MalwareScope — Malware Analyzer | ✅ |
| F-03 | Forensics | **PCAPForge** ← you are here | ✅ |

---

<div align="center">

Copyright © 2025 Desarrollado desde Las Breñas con 💜 por [@jmsDev](https://www.linkedin.com/in/jmsilva83) · All rights reserved

</div>
