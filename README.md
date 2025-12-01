# IEEE CyberSecurity Competition 2025 - DFIR Hunters

[![DFIR][dfir-badge]][dfir-url]
[![Forensics][forensics-badge]][forensics-url]
[![Incident Response][ir-badge]][ir-url]
[![Threat Hunting][th-badge]][th-url]
[![Malware Analysis][malware-badge]][malware-url]

[dfir-badge]: https://img.shields.io/badge/DFIR-Digital%20Forensics-FF6B6B?style=flat&logo=search&logoColor=white
[dfir-url]: https://www.sans.org/cyber-security-courses/digital-forensics-essentials/
[forensics-badge]: https://img.shields.io/badge/Forensics-Investigation-4ECDC4?style=flat&logo=magnifying-glass&logoColor=white
[forensics-url]: https://www.forensicfocus.com/
[ir-badge]: https://img.shields.io/badge/Incident%20Response-Analysis-95E1D3?style=flat&logo=security&logoColor=white
[ir-url]: https://www.incidentresponse.com/
[th-badge]: https://img.shields.io/badge/Threat%20Hunting-Detection-F38181?style=flat&logo=target&logoColor=white
[th-url]: https://www.threathunting.net/
[malware-badge]: https://img.shields.io/badge/Malware%20Analysis-Reverse%20Engineering-AA96DA?style=flat&logo=bug&logoColor=white
[malware-url]: https://www.malware-traffic-analysis.net/

## Overview

This repository contains comprehensive Digital Forensics and Incident Response (DFIR) challenges for IEEE CyberSecurity Competition 2025. Each lab provides hands-on experience with real-world attack scenarios, complete with automated deployment scripts, packet captures, memory dumps, and detailed writeups.

**Repository:** [https://github.com/qays3/DFIR-Hunters](https://github.com/qays3/DFIR-Hunters)

## Competition Structure

### Qualification Round

| Challenge | Category | Difficulty | Description | Port |
|-----------|----------|-----------|-------------|------|
| [NetRules Hunter](https://github.com/qays3/DFIR-Hunters/tree/main/Qualification/NetRules%20Hunter) | Network Security | Medium | Network intrusion detection with Snort rules - analyze PCAP containing 6 attack patterns (SSH brute force, SQL injection, DNS tunneling, Cobalt Strike, ransomware C2, data exfiltration) | 5001 |
| [CryptoMiner Hunter](https://github.com/qays3/DFIR-Hunters/tree/main/Qualification/CryptoMiner%20Hunter) | Memory Forensics | Hard | Ubuntu memory dump analysis - investigate cryptojacking attack with XMRig miner, SSH compromise, and persistence mechanisms using Volatility 3 | 5003 |
| [APT41](https://github.com/qays3/DFIR-Hunters/tree/main/Qualification/APT41) | Network Forensics | Medium | APT41 multi-stage attack analysis - examine corporate network breach with C2 beacons, credential harvesting, DNS tunneling, and data exfiltration | 5007 |
| [LAZARUS HEIST](https://github.com/qays3/DFIR-Hunters/tree/main/Qualification/LAZARUS%20HEIST) | Banking Malware | Medium | Lazarus Group SWIFT heist - analyze $96M banking fraud with keylogger deployment, credential theft, and cryptocurrency mining | 5005 |

### Finals Round

| Challenge | Category | Difficulty | Description | Port |
|-----------|----------|-----------|-------------|------|
| [GPP Hunter](https://github.com/qays3/DFIR-Hunters/tree/main/Final/GPP%20Hunter) | Active Directory | Medium | CVE-2014-1812 Group Policy Preferences password extraction - decrypt credentials from SYSVOL share using Microsoft's published AES key | 5009 |
| [SOC (Logs Hunter)](https://github.com/qays3/DFIR-Hunters/tree/main/Final/SOC) | SIEM Analysis | Medium | ELK Stack log analysis - investigate trojanized GitHub repository with backdoor deployment, persistence, and anti-forensics via Kibana queries | 5000 |
| [SupplyChain Hunter](https://github.com/qays3/DFIR-Hunters/tree/main/Final/SupplyChain%20Hunter) | DevSecOps | Easy | CI/CD supply chain attack - analyze compromised GitLab pipeline with credential harvesting, financial data theft, and backdoor deployment | 5006 |

## Directory Structure

```
DFIR-Hunters/
├── README.md
├── Qualification/
│   ├── NetRules Hunter/
│   │   ├── README.md
│   │   ├── create.py (Traffic generator)
│   │   ├── excatrct.sh (Attack extraction)
│   │   ├── solution.rules
│   │   └── app/
│   ├── CryptoMiner Hunter/
│   │   ├── README.md
│   │   ├── memory-lime.lime (8GB memory dump)
│   │   ├── ubuntu-6.8.0-71-generic.json (Symbol table)
│   │   └── app/
│   ├── APT41/
│   │   ├── README.md
│   │   ├── APT41.pcap
│   │   ├── solution.json
│   │   └── app/
│   └── LAZARUS HEIST/
│       ├── README.md
│       ├── lazarus_attack.pcap
│       ├── solution.json
│       └── app/
└── Final/
    ├── GPP Hunter/
    │   ├── README.md
    │   ├── solve.py (Decryption script)
    │   ├── challenge.pcap
    │   └── app/
    ├── SOC/
    │   ├── README.md
    │   ├── setup.sh (ELK deployment)
    │   ├── solution.md
    │   └── app/
    └── SupplyChain Hunter/
        ├── README.md
        ├── Create.sh (Docker environment)
        ├── cloud_attack.pcap
        └── app/
```

## Technologies & Tools

### Network Forensics
- Wireshark / tshark
- Snort IDS/IPS
- NetworkMiner
- Zeek (Bro)

### Memory Forensics
- Volatility 3
- LiME (Linux Memory Extractor)
- dwarf2json (Symbol table generation)

### SIEM & Log Analysis
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Filebeat
- Auditbeat
- KQL (Kibana Query Language)

### Active Directory Security
- PowerShell
- PyCryptodome
- Scapy

### DevSecOps Security
- GitLab CI/CD
- Docker & Docker Compose
- Python
- Bash scripting

## Quick Start

### Qualification Round

#### NetRules Hunter
```bash
docker build -t netrules .
docker run -d --name NetRules -p 5001:5001 --restart unless-stopped netrules
```
Access: http://localhost:5001

#### CryptoMiner Hunter
```bash
docker build -t cryptominer .
docker run -d --name CryptoMiner -p 5003:5003 --restart unless-stopped cryptominer
```
Access: http://localhost:5003

#### APT41
```bash
docker build -t apt41 .
docker run -d --name APT41 -p 5007:5007 --restart unless-stopped apt41
```
Access: http://localhost:5007

#### LAZARUS HEIST
```bash
docker build -t lazarus .
docker run -d --name LAZARUS -p 5005:5005 --restart unless-stopped lazarus
```
Access: http://localhost:5005

### Finals Round

#### GPP Hunter
```bash
docker build -t gpp .
docker run -d --name GPP -p 5009:5009 --restart unless-stopped gpp
```
Access: http://localhost:5009?access=29910461-9afb-4c57-b4a4-b7ff2026d72c

#### SOC (Logs Hunter)
```bash
docker build -t soc .
docker run -d --name SOC -p 5000:5000 --restart unless-stopped soc
```
Access: http://localhost:5000/?access=29910461-9afb-4c57-b4a4-b7ff2026d72c

External Access: http://84.247.162.93:5601 (Kibana)
- Username: player
- Password: q4y$_h3r333333

#### SupplyChain Hunter
```bash
docker build -t supplychain .
docker run -d --name SupplyChain -p 5006:5006 --restart unless-stopped supplychain
```
Access: http://localhost:5006/?access=29910461-9afb-4c57-b4a4-b7ff2026d72c

## Challenge Highlights

### Qualification Round

**NetRules Hunter** - Write Snort detection rules for 6 real attack patterns embedded in network traffic. Learn behavioral vs signature-based detection, regex patterns, and threshold-based alerting.

**CryptoMiner Hunter** - Analyze Ubuntu memory dump to uncover SSH-based cryptojacking. Extract process trees, network connections, command histories, and kernel modules using Volatility 3.

**APT41** - Investigate sophisticated APT attack chain spanning initial compromise through data exfiltration. Track C2 infrastructure, credential harvesting, DNS tunneling, and Kerberos attacks.

**LAZARUS HEIST** - Dissect North Korean state-sponsored banking malware targeting SWIFT systems. Decrypt XOR-encoded payloads, trace $96M fraudulent transfers, and analyze persistence mechanisms.

### Finals Round

**GPP Hunter** - Exploit CVE-2014-1812 to decrypt Group Policy Preferences passwords using Microsoft's publicly disclosed AES key. Extract credentials from SYSVOL share in network capture.

**SOC (Logs Hunter)** - Hunt threats in ELK Stack logs from trojanized GitHub repository attack. Query Filebeat and Auditbeat data to uncover backdoor deployment, privilege escalation, and anti-forensics.

**SupplyChain Hunter** - Analyze CI/CD supply chain compromise through GitLab pipeline. Trace malicious runner registration, credential exfiltration, and production server backdoors in PCAP.

## Key Learning Objectives

- **Network Traffic Analysis**: Deep packet inspection, protocol analysis, attack pattern recognition
- **Memory Forensics**: Process analysis, malware detection, artifact extraction from RAM dumps
- **Log Analysis**: SIEM queries, correlation, timeline reconstruction, threat hunting
- **Malware Analysis**: Static analysis, dynamic behavior, IOC extraction, decryption techniques
- **Active Directory Security**: GPP vulnerabilities, credential attacks, domain exploitation
- **DevSecOps**: CI/CD security, supply chain attacks, pipeline compromise detection
- **Incident Response**: Attack chain reconstruction, evidence collection, root cause analysis

## Repository Navigation

- [`/Qualification/`](https://github.com/qays3/DFIR-Hunters/tree/main/Qualification) - First round challenges (NetRules, CryptoMiner, APT41, LAZARUS)
- [`/Final/`](https://github.com/qays3/DFIR-Hunters/tree/main/Final) - Championship round challenges (GPP, SOC, SupplyChain)
- Each challenge folder contains:
  - `README.md` - Complete documentation with scenarios, attack analysis, and solutions
  - `app/` - Docker-based challenge application
  - `Create/` or `Build/` - Automated environment setup scripts
  - `Solve/` - Solution scripts and writeups
  - Challenge artifacts (PCAP files, memory dumps, logs)

## Documentation

Each challenge includes comprehensive documentation:

1. **Scenario Overview** - Attack background and objectives
2. **Infrastructure Setup** - Deployment instructions and architecture
3. **Attack Methodology** - Complete attack chain breakdown
4. **Analysis Walkthrough** - Step-by-step investigation guide
5. **Investigation Questions** - Challenge objectives with solutions
6. **Incident Report** - Executive summary and technical findings
7. **Defense Strategies** - Remediation and security hardening
8. **References** - Tools, techniques, and further reading

## Author

**Challenge Designer:** Qays Sarayra  
**Contact:** info@qayssarayra.com  
**Specializations:**
- Network Security & Intrusion Detection
- Memory Forensics & Malware Analysis
- Active Directory Security
- SOC Operations & SIEM Engineering
- DevSecOps & Supply Chain Security

## License

This repository is part of IEEE CyberSecurity Competition 2025.

Educational use only. All attack scenarios are simulated in isolated environments for training purposes.

---

**Competition:** IEEE CyberSecurity Competition 2025  
**Category:** Digital Forensics and Incident Response (DFIR)  
**Repository:** https://github.com/qays3/DFIR-Hunters