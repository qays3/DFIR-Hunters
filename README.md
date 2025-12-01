# IEEE CyberSecurity Competition 2025 - Workstation

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

This workstation contains source code and automated build scripts for IEEE CyberSecurity Competition 2025 challenges. Each lab includes automated scripting for deployment and writeups documenting solution approaches.

## Competition Structure

### Qualification Round

| Challenge | Difficulty | Status |
|-----------|-----------|--------|
| NetRules Hunter | Mid | ✓ |
| CryptoMiner Hunter | Hard | ✓ |
| APT41 | Mid | ✓ |
| LAZARUS HEIST | Mid | ✓ |

### Finals Round

| Challenge | Difficulty | Status |
|-----------|-----------|--------|
| GPP Hunter | Mid | ✓ |
| Logs Hunter (SOC) | Mid | ✓ |
| SupplyChain Hunter | Mid | ✓ |

## Directory Structure
```
DFIR/
├── Qualification/
│   ├── NetRules Hunter/
│   ├── CryptoMiner Hunter/
│   ├── APT41/
│   └── LAZARUS HEIST/
└── Final/
    ├── GPP Hunter/
    ├── SOC/
    └── SupplyChain Hunter/
```

## Build Process

Each challenge directory contains automated scripts for environment setup, deployment, and validation. Writeups document the challenge design, intended solution path, and alternative approaches.

## Technologies Used

Challenges leverage various forensics and incident response tools including memory analysis frameworks, network traffic analysis utilities, log parsing tools, and threat intelligence platforms.

## Repository Navigation

- `/Qualification/` - First round challenges
- `/Final/` - Championship round challenges
- Each challenge folder contains build scripts and writeups