# SupplyChain Hunter - DevSecOps CI/CD Attack Analysis

[![DFIR][dfir-badge]][dfir-url]
[![DevSecOps][devsecops-badge]][devsecops-url]
[![CI/CD Security][cicd-badge]][cicd-url]
[![Supply Chain][supply-badge]][supply-url]
[![Network Forensics][network-badge]][network-url]
[![GitLab][gitlab-badge]][gitlab-url]

[dfir-badge]: https://img.shields.io/badge/DFIR-Digital%20Forensics-FF6B6B?style=flat&logo=search&logoColor=white
[dfir-url]: https://www.sans.org/cyber-security-courses/digital-forensics-essentials/
[devsecops-badge]: https://img.shields.io/badge/DevSecOps-CI%2FCD%20Security-2ECC71?style=flat&logo=gitlab&logoColor=white
[devsecops-url]: https://www.devsecops.org/
[cicd-badge]: https://img.shields.io/badge/CI%2FCD-Pipeline%20Security-3498DB?style=flat&logo=jenkins&logoColor=white
[cicd-url]: https://owasp.org/www-project-devsecops-guideline/
[supply-badge]: https://img.shields.io/badge/Supply%20Chain-Attack%20Analysis-E74C3C?style=flat&logo=supply&logoColor=white
[supply-url]: https://www.cisa.gov/supply-chain-risk-management
[network-badge]: https://img.shields.io/badge/Network%20Forensics-PCAP%20Analysis-5DADE2?style=flat&logo=wireshark&logoColor=white
[network-url]: https://www.netresec.com/
[gitlab-badge]: https://img.shields.io/badge/GitLab-CI%2FCD%20Platform-FCA121?style=flat&logo=gitlab&logoColor=white
[gitlab-url]: https://about.gitlab.com/

## Table of Contents

1. [Scenario Overview](#scenario-overview)
2. [Infrastructure Architecture](#infrastructure-architecture)
3. [Attack Chain Analysis](#attack-chain-analysis)
4. [Investigation Questions](#investigation-questions)
5. [PCAP Analysis](#pcap-analysis)
6. [Compromise Indicators](#compromise-indicators)
7. [Defense Strategies](#defense-strategies)
8. [Repository](#repository)

---

## Scenario Overview

You have been hired as a Defense Analyst for a DevSecOps security team at SecureBank Corporation. The company discovered suspicious network activity across their CI/CD infrastructure and production servers handling financial transactions.

During your investigation, you obtained a network packet capture from the compromised environment. Your job is to analyze this evidence and determine how attackers breached the GitLab pipeline to access production systems containing sensitive financial data.

**Affected Systems:**

- GitLab CI/CD servers
- Production payment and authentication systems
- Database servers with customer financial records
- External production endpoints

**Mission:** Analyze the packet capture to identify the attack methods, stolen data, and compromised infrastructure components.

---

## Infrastructure Architecture

### Network Topology

```
172.40.1.0/24 - Production Cloud Network

├── 172.40.1.10 - WEB-PUBLIC-01 (Public Web Server)
├── 172.40.1.11 - API-PUBLIC-02 (Public API Server)
├── 172.40.1.20 - GITLAB-CI-CD (GitLab Server)
├── 172.40.1.21 - GITLAB-RUNNER (CI/CD Runner)
├── 172.40.1.30 - PROD-PAYMENT (Payment Server)
├── 172.40.1.31 - PROD-AUTH (Authentication Server)
├── 172.40.1.32 - PROD-DATA (Database Server)
└── 172.40.1.200 - attacker-c2 (Attacker C2 Server)
```

### Service Endpoints

**GitLab CI/CD (172.40.1.20:8080):**

- /api/v4/projects/1/trigger/pipeline
- /api/v4/projects/1/repository/archive.tar.gz
- /api/v4/runners/register
- /api/v4/jobs/{id}/trace

**Public Web (172.40.1.10):**

- /api/health
- /api/status
- /api/metrics

**Public API (172.40.1.11):**

- /api/v1/payments
- /api/v1/users
- /api/v1/transactions

---

## Attack Chain Analysis

### Phase 1: GitLab Pipeline Compromise

The attacker compromises the GitLab CI/CD pipeline by injecting malicious code into a feature branch.

**Attack Vector:**

1. Attacker obtains GitLab authentication token
2. Creates malicious branch: feature-supply-chain-exploit
3. Injects malicious CI/CD configuration
4. Triggers pipeline execution

**GitLab Token Obtained:**

```
glpat-2Kx9mP4nQ7vB8sL1eR6wZ3uY5tI9
```

**Headers Used:**

```http
X-Auth-Token: glpat-2Kx9
X-Session-Key: mP4nQ7
X-Request-ID: vB8sL1
X-Client-Version: eR6wZ3
X-Build-Hash: uY5tI9
```

### Phase 2: Runner Registration

Malicious GitLab runner registered with compromised token:

**Runner Token (Base64):**

```
UjFJNU9EYzJOVFF6TWpGaFFtTkVaVVkzT0Rrd01USXpORFUy
```

**Decoded Token:**

```
R1I5ODc2NTQzMjFhQmNEZUY3ODkwMTIzNDU2
```

**Runner Registration Payload:**

```json
{
  "token": "UjFJNU9EYzJOVFF6TWpGaFFtTkVaVVkzT0Rrd01USXpORFUy",
  "description": "Compromised Runner",
  "tags": ["production", "docker"]
}
```

### Phase 3: Malicious Pipeline Execution

Pipeline triggered with malicious variables:

```json
{
  "ref": "master",
  "variables": [
    {
      "key": "ENVIRONMENT",
      "value": "production"
    },
    {
      "key": "DEPLOY_BRANCH",
      "value": "feature-supply-chain-exploit"
    }
  ]
}
```

### Phase 4: Production Server Compromise

The malicious pipeline deploys backdoors to production web server.

**Compromised Server:** WEB-PUBLIC-01

**Exfiltrated Financial Data:**

```json
{
  "server": "WEB-PUBLIC-01",
  "users_online": 1247,
  "session_tokens": [
    "ses_9a8f7e6d5c4b3a29",
    "ses_1e2d3c4b5a69879f"
  ],
  "api_keys": [
    "ak_web_prod_78291",
    "ak_analytics_45637"
  ],
  "financial_data": {
    "daily_volume": "47,293,847.92",
    "accounts": [
      "4532-7834-9012-5678",
      "5555-8901-2345-6789"
    ],
    "trojan_installed": true,
    "nc_listeners": ["4444", "4445", "4446"],
    "shell_uploads": [
      "/tmp/backdoor.sh",
      "/usr/bin/system-update"
    ]
  }
}
```

### Phase 5: Credential Harvesting

JWT signing keys and database credentials stolen:

```json
{
  "operation": "credential_exfiltration",
  "status": "success",
  "auth_jwt_key": "HS256_ultra_secure_production_signing_key_P7mQ9xR",
  "mongodb_connection": "mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod",
  "exfiltration_complete": true
}
```

**Stolen Credentials:**

- JWT Signing Key: HS256_ultra_secure_production_signing_key_P7mQ9xR
- MongoDB Connection: mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod

### Phase 6: Backdoor Deployment

Three netcat reverse shell listeners established:

```
Port 4444: Primary backdoor
Port 4445: Secondary backdoor
Port 4446: Tertiary backdoor
```

**Backdoor Files:**

- /tmp/backdoor.sh
- /usr/bin/system-update (trojan disguised as system binary)

---

## Investigation Questions

### Question 1: GitLab Pipeline Compromise

What is the GitLab runner token used in the malicious pipeline, and which branch was modified to inject the malicious CI/CD configuration?

**Answer Format:** Token_BranchName

**Analysis Steps:**

```bash
tshark -r cloud_attack.pcap -Y "http contains \"X-Auth-Token\"" -T fields -e http.request.line

tshark -r cloud_attack.pcap -Y "http contains \"token\"" -T fields -e http.file_data | xxd -r -p

echo "UjFJNU9EYzJOVFF6TWpGaFFtTkVaVVkzT0Rrd01USXpORFUy" | base64 -d

tshark -r cloud_attack.pcap -Y "http contains \"DEPLOY_BRANCH\"" -T fields -e http.file_data | xxd -r -p
```

**Answer:** R1I5ODc2NTQzMjFhQmNEZUY3ODkwMTIzNDU2_feature-supply-chain-exploit

### Question 2: Financial Data Theft

How much daily transaction volume was stolen from the payment server, and what are the two compromised credit card account numbers?

**Answer Format:** $V1,$V2,$V3.MM_account1_account2

**Analysis Steps:**

```bash
tshark -r cloud_attack.pcap -Y "tcp contains \"daily_volume\"" -T fields -e tcp.payload | xxd -r -p

strings cloud_attack.pcap | grep -A5 "daily_volume"
```

**Answer:** 47,293,847.92_4532-7834-9012-5678_5555-8901-2345-6789

### Question 3: Credential Harvesting

What JWT signing algorithm and key were stolen, and what is the MongoDB connection string?

**Answer Format:** JWT_MongoDB://connection_string

**Analysis Steps:**

```bash
tshark -r cloud_attack.pcap -Y "tcp contains \"credential_exfiltration\"" -T fields -e tcp.payload | xxd -r -p

tshark -r cloud_attack.pcap -Y "tcp contains \"auth_jwt_key\"" -T fields -e tcp.payload | xxd -r -p
```

**Answer:** HS256_ultra_secure_production_signing_key_P7mQ9xR_mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod

### Question 4: Backdoor Deployment

How many different reverse shell listeners were established by the attacker in the initial web server compromise, and was a trojan installed on the server?

**Answer Format:** X_true_or_false

**Analysis Steps:**

```bash
tshark -r cloud_attack.pcap -Y "tcp contains \"nc_listeners\"" -T fields -e tcp.payload | xxd -r -p

strings cloud_attack.pcap | grep -A3 "trojan_installed"
```

**Answer:** 3_true

### Question 5: Attack Timeline

What was the total number of production servers compromised through the CI/CD pipeline, and how many user accounts were active during the attack?

**Answer Format:** X_Y

**Analysis Steps:**

```bash
tshark -r cloud_attack.pcap -Y "tcp contains \"47,293,847.92\"" -T fields -e tcp.payload | xxd -r -p

strings cloud_attack.pcap | grep -i "server\|users_online"
```

**Answer:** 1_1247

---

## PCAP Analysis

### Traffic Patterns

**HTTP Requests to GitLab:**

```
POST /api/v4/projects/1/trigger/pipeline
GET /api/v4/projects/1/repository/archive.tar.gz?sha=malicious-commit
POST /api/v4/runners/register
POST /api/v4/jobs/12345/trace
```

### Key Indicators

**GitLab Authentication:**

```
X-Auth-Token: glpat-2Kx9mP4nQ7vB8sL1eR6wZ3uY5tI9
```

**Pipeline Trigger:**

```json
{
  "ref": "master",
  "variables": [
    {"key": "ENVIRONMENT", "value": "production"},
    {"key": "DEPLOY_BRANCH", "value": "feature-supply-chain-exploit"}
  ]
}
```

**Data Exfiltration:**

```
Operation: credential_exfiltration
JWT Key: HS256_ultra_secure_production_signing_key_P7mQ9xR
MongoDB: mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@...
Daily Volume: $47,293,847.92
Accounts: 4532-7834-9012-5678, 5555-8901-2345-6789
```

### Tshark Commands

#### Extract GitLab Token

```bash
tshark -r cloud_attack.pcap -Y "http contains \"X-Auth-Token\"" \
       -T fields -e http.request.line | grep -oE "glpat-[^,]*" | tr -d '\r\n'
```

#### Extract Runner Token

```bash
tshark -r cloud_attack.pcap -Y "http contains \"token\"" \
       -T fields -e http.file_data | xxd -r -p | grep -oE "\"token\":\"[^\"]*\"" | cut -d'"' -f4 | base64 -d
```

#### Extract Branch Name

```bash
tshark -r cloud_attack.pcap -Y "http contains \"DEPLOY_BRANCH\"" \
       -T fields -e http.file_data | xxd -r -p | grep -oE "\"value\":\"[^\"]*\"" | tail -1 | cut -d'"' -f4
```

#### Extract Financial Data

```bash
tshark -r cloud_attack.pcap -Y "tcp contains \"daily_volume\"" \
       -T fields -e tcp.payload | xxd -r -p | jq -r '.financial_data'
```

#### Extract Credentials

```bash
tshark -r cloud_attack.pcap -Y "tcp contains \"credential_exfiltration\"" \
       -T fields -e tcp.payload | xxd -r -p | jq .
```

---

## Compromise Indicators

### Network IOCs

**Malicious IPs:**

```
172.40.1.200 - Attacker C2 server
```

**Compromised Ports:**

```
4444 - Reverse shell listener 1
4445 - Reverse shell listener 2
4446 - Reverse shell listener 3
```

### GitLab IOCs

**Compromised Tokens:**

```
GitLab PAT: glpat-2Kx9mP4nQ7vB8sL1eR6wZ3uY5tI9
Runner Token: R1I5ODc2NTQzMjFhQmNEZUY3ODkwMTIzNDU2
```

**Malicious Branch:**

```
feature-supply-chain-exploit
```

### File IOCs

**Backdoor Files:**

```
/tmp/backdoor.sh
/usr/bin/system-update (trojan)
```

### Credential IOCs

**Stolen Credentials:**

```
JWT Key: HS256_ultra_secure_production_signing_key_P7mQ9xR
MongoDB User: data_analytics
MongoDB Pass: D@t@_An@lyt1cs_B7pQ
MongoDB Host: data-cluster-01:27017
Database: analytics_prod
```

**Session Tokens:**

```
ses_9a8f7e6d5c4b3a29
ses_1e2d3c4b5a69879f
```

**API Keys:**

```
ak_web_prod_78291
ak_analytics_45637
```

### Financial IOCs

**Compromised Accounts:**

```
4532-7834-9012-5678
5555-8901-2345-6789
```

**Daily Transaction Volume:**

```
$47,293,847.92
```

---

## Defense Strategies

### Immediate Response

#### 1. Revoke Compromised Credentials

```bash
gitlab-rails console
token = PersonalAccessToken.find_by_token('glpat-2Kx9mP4nQ7vB8sL1eR6wZ3uY5tI9')
token.revoke!

Runner.where(token: 'R1I5ODc2NTQzMjFhQmNEZUY3ODkwMTIzNDU2').destroy_all
```

#### 2. Delete Malicious Branch

```bash
git push origin --delete feature-supply-chain-exploit
git branch -D feature-supply-chain-exploit
```

#### 3. Rotate JWT Signing Key

```bash
openssl rand -base64 64 > /etc/app/jwt_secret.key
systemctl restart app-server
```

#### 4. Rotate Database Credentials

```bash
mongo --host data-cluster-01:27017
use analytics_prod
db.changeUserPassword("data_analytics", "NewSecurePassword123!")
```

#### 5. Kill Backdoor Processes

```bash
pkill -f backdoor.sh
pkill -f system-update
netstat -tulpn | grep -E "4444|4445|4446" | awk '{print $7}' | cut -d'/' -f1 | xargs kill -9
```

#### 6. Remove Backdoor Files

```bash
rm -f /tmp/backdoor.sh
rm -f /usr/bin/system-update
```

### Pipeline Security Hardening

#### 1. Implement Branch Protection

```yaml
protected_branches:
  - name: master
    push_access_level: maintainer
    merge_access_level: maintainer
    allow_force_push: false
  - name: production
    push_access_level: no_one
    merge_access_level: maintainer
    allow_force_push: false
```

#### 2. Secure GitLab Runner

```yaml
[[runners]]
  name = "secure-runner"
  url = "https://gitlab.securebank.com"
  token = "ROTATED_TOKEN"
  executor = "docker"
  
  [runners.docker]
    privileged = false
    disable_cache = true
    volumes = ["/var/run/docker.sock:/var/run/docker.sock"]
    
  [runners.cache]
    Type = "s3"
    Shared = false
```

#### 3. Pipeline Security Scanning

```yaml
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml

stages:
  - security
  - test
  - build
  - deploy

secret_detection:
  stage: security
  allow_failure: false

sast:
  stage: security
  allow_failure: false
```

#### 4. Enforce MFA

```bash
gitlab-rails console
users = User.where(admin: true)
users.each { |u| u.update(require_two_factor_authentication: true) }
```

### Network Security

#### 1. Network Segmentation

```bash
iptables -A FORWARD -s 172.40.1.20 -d 172.40.1.30 -j DROP
iptables -A FORWARD -s 172.40.1.21 -d 172.40.1.30 -j DROP
iptables -A FORWARD -s 172.40.1.20 -d 172.40.1.31 -j DROP
iptables -A FORWARD -s 172.40.1.21 -d 172.40.1.31 -j DROP
```

#### 2. Egress Filtering

```bash
iptables -A OUTPUT -p tcp --dport 4444 -j DROP
iptables -A OUTPUT -p tcp --dport 4445 -j DROP
iptables -A OUTPUT -p tcp --dport 4446 -j DROP
```

#### 3. IDS Rules

```
alert tcp $HOME_NET any -> $EXTERNAL_NET [4444,4445,4446] (msg:"Reverse Shell Connection Attempt"; flow:to_server,established; classtype:trojan-activity; sid:1000001;)

alert http $HOME_NET any -> any any (msg:"GitLab API Token Exfiltration"; content:"X-Auth-Token"; content:"glpat-"; distance:0; classtype:credential-theft; sid:1000002;)

alert tcp $HOME_NET any -> any 27017 (msg:"MongoDB Credential Exfiltration"; content:"mongodb://"; pcre:"/mongodb:\/\/[^:]+:[^@]+@/"; classtype:credential-theft; sid:1000003;)
```

### Monitoring

#### 1. GitLab Audit Logs

```ruby
AuditEvent.where("created_at > ?", 1.day.ago)
          .where(entity_type: ['Runner', 'PersonalAccessToken', 'Project'])
          .where(action: ['create', 'update', 'destroy'])
```

#### 2. SIEM Query

```spl
index=gitlab sourcetype=audit
| search action IN ("runner_registered", "token_created", "branch_created")
| stats count by user, action, entity_type
| where count > 5
```

---

## Repository

### GitHub Repository

[https://github.com/qays3/DFIR-Hunters/tree/main/Final/SupplyChain%20Hunter](https://github.com/qays3/DFIR-Hunters/tree/main/Final/SupplyChain%20Hunter)

### Repository Structure

```
SupplyChain Hunter/
├── README.md
├── app/
│   ├── app.py
│   ├── index.html
│   ├── config.cfg
│   ├── requirements.txt
│   ├── template.json
│   └── assets/
├── Create/
│   ├── Build/
│   │   ├── Create.sh
│   │   └── CLOUD_CICD_BREACH/
│   │       ├── docker-compose.yml
│   │       ├── scripts/
│   │       ├── pcaps/
│   │       └── intel/
│   └── File/
│       └── cloud_attack.pcap
└── Solve/
    ├── solution.json
    ├── steps.md
    └── template.json
```

### Deployment Instructions

#### Challenge Application

```bash
cd app

docker build -t supplychain .
docker run -d --name SupplyChain -p 5006:5006 --restart unless-stopped supplychain

# Access at: http://localhost:5006/?access=29910461-9afb-4c57-b4a4-b7ff2026d72c

```



#### Traffic Generation

```bash
cd Create/Build
chmod +x Create.sh
./Create.sh
```

### Challenge Submission

Answers are submitted in JSON format:

```json
{
  "gitlab_compromise": "R1I5ODc2NTQzMjFhQmNEZUY3ODkwMTIzNDU2_feature-supply-chain-exploit",
  "financial_theft": "47,293,847.92_4532-7834-9012-5678_5555-8901-2345-6789",
  "credential_harvesting": "HS256_ultra_secure_production_signing_key_P7mQ9xR_mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod",
  "backdoor_deployment": "3_true",
  "attack_timeline": "1_1247"
}
```

---

## References

### CI/CD Security

- OWASP DevSecOps: [https://owasp.org/www-project-devsecops-guideline/](https://owasp.org/www-project-devsecops-guideline/)
- GitLab Security: [https://docs.gitlab.com/ee/security/](https://docs.gitlab.com/ee/security/)
- CISA Supply Chain: [https://www.cisa.gov/supply-chain-risk-management](https://www.cisa.gov/supply-chain-risk-management)

### Threat Intelligence

- MITRE ATT&CK T1195: Supply Chain Compromise
- MITRE ATT&CK T1078: Valid Accounts
- MITRE ATT&CK T1071: Application Layer Protocol

---

## Authors

Challenge Designer: Qays Sarayra  
Contact: info@qayssarayra.com  
Specialization: DevSecOps, CI/CD Security, Supply Chain Attack Analysis

---

## License

This challenge is part of IEEE CyberSecurity Competition 2025 - Finals Round.

Educational use only. All attacks are simulated in isolated Docker environments.

---

Competition: IEEE CyberSecurity Competition 2025  
Round: Finals  
Category: DFIR  
Difficulty: Easy  
Expected Completion Time: 1-2 hours