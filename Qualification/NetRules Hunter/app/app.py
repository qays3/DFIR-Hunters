from typing import Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Request, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
import os
import uvicorn
import re
from scapy.all import rdpcap, Raw
from collections import defaultdict

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
def load_config():
    config = {}
    with open('config.cfg', 'r') as f:
        for line in f:
            line = line.strip()
            if line and '=' in line:
                key, value = line.split('=', 1)
                config[key] = value
    return config

CONFIG = load_config()
SECRET = CONFIG['SECRET']
FLAG = CONFIG['FLAG']

MAX_FILE_SIZE = 1 * 1024 * 1024
PCAP_FILE = "sample.pcap"
SIGNATURES_DIR = "./770c7d50-126d-481a-80d5-a04d076d3aa8"

TRAFFIC_CONFIG = {
    'ssh_bruteforce': {
        'name': 'SSH Brute Force',
        'type': 'Authentication Attack',
        'difficulty': 'Easy',
        'protocol': 'SSH/TCP',
        'min_signatures': 1,
        'required_sids': ['1000001'],
        'signature_file': 'ssh_bruteforce.txt',
        'min_threshold': 3,
        'time_window': 60
    },
    'sql_injection': {
        'name': 'SQL Injection',
        'type': 'Web Attack',
        'difficulty': 'Medium',
        'protocol': 'HTTP/TCP',
        'min_signatures': 3,
        'required_sids': ['1000002', '1000003', '1000004'],
        'signature_file': 'sql_injection.txt'
    },
    'dns_tunneling': {
        'name': 'DNS Tunneling',
        'type': 'Data Exfiltration',
        'difficulty': 'Medium',
        'protocol': 'DNS/UDP',
        'min_signatures': 3,
        'required_sids': ['1000005', '1000006', '1000007'],
        'signature_file': 'dns_tunneling.txt'
    },
    'cobalt_strike': {
        'name': 'Cobalt Strike Beacon',
        'type': 'C2 Communication',
        'difficulty': 'Hard',
        'protocol': 'HTTP/TCP',
        'min_signatures': 3,
        'required_sids': ['1000008', '1000009', '1000010'],
        'signature_file': 'cobalt_strike.txt'
    },
    'ransomware_c2': {
        'name': 'Ransomware C2',
        'type': 'Command & Control',
        'difficulty': 'Hard',
        'protocol': 'HTTPS/TCP',
        'min_signatures': 3,
        'required_sids': ['1000011', '1000012', '1000013'],
        'signature_file': 'ransomware_c2.txt'
    },
    'data_exfiltration': {
        'name': 'Data Exfiltration',
        'type': 'Data Theft',
        'difficulty': 'Very Hard',
        'protocol': 'HTTP/TCP',
        'min_signatures': 4,
        'required_sids': ['1000014', '1000015', '1000016', '1000017'],
        'signature_file': 'data_exfiltration.txt'
    }
}

ATTACK_SIGNATURES = {
    'ssh_bruteforce.txt': [
        'SSH-2.0',
        'diffie-hellman',
        'ssh-rsa',
        'ssh-dss',
        'ecdsa-sha2',
        'ssh-ed25519',
        'Failed password',
        'Invalid user',
        'Connection closed',
        'Received disconnect',
        'Connection reset',
        'publickey',
        'keyboard-interactive',
        'password',
        'aes128-ctr',
        'aes192-ctr',
        'aes256-ctr',
        'aes128-cbc',
        'aes256-cbc',
        '3des-cbc',
        'hmac-sha1',
        'hmac-sha2-256',
        'hmac-sha2-512',
        'hmac-md5',
        'zlib',
        'none',
        'kex_exchange',
        'hostkey',
        'session_id',
    ],
    
    'sql_injection.txt': [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 'a'='a",
        "admin'--",
        "' UNION SELECT",
        "UNION ALL SELECT",
        "' AND '1'='1",
        "' AND 1=1--",
        "; DROP TABLE",
        "; DELETE FROM",
        "'; EXEC",
        "'; EXECUTE",
        "CAST(0x",
        "CONCAT(0x",
        "' WAITFOR DELAY",
        "BENCHMARK(",
        "SLEEP(",
        "pg_sleep(",
        "' AND SLEEP(",
        "' OR SLEEP(",
        "' XOR '1'='1",
        "1' AND '1'='1",
        "1' OR '1'='1",
        "' OR username LIKE '%",
        "' OR email LIKE '%",
        "' OR password LIKE '%",
        "HAVING 1=1--",
        "GROUP BY",
        "ORDER BY",
        "' INTO OUTFILE",
        "' INTO DUMPFILE",
        "LOAD_FILE(",
        "' AND (SELECT",
        "' OR (SELECT",
        "@@version",
        "@@datadir",
        "@@hostname",
        "@@basedir",
        "information_schema",
        "mysql.user",
        "sys.tables",
        "sys.databases",
        "sys.objects",
        "sysobjects",
        "syscolumns",
        "xp_cmdshell",
        "sp_executesql",
        "sp_configure",
        "'; SHUTDOWN--",
        "CHAR(0x",
        "CHR(0x",
        "0x3a3a",
        "EXTRACTVALUE(",
        "UPDATEXML(",
        "name FROM syscolumns",
        "table_name FROM information_schema",
        "column_name FROM information_schema",
        "user()",
        "current_user",
        "session_user",
        "database()",
        "schema()",
        "version()",
        "' AND ASCII",
        "' AND SUBSTRING",
        "' AND MID(",
        "UNION SELECT NULL",
        "UNION SELECT 1,2,3",
        "concat(username,0x3a,password)",
        "group_concat(",
        "' AND 1=2 UNION SELECT",
    ],
    
    'dns_tunneling.txt': [
        '.dnscat',
        '.iodine',
        '.dns2tcp',
        '.tunnel',
        '.exfil',
        '.data',
        '.file',
        '.dnstunnel',
        '.tun',
        '.covert',
        '.c2',
        '.cmd',
        '.shell',
        '-encoded',
        '-base64',
        '-base32',
        '-hex',
        '-data',
        '-chunk',
        '-part',
        'aaaaaaaaaa',
        'zzzzzzzzzz',
        '0000000000',
        '9999999999',
        'abcdefghij',
        'qwertyuiop',
        '1234567890',
        'xxxxxxxxxx',
        'yyyyyyyyyy',
        '.tk',
        '.ga',
        '.ml',
        '.cf',
        '.gq',
        '.pw',
        '.top',
        'TXT',
        'NULL',
        'CNAME',
        'MX',
        'SRV',
        'A',
        'AAAA',
        'NS',
        'PTR',
        'dnscat2',
        'iodined',
        'dns2tcpd',
    ],
    
    'cobalt_strike.txt': [
        '/submit.php',
        '/pixel.gif',
        '/activity',
        '/fakeurl',
        '/match',
        '/updates',
        '/download',
        '/push',
        '/rest',
        '/api/v1',
        '/api/v2',
        '/load',
        '/__utm.gif',
        '/ga.js',
        '/ptj',
        '/pixel',
        '/j.ad',
        'Cookie: SESSIONID=',
        'Cookie: MZ=',
        'Cookie: __cfduid=',
        'Cookie: __utma=',
        'Cookie: session=',
        'Accept: */*',
        'Accept: text/html',
        'Accept: text/html,application/xhtml+xml',
        'Accept-Language: en-US',
        'Accept-Language: en-US,en',
        'Accept-Encoding: gzip, deflate',
        'Accept-Encoding: gzip',
        'User-Agent: Mozilla/5.0',
        'User-Agent: Microsoft',
        'User-Agent: Internet Explorer',
        'User-Agent: Mozilla/4.0',
        'User-Agent: Mozilla/5.0 (compatible; MSIE',
        'beacon',
        'tasks',
        'metadata',
        'output',
        'http-get',
        'http-post',
        'Content-Type: application/octet-stream',
        'application/x-www-form-urlencoded',
        'HTTP/1.1 200 OK',
        'Server: Apache',
        'Server: nginx',
        'Server: Microsoft-IIS',
        'Server: Apache/2.',
        'Server: nginx/1.',
        'Connection: close',
        'Connection: keep-alive',
    ],
    
    'ransomware_c2.txt': [
        '/api/register',
        '/api/checkin',
        '/api/command',
        '/api/upload',
        '/api/download',
        '/api/status',
        '/api/victim',
        '/api/bot',
        '/gate.php',
        '/panel.php',
        '/admin.php',
        '/config.php',
        '/index.php',
        '/main.php',
        '/key',
        '/encrypt',
        '/payment',
        '/decrypt',
        '/victim',
        '/bitcoin',
        '/wallet',
        '/ransom',
        '/price',
        '/buy',
        'victim_id=',
        'machine_id=',
        'computer_name=',
        'username=',
        'os_version=',
        'encryption_key=',
        'file_list=',
        'drive_info=',
        'system_info=',
        'hwid=',
        'POST /gate',
        'GET /config',
        'POST /api',
        'Content-Type: multipart/form-data',
        'Content-Disposition: form-data',
        'boundary=',
        'boundary=----',
        'User-Agent: WinHTTP',
        'User-Agent: python-requests',
        'User-Agent: curl',
        'Accept: */*',
        'Connection: Keep-Alive',
        'Connection: close',
        'X-Session-ID:',
        'X-Machine-ID:',
        'X-Victim-ID:',
        'X-Bot-ID:',
        'Authorization: Bearer',
        'key=',
        'id=',
        'status=',
        'cmd=',
    ],
    
    'data_exfiltration.txt': [
        'filename=',
        'document=',
        'file=',
        'upload=',
        'data=',
        'content=',
        'attachment=',
        'archive=',
        'backup=',
        'export=',
        'transfer=',
        'send=',
        'share=',
        '.zip',
        '.rar',
        '.7z',
        '.tar',
        '.gz',
        '.bz2',
        '.tgz',
        '.pdf',
        '.doc',
        '.docx',
        '.xls',
        '.xlsx',
        '.ppt',
        '.pptx',
        '.csv',
        '.txt',
        '.sql',
        '.db',
        '.mdb',
        '.accdb',
        '.sqlite',
        'confidential',
        'secret',
        'private',
        'internal',
        'restricted',
        'classified',
        'password',
        'credential',
        'financial',
        'payroll',
        'salary',
        'employee',
        'customer',
        'client',
        'account',
        'invoice',
        'report',
        'budget',
        'contract',
        'agreement',
        'sensitive',
        'proprietary',
        'Content-Type: multipart/form-data',
        'Content-Type: application/x-www-form-urlencoded',
        'Content-Type: application/octet-stream',
        'Content-Type: application/zip',
        'Content-Type: application/pdf',
        'Content-Type: application/msword',
        'Content-Disposition: attachment',
        'Content-Disposition: form-data',
        'POST /upload',
        'POST /share',
        'POST /send',
        'POST /transfer',
        'POST /backup',
        'POST /export',
        'POST /sync',
        'POST /file',
        'base64,',
        'data:image',
        'data:application',
        'data:text',
        'name="file"',
        'name="document"',
        'name="upload"',
        'name="attachment"',
    ]
}

def create_signature_files():
    """Create signature files in the signatures directory"""
    os.makedirs(SIGNATURES_DIR, exist_ok=True)
    
    for filename, signatures in ATTACK_SIGNATURES.items():
        filepath = os.path.join(SIGNATURES_DIR, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            for sig in signatures:
                f.write(sig + '\n')

create_signature_files()

def load_signatures(filename):
    filepath = os.path.join(SIGNATURES_DIR, filename)
    if not os.path.exists(filepath):
        return []
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        signatures = [line.strip() for line in f if line.strip()]
    return signatures

def validate_file_upload(file: UploadFile):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    
    if not file.filename.lower().endswith('.rules'):
        raise HTTPException(status_code=400, detail="File must have .rules extension")
    
    filename_pattern = r'^[a-zA-Z0-9_\-\.]+\.rules$'
    if not re.match(filename_pattern, file.filename):
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    if len(file.filename) > 255:
        raise HTTPException(status_code=400, detail="Filename too long")

def validate_file_content(content: bytes):
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="File is empty")
    
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail=f"File too large")
    
    try:
        text_content = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be valid UTF-8 text")
    
    if '\x00' in text_content:
        raise HTTPException(status_code=400, detail="File contains null bytes")
    
    has_rule = re.search(r'\balert\s+(tcp|udp|icmp)', text_content, re.IGNORECASE)
    if not has_rule:
        raise HTTPException(status_code=400, detail="File does not contain valid Snort rules")
    
    return text_content

def sanitize_rules_content(content: str):
    lines = content.split('\n')
    sanitized_lines = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#'):
            sanitized_lines.append(line[:10000])
    
    return '\n'.join(sanitized_lines[:10000])

def parse_snort_rules(rules_content: str):
    rules = []
    rule_pattern = r'alert\s+(tcp|udp|icmp)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s+\((.*?)\)'
    
    for match in re.finditer(rule_pattern, rules_content, re.IGNORECASE | re.DOTALL):
        protocol = match.group(1).lower()
        dst_port = match.group(5)
        rule_options = match.group(6)
        
        content_match = re.search(r'content:\s*"([^"]+)"', rule_options)
        content = content_match.group(1) if content_match else None
        
        sid_match = re.search(r'sid:\s*(\d+)', rule_options)
        sid = sid_match.group(1) if sid_match else None
        
        pcre_match = re.search(r'pcre:\s*"([^"]+)"', rule_options)
        pcre_pattern = pcre_match.group(1) if pcre_match else None
        
        threshold_match = re.search(r'threshold:\s*type\s+threshold,\s*track\s+by_src,\s*count\s+(\d+),\s*seconds\s+(\d+)', rule_options)
        threshold = None
        if threshold_match:
            threshold = {
                'count': int(threshold_match.group(1)),
                'seconds': int(threshold_match.group(2))
            }
        
        if content and sid:
            rules.append({
                'protocol': protocol,
                'dst_port': dst_port,
                'content': content,
                'pcre': pcre_pattern,
                'sid': sid,
                'threshold': threshold
            })
    
    return rules

def validate_rule_ports(rules):
    port_requirements = {
        '1000001': '22',
        '1000002': '80',
        '1000003': '80',
        '1000004': '80',
        '1000005': '53',
        '1000006': '53',
        '1000007': '53',
        '1000008': '443',
        '1000009': '443',
        '1000010': '443',
        '1000011': '443',
        '1000012': '443',
        '1000013': '443',
        '1000014': '80',
        '1000015': '80',
        '1000016': '80',
        '1000017': '80'
    }
    
    for rule in rules:
        sid = rule['sid']
        dst_port = rule['dst_port']
        
        if sid in port_requirements:
            required_port = port_requirements[sid]
            if dst_port != required_port and dst_port != 'any':
                raise HTTPException(
                    status_code=400,
                    detail=f"Rule SID {sid} has incorrect destination port. Expected port {required_port}."
                )
            
            if dst_port == 'any':
                raise HTTPException(
                    status_code=400,
                    detail=f"Rule SID {sid} uses 'any' port. Specify port {required_port} for proper detection."
                )
    
    return rules

def check_signature_in_static_list(rule, traffic_name):
    """Check if signature exists in static signature files"""
    config = TRAFFIC_CONFIG.get(traffic_name)
    if not config:
        return False
    
    signature_file = config.get('signature_file')
    if not signature_file:
        return False
    
    valid_signatures = load_signatures(signature_file)
    if not valid_signatures:
        return False
    
    content = rule['content'].lower().strip()
    pcre = rule.get('pcre', '').lower() if rule.get('pcre') else ''
    
    if len(content) < 2:
        return False
    
    if pcre:
        pcre_clean = pcre.strip('/')
        for valid_sig in valid_signatures:
            valid_sig_lower = valid_sig.lower()
            try:
                if re.search(pcre_clean, valid_sig_lower, re.IGNORECASE):
                    return True
            except:
                pass
    
    for valid_sig in valid_signatures:
        valid_sig_lower = valid_sig.lower().strip()
        
        if content == valid_sig_lower:
            return True
        
        if content in valid_sig_lower or valid_sig_lower in content:
            return True
        
        content_words = set(content.split())
        sig_words = set(valid_sig_lower.split())
        if content_words & sig_words:
            return True
    
    return False

def pre_validate_rules_will_match(rules, packets):
    """Validate: signature must be in PCAP OR in static signature list"""
    sid_to_traffic = {}
    for traffic_name, config in TRAFFIC_CONFIG.items():
        for sid in config['required_sids']:
            sid_to_traffic[sid] = traffic_name
    
    for rule in rules:
        sid = rule['sid']
        if sid not in sid_to_traffic:
            continue
        
        traffic_name = sid_to_traffic[sid]
        
        in_pcap = False
        if rule.get('threshold'):
            in_pcap = match_rule_with_threshold(rule, packets)
        else:
            in_pcap = match_rule_against_pcap(rule, packets)
        
        if in_pcap:
            continue
        
        in_static_signatures = check_signature_in_static_list(rule, traffic_name)
        
        if not in_static_signatures:
            traffic_display = traffic_name.replace('_', ' ').title()
            raise HTTPException(
                status_code=400,
                detail=f"Rule SID {sid} ({traffic_display}) signature '{rule['content']}' not found. "
                       f"It must exist in either the PCAP traffic OR the valid signature patterns."
            )

def validate_ssh_threshold(rule):
    if rule['sid'] == '1000001':
        threshold = rule.get('threshold')
        if not threshold:
            raise HTTPException(
                status_code=400,
                detail="SSH Brute Force rule (SID 1000001) must include threshold detection. "
                       "Use: threshold: type threshold, track by_src, count 3, seconds 60;"
            )
        
        if threshold['count'] < 3:
            raise HTTPException(
                status_code=400,
                detail="SSH Brute Force threshold count must be at least 3 failed attempts."
            )
        
        if threshold['seconds'] > 60:
            raise HTTPException(
                status_code=400,
                detail="SSH Brute Force time window must be 60 seconds or less."
            )

def validate_dynamic_signatures(rules):
    for rule in rules:
        sid = rule['sid']
        
        if sid == '1000001':
            validate_ssh_threshold(rule)
    
    return rules

def validate_unique_signatures(rules):
    traffic_groups = {
        'ssh_bruteforce': ['1000001'],
        'sql_injection': ['1000002', '1000003', '1000004'],
        'dns_tunneling': ['1000005', '1000006', '1000007'],
        'cobalt_strike': ['1000008', '1000009', '1000010'],
        'ransomware_c2': ['1000011', '1000012', '1000013'],
        'data_exfiltration': ['1000014', '1000015', '1000016', '1000017']
    }
    
    all_contents = []
    for rule in rules:
        content = rule['content'].lower().strip()
        if content in all_contents:
            raise HTTPException(
                status_code=400,
                detail=f"Duplicate content signature detected: '{rule['content']}'. Each rule must have a unique content signature."
            )
        all_contents.append(content)
    
    for traffic_name, sids in traffic_groups.items():
        category_rules = [r for r in rules if r['sid'] in sids]
        
        if len(category_rules) < len(sids):
            continue
        
        signatures = []
        for rule in category_rules:
            sig = rule['content'].lower().strip()
            signatures.append(sig)
        
        if len(signatures) != len(set(signatures)):
            raise HTTPException(
                status_code=400,
                detail=f"Duplicate content signatures detected in {traffic_name.replace('_', ' ').title()} rules. Each rule must have a unique signature."
            )
    
    return rules

def load_pcap_packets():
    if not os.path.exists(PCAP_FILE):
        raise HTTPException(status_code=500, detail="PCAP file not found")
    
    try:
        packets = rdpcap(PCAP_FILE)
        return packets
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading PCAP: {str(e)}")

def match_rule_with_threshold(rule, packets):
    if not rule.get('threshold'):
        return match_rule_against_pcap(rule, packets)
    
    threshold = rule['threshold']
    content_pattern = rule['content']
    protocol = rule['protocol']
    
    src_timestamps = defaultdict(list)
    
    for packet in packets:
        try:
            if protocol == 'tcp' and packet.haslayer('TCP'):
                if packet.haslayer(Raw):
                    payload = bytes(packet[Raw].load).decode('utf-8', errors='ignore')
                    
                    if re.search(re.escape(content_pattern), payload, re.IGNORECASE):
                        src_ip = packet['IP'].src if packet.haslayer('IP') else 'unknown'
                        timestamp = float(packet.time)
                        src_timestamps[src_ip].append(timestamp)
        except:
            continue
    
    for src_ip, timestamps in src_timestamps.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            count = 0
            window_start = timestamps[i]
            for j in range(i, len(timestamps)):
                if timestamps[j] - window_start <= threshold['seconds']:
                    count += 1
                else:
                    break
            
            if count >= threshold['count']:
                return True
    
    return False

def match_rule_against_pcap(rule, packets):
    matched = False
    content_pattern = rule['content']
    protocol = rule['protocol']
    pcre_pattern = rule['pcre']
    sid = rule['sid']
    
    for packet in packets:
        try:
            if protocol == 'tcp' and packet.haslayer('TCP'):
                if packet.haslayer(Raw):
                    payload = bytes(packet[Raw].load).decode('utf-8', errors='ignore')
                    
                    if re.search(re.escape(content_pattern), payload, re.IGNORECASE):
                        if pcre_pattern:
                            try:
                                pcre_clean = pcre_pattern.strip('/')
                                if re.search(pcre_clean, payload, re.IGNORECASE):
                                    matched = True
                                    break
                            except:
                                matched = True
                                break
                        else:
                            matched = True
                            break
            
            elif protocol == 'udp' and packet.haslayer('UDP'):
                if packet.haslayer(Raw):
                    payload = bytes(packet[Raw].load).decode('utf-8', errors='ignore')
                    if re.search(re.escape(content_pattern), payload, re.IGNORECASE):
                        matched = True
                        break
                
                if packet.haslayer('DNS'):
                    try:
                        dns_layer = packet['DNS']
                        if dns_layer.qd:
                            qname = dns_layer.qd.qname.decode('utf-8', errors='ignore')
                            if re.search(re.escape(content_pattern), qname, re.IGNORECASE):
                                if pcre_pattern:
                                    try:
                                        pcre_clean = pcre_pattern.strip('/')
                                        if re.search(pcre_clean, qname, re.IGNORECASE):
                                            matched = True
                                            break
                                    except:
                                        matched = True
                                        break
                                else:
                                    matched = True
                                    break
                    except:
                        pass
            
            elif protocol == 'icmp' and packet.haslayer('ICMP'):
                if packet.haslayer(Raw):
                    payload = bytes(packet[Raw].load).decode('utf-8', errors='ignore')
                    if re.search(re.escape(content_pattern), payload, re.IGNORECASE):
                        matched = True
                        break
        except:
            continue
    
    return matched

@app.post("/api/scan")
async def scan_traffic(request: Request, file: UploadFile = File(...), access_token: Optional[str] = Cookie(None)):
    if not check_access(request, access_token):
        raise HTTPException(status_code=403, detail="Unauthorized")
    return await scan_traffic_impl(file)

async def scan_traffic_impl(file: UploadFile = File(...)):

    validate_file_upload(file)
    
    try:
        content = await file.read()
        text_content = validate_file_content(content)
        rules_content = sanitize_rules_content(text_content)
        
        if 'REPLACE_WITH_REAL_SIGNATURE' in rules_content or 'REPLACE_WITH' in rules_content:
            raise HTTPException(status_code=400, detail="Template strings detected. Write authentic Snort rules with real signatures.")
        
        rule_list = parse_snort_rules(rules_content)
        
        if len(rule_list) == 0:
            raise HTTPException(status_code=400, detail="No valid Snort rules found")
        
        if len(rule_list) > 50:
            raise HTTPException(status_code=400, detail="Too many rules. Maximum 50 rules allowed")
        
        packets = load_pcap_packets()
        
        validate_rule_ports(rule_list)
        validate_dynamic_signatures(rule_list)
        validate_unique_signatures(rule_list)
        
        pre_validate_rules_will_match(rule_list, packets)
        
        signature_counts = {}
        for traffic_name, config in TRAFFIC_CONFIG.items():
            matched_sids = 0
            for sid in config['required_sids']:
                for rule in rule_list:
                    if rule['sid'] == sid:
                        matched_sids += 1
                        break
            
            signature_counts[traffic_name] = {
                'matched': matched_sids,
                'required': config['min_signatures']
            }
        
        results = {}
        matched_sids = set()
        
        for rule in rule_list:
            sid = rule['sid']
            
            if rule.get('threshold'):
                if match_rule_with_threshold(rule, packets):
                    matched_sids.add(sid)
            else:
                if match_rule_against_pcap(rule, packets):
                    matched_sids.add(sid)
        
        for traffic_name, config in TRAFFIC_CONFIG.items():
            required_sids = set(config['required_sids'])
            matched_count = signature_counts[traffic_name]['matched']
            required_count = signature_counts[traffic_name]['required']
            
            if matched_count == required_count:
                results[traffic_name] = True
            elif required_sids.issubset(matched_sids):
                results[traffic_name] = True
            else:
                results[traffic_name] = False
        
        detected_count = sum(results.values())
        total_count = len(TRAFFIC_CONFIG)
        
        response_data = {
            'success': True,
            'results': results,
            'signature_counts': signature_counts,
            'detected': detected_count,
            'total': total_count
        }
        
        if detected_count == total_count:
            response_data['flag'] = FLAG
            response_data['message'] = "Congratulations! All traffic patterns detected!"
        
        return JSONResponse(content=response_data)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/api/traffic-info")
async def get_traffic_info(request: Request, access_token: Optional[str] = Cookie(None)):
    if not check_access(request, access_token):
        raise HTTPException(status_code=403, detail="Unauthorized")
    return await get_traffic_info_impl()

async def get_traffic_info_impl():

    info = {}
    for key, config in TRAFFIC_CONFIG.items():
        info[key] = {
            'name': config['name'],
            'type': config['type'],
            'difficulty': config['difficulty'],
            'protocol': config['protocol']
        }
    return JSONResponse(content=info)

@app.get("/sample.pcap")
async def download_pcap(request: Request, access_token: Optional[str] = Cookie(None)):
    if not check_access(request, access_token):
        raise HTTPException(status_code=403, detail="Unauthorized")
    return await download_pcap_impl()

async def download_pcap_impl():

    pcap_path = "sample.pcap"
    if os.path.exists(pcap_path):
        return FileResponse(
            pcap_path,
            media_type="application/vnd.tcpdump.pcap",
            filename="sample.pcap"
        )
    raise HTTPException(status_code=404, detail="PCAP file not found")


@app.get("/template.rules")
async def download_template(request: Request, access_token: Optional[str] = Cookie(None)):
    if not check_access(request, access_token):
        raise HTTPException(status_code=403, detail="Unauthorized")
    template_path = "template.rules"
    if os.path.exists(template_path):
        return FileResponse(
            template_path,
            media_type="application/octet-stream",
            filename="template.rules"
        )
    raise HTTPException(status_code=404, detail="Template file not found")

def check_access(request: Request, access_token: Optional[str] = Cookie(None)):
    access_param = request.query_params.get('access')
    if access_param == SECRET or access_token == SECRET:
        return True
    return False

@app.get("/")
async def read_root(request: Request, access: str = None):
    if access != SECRET:
        return RedirectResponse(url="https://qayssarayra.com/")
    response = FileResponse("index.html")
    response.set_cookie(key="access_token", value=SECRET, httponly=False, max_age=3600, samesite='lax')
    return response

app.mount("/assets", StaticFiles(directory="assets", html=True), name="assets")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5001)