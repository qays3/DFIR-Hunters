from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import yara
import os
import tempfile
import uvicorn
import re

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FLAG = "flag{$93_y4r4_!s_my_s1s_and_1_luv_h3r<3_7h4t_why_!_luv_y4r4_rul3$}"


MAX_FILE_SIZE = 1 * 1024 * 1024

MALWARE_SAMPLES = {
    'mirai': (
        b'\x7F\x45\x4C\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x2F\x62\x69\x6E\x2F\x62\x75\x73\x79\x62\x6F\x78\x20\x4D\x49\x52\x41\x49'
        b'\x5B\x6B\x77\x6F\x72\x6B\x65\x72\x5D'
        b'\x2F\x64\x65\x76\x2F\x77\x61\x74\x63\x68\x64\x6F\x67'
        b'\x41\x54\x54\x41\x43\x4B'
        b'\x53\x43\x41\x4E\x4E\x45\x52'
        b'\x74\x65\x6C\x6E\x65\x74'
        b'\x61\x64\x6D\x69\x6E\x3A\x61\x64\x6D\x69\x6E'
        b'\x53\x59\x4E\x46\x4C\x4F\x4F\x44'
    ),
    'wannacry': (
        b'\x4D\x5A\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00'
        b'\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
        b'\x50\x45\x00\x00\x4C\x01\x03\x00\xF4\x72\x5B\x58\x00\x00\x00\x00'
        b'\x2E\x77\x6E\x72\x79\x40\x32\x6F\x6C\x37\x2E\x77\x63\x72\x79'
        b'\x40\x57\x61\x6E\x61\x44\x65\x63\x72\x79\x70\x74\x6F\x72\x40\x2E\x65\x78\x65'
        b'\x49\x75\x71\x65\x72\x66\x73\x6F\x64\x70\x39\x69\x66\x6A\x61\x70\x6F\x73\x64\x66\x6A\x68\x67\x6F\x73\x75\x72\x69\x6A\x66\x61\x65\x77\x72\x77\x65\x72\x67\x77\x65\x61\x2E\x63\x6F\x6D'
        b'\x31\x31\x35\x70\x37\x55\x4D\x4D\x6E\x67\x6F\x6A\x31\x70\x4D\x76\x6B\x70\x48\x69\x6A\x63\x52\x64\x66\x4A\x4E\x58\x6A\x36\x4C\x72\x4C\x6E'
        b'\x4D\x73\x57\x69\x6E\x5A\x6F\x6E\x65\x73\x43\x61\x63\x68\x65\x43\x6F\x75\x6E\x74\x65\x72\x4D\x75\x74\x65\x78\x41'
        b'\x76\x73\x73\x61\x64\x6D\x69\x6E\x20\x64\x65\x6C\x65\x74\x65\x20\x73\x68\x61\x64\x6F\x77\x73'
        b'\x69\x63\x61\x63\x6C\x73\x20\x2E\x20\x2F\x67\x72\x61\x6E\x74\x20\x45\x76\x65\x72\x79\x6F\x6E\x65\x3A\x46'
    ),
    'emotet': (
        b'\x4D\x5A\x90\x00\x02\x00\x00\x00\x04\x00\x0F\x00\xFF\xFF\x00\x00'
        b'\x50\x45\x00\x00\x4C\x01\x06\x00\xA9\x83\x4F\x5D\x00\x00\x00\x00'
        b'\x49\x39\x38\x42\x36\x38\x45\x33\x43'
        b'\x53\x4F\x46\x54\x57\x41\x52\x45\x5C\x4D\x69\x63\x72\x6F\x73\x6F\x66\x74\x5C\x57\x69\x6E\x64\x6F\x77\x73\x5C\x43\x75\x72\x72\x65\x6E\x74\x56\x65\x72\x73\x69\x6F\x6E\x5C\x52\x75\x6E'
        b'\x4D\x41\x50\x49\x33\x32\x2E\x64\x6C\x6C'
        b'\x4D\x41\x50\x49\x49\x6E\x69\x74\x69\x61\x6C\x69\x7A\x65'
        b'\x50\x4F\x53\x54\x20\x2F\x67\x61\x74\x65\x2E\x70\x68\x70\x20\x48\x54\x54\x50'
        b'\x6D\x75\x6C\x74\x69\x70\x61\x72\x74\x2F\x66\x6F\x72\x6D\x2D\x64\x61\x74\x61'
        b'\x54\x72\x69\x63\x6B\x42\x6F\x74'
        b'\x55\x50\x58\x30'
    ),
    'petya': (
        b'\x4D\x5A\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00'
        b'\x50\x45\x00\x00\x4C\x01\x08\x00\xF7\xA3\x65\x59\x00\x00\x00\x00'
        b'\x49\x66\x20\x79\x6F\x75\x20\x73\x65\x65\x20\x74\x68\x69\x73\x20\x74\x65\x78\x74'
        b'\x31\x4D\x7A\x37\x31\x35\x33\x48\x4D\x75\x78\x58\x54\x75\x52\x32\x52\x31\x74\x37\x38\x6D\x47\x53\x64\x7A\x61\x41\x74\x4E\x62\x42\x57\x58'
        b'\x45\x74\x65\x72\x6E\x61\x6C\x42\x6C\x75\x65'
        b'\x4D\x53\x31\x37\x2D\x30\x31\x30'
        b'\x4D\x69\x6D\x69\x6B\x61\x74\x7A'
        b'\x50\x53\x45\x58\x45\x43'
        b'\x76\x73\x73\x61\x64\x6D\x69\x6E\x20\x64\x65\x6C\x65\x74\x65\x20\x73\x68\x61\x64\x6F\x77\x73'
    ),
    'zeus': (
        b'\x4D\x5A\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00'
        b'\x50\x45\x00\x00\x4C\x01\x05\x00\xC2\x6F\x89\x4A\x00\x00\x00\x00'
        b'\x5A\x42\x54\x32\x2E\x31\x2E\x30\x2E\x31\x30'
        b'\x5F\x5F\x53\x59\x53\x54\x45\x4D\x5F\x5F\x4D\x55\x54\x45\x58\x5F\x5F'
        b'\x7A\x62\x6F\x74\x2E\x73\x79\x73'
        b'\x77\x73\x32\x5F\x33\x32\x2E\x64\x6C\x6C'
        b'\x57\x65\x62\x49\x6E\x6A\x65\x63\x74'
        b'\x46\x6F\x72\x6D\x47\x72\x61\x62\x62\x65\x72'
        b'\x66\x69\x72\x65\x66\x6F\x78\x2E\x65\x78\x65'
        b'\x63\x68\x61\x73\x65\x2E\x63\x6F\x6D'
    ),
    'stuxnet': (
        b'\x4D\x5A\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00'
        b'\x50\x45\x00\x00\x4C\x01\x07\x00\xD8\x3F\x91\x4C\x00\x00\x00\x00'
        b'\x6D\x72\x78\x6E\x65\x74\x2E\x73\x79\x73'
        b'\x6D\x79\x72\x74\x75\x73'
        b'\x52\x65\x61\x6C\x74\x65\x6B'
        b'\x53\x74\x65\x70\x37\x5F\x50\x4C\x43'
        b'\x53\x37\x2D\x33\x30\x30'
        b'\x53\x69\x65\x6D\x65\x6E\x73'
        b'\x31\x34\x31\x30\x48\x7A'
        b'\x4D\x53\x31\x30\x2D\x30\x34\x36'
    )
}

MALWARE_CONFIG = {
    'mirai': {
        'name': 'Mirai',
        'type': 'IoT Botnet',
        'difficulty': 'Easy',
        'year': '2016',
        'min_signatures': 1,
        'signatures': [
            r'\{ 7F 45 4C 46 \}',
            r'busybox.*MIRAI',
            r'\[kworker\]',
            r'/dev/watchdog',
            r'/dev/null',
            r'ATTACK',
            r'SCANNER',
            r'REPORT',
            r'telnet',
            r'SYNFLOOD',
            r'ACKFLOOD',
            r'UDPFLOOD',
            r'HTTP_FLOOD',
            r'VSE_FLOOD',
            r'GRE_FLOOD',
            r'COMBO_FLOOD',
            r'STD_FLOOD',
            r'/bin/sh',
            r'/proc/net/tcp',
            r'socket\(AF_INET',
            r'inet_addr',
            r'connect\(',
            r'rand\(\)',
            r'pthread_create',
            r'killer_',
            r'scanner_',
            r'attack_',
            r'resolve_func',
            r'table_unlock',
            r'util_sockaddr',
        ]
    },
    'wannacry': {
        'name': 'WannaCry',
        'type': 'Ransomware',
        'difficulty': 'Medium',
        'year': '2017',
        'min_signatures': 3,
        'signatures': [
            r'\.wnry',
            r'\.wcry',
            r'WanaDecryptor',
            r'WanaCrypt0r',
            r'Wana\s*Decrypt0r',
            r'@WanaDecryptor@',
            r'Iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea',
            r'MsWinZonesCacheCounterMutex',
            r'Global\\MsWinZone',
            r'vssadmin.*delete.*shadows',
            r'wbadmin.*delete.*catalog',
            r'bcdedit.*bootstatuspolicy.*ignoreallfailures',
            r'115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn',
            r'tasksche\.exe',
            r'@Please_Read_Me@\.txt',
            r'msg/m_.*\.wnry',
            r'c\.wnry',
            r'r\.wnry',
            r's\.wnry',
            r't\.wnry',
            r'u\.wnry',
            r'taskdl\.exe',
            r'taskse\.exe',
            r'icacls.*grant.*Everyone:F',
            r'attrib.*\+h\s+\.',
            r'DoublePulsar',
            r'EternalBlue',
            r'SMBv1',
            r'MS17-010',
        ]
    },
    'emotet': {
        'name': 'Emotet',
        'type': 'Banking Trojan',
        'difficulty': 'Medium',
        'year': '2014-2021',
        'min_signatures': 3,
        'signatures': [
            r'I98B68E3C',
            r'MAPI32\.dll',
            r'MAPIInitialize',
            r'MAPISendMail',
            r'gate\.php',
            r'/[a-z]{2,8}\.php',
            r'multipart/form-data',
            r'Content-Disposition:\s*form-data',
            r'TrickBot',
            r'Qakbot',
            r'RegCreateKeyExW',
            r'RegSetValueExW',
            r'VirtualAlloc',
            r'VirtualProtect',
            r'CreateProcessW',
            r'WriteProcessMemory',
            r'ResumeThread',
            r'NtUnmapViewOfSection',
            r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            r'GetTempPathW',
            r'CryptAcquireContextW',
            r'CryptGenRandom',
            r'InternetOpenW',
            r'InternetConnectW',
            r'HttpOpenRequestW',
            r'HttpSendRequestW',
            r'URLDownloadToFileW',
            r'WNetEnumResourceW',
            r'NetShareEnum',
            r'SHGetFolderPathW',
            r'CommandLineToArgvW',
        ]
    },
    'petya': {
        'name': 'Petya/NotPetya',
        'type': 'Destructive Ransomware',
        'difficulty': 'Medium',
        'year': '2017',
        'min_signatures': 3,
        'signatures': [
            r'If you see this text',
            r'your files are no longer accessible',
            r'1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX',
            r'EternalBlue',
            r'EternalRomance',
            r'MS17-010',
            r'Mimikatz',
            r'sekurlsa::',
            r'PSEXEC',
            r'PsExec\.exe',
            r'vssadmin.*delete.*shadows',
            r'wmic.*shadowcopy.*delete',
            r'wbadmin.*delete.*backup',
            r'bcdedit.*recoveryenabled.*no',
            r'\\\\\.\\PhysicalDrive0',
            r'CreateFileW.*GENERIC_WRITE.*OPEN_EXISTING',
            r'DeviceIoControl',
            r'IOCTL_DISK_',
            r'MBR',
            r'perfc\.dat',
            r'DhcpClientUpdate',
            r'wevtutil.*cl.*System',
            r'wevtutil.*cl.*Security',
            r'TaskKill',
            r'net\s+use',
            r'net\s+share',
            r'\\Device\\Harddisk',
        ]
    },
    'zeus': {
        'name': 'Zeus',
        'type': 'Banking Malware',
        'difficulty': 'Hard',
        'year': '2007-2014',
        'min_signatures': 4,
        'signatures': [
            r'ZBT2\.1',
            r'ZBOT',
            r'__SYSTEM__MUTEX__',
            r'__SYSTEM_MUTEX_',
            r'zbot\.sys',
            r'ntos\.exe',
            r'oembios\.exe',
            r'twext\.exe',
            r'sdra64\.exe',
            r'ws2_32\.dll',
            r'wininet\.dll',
            r'advapi32\.dll',
            r'user32\.dll',
            r'WebInject',
            r'FormGrabber',
            r'HttpOpenRequestA',
            r'HttpSendRequestA',
            r'InternetReadFile',
            r'firefox\.exe',
            r'chrome\.exe',
            r'iexplore\.exe',
            r'opera\.exe',
            r'safari\.exe',
            r'SetWindowsHookExA',
            r'GetAsyncKeyState',
            r'GetForegroundWindow',
            r'GetWindowTextA',
            r'CreateRemoteThread',
            r'VirtualAllocEx',
            r'WriteProcessMemory',
            r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            r'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
            r'ZwQuerySystemInformation',
            r'NtQueryInformationProcess',
            r'CryptEncrypt',
            r'CryptDecrypt',
            r'RC4',
            r'base64',
        ]
    },
    'stuxnet': {
        'name': 'Stuxnet',
        'type': 'Industrial Sabotage',
        'difficulty': 'Hard',
        'year': '2010',
        'min_signatures': 5,
        'signatures': [
            r'mrxnet\.sys',
            r'mrxcls\.sys',
            r'myrtus',
            r'Realtek',
            r'JMicron',
            r'Jmidebs\.sys',
            r'Step7_PLC',
            r'S7-300',
            r'S7-400',
            r'S7-200',
            r'Siemens',
            r'SIMATIC',
            r'WinCC',
            r'PCS\s*7',
            r'1410Hz',
            r'1064Hz',
            r'807Hz',
            r'MS10-046',
            r'MS10-061',
            r'MS08-067',
            r'\.LNK',
            r'CPLINK\.DLL',
            r'ShellExecute',
            r'LoadLibrary',
            r'GetProcAddress',
            r'CreateFileW',
            r'WriteFile',
            r'DeviceIoControl',
            r'\\\\\.\\',
            r'GlobalRoot',
            r'SystemRoot',
            r'kernel32\.dll',
            r'ntdll\.dll',
            r'advapi32\.dll',
            r'ole32\.dll',
            r'rpcrt4\.dll',
            r'DB_CONNECT',
            r'OB_1',
            r'FC_1',
            r'PLC_',
            r'DP_RECV',
            r'DP_SEND',
            r'profibus',
            r'PROFINET',
        ]
    }
}


DANGEROUS_PATTERNS = [
    r'<script[^>]*>[^<]*</script>',
    r'javascript:\s*\w+\(',
    r'on(load|click|error|mouseover)\s*=\s*["\'][^"\']+["\']',
]

def validate_file_upload(file: UploadFile):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    
    if not file.filename.lower().endswith('.yar'):
        raise HTTPException(status_code=400, detail="File must have .yar extension")
    
    filename_pattern = r'^[a-zA-Z0-9_\-\.]+\.yar$'
    if not re.match(filename_pattern, file.filename):
        raise HTTPException(status_code=400, detail="Invalid filename. Only alphanumeric characters, underscores, hyphens, and dots allowed")
    
    if len(file.filename) > 255:
        raise HTTPException(status_code=400, detail="Filename too long")

def validate_file_content(content: bytes):
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="File is empty")
    
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail=f"File too large. Maximum size is {MAX_FILE_SIZE / 1024 / 1024}MB")
    
    if content.startswith(b'\x4D\x5A') or content.startswith(b'\x7F\x45\x4C\x46'):
        raise HTTPException(status_code=400, detail="Binary executable files are not allowed")
    
    if content.startswith(b'PK\x03\x04'):
        raise HTTPException(status_code=400, detail="Archive files are not allowed")
    
    if content.startswith(b'%PDF'):
        raise HTTPException(status_code=400, detail="PDF files are not allowed")
    
    try:
        text_content = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be valid UTF-8 text")
    
    if '\x00' in text_content:
        raise HTTPException(status_code=400, detail="File contains null bytes")
    
    lines = text_content.split('\n')
    if len(lines) > 10000:
        raise HTTPException(status_code=400, detail="File has too many lines")
    
    for line in lines[:100]:
        if len(line) > 10000:
            raise HTTPException(status_code=400, detail="File contains excessively long lines")
    
    has_rule = re.search(r'\brule\s+\w+', text_content, re.IGNORECASE)
    if not has_rule:
        raise HTTPException(status_code=400, detail="File does not appear to contain valid YARA rules")
    
    return text_content

def sanitize_yara_content(content: str):
    content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
    
    lines = content.split('\n')
    sanitized_lines = []
    for line in lines:
        if line.strip():
            sanitized_lines.append(line[:10000])
    
    return '\n'.join(sanitized_lines[:10000])

def count_matching_signatures(yara_rules: str, malware_name: str):
    config = MALWARE_CONFIG.get(malware_name)
    if not config:
        return 0
    
    matched_patterns = 0
    for sig_pattern in config['signatures']:
        if re.search(sig_pattern, yara_rules, re.IGNORECASE):
            matched_patterns += 1
    
    return matched_patterns

def validate_rule_quality(yara_rules: str, malware_name: str):
    config = MALWARE_CONFIG.get(malware_name)
    if not config:
        return
    
    matched_patterns = count_matching_signatures(yara_rules, malware_name)
    min_required = config['min_signatures']
    
    if matched_patterns < min_required:
        raise HTTPException(
            status_code=400,
            detail=f"Rule for {malware_name} requires at least {min_required} valid signature(s). Found {matched_patterns}. Research actual {malware_name} IOCs."
        )

@app.post("/api/scan")
async def scan_malware(file: UploadFile = File(...)):
    validate_file_upload(file)
    
    tmp_path = None
    try:
        content = await file.read()
        text_content = validate_file_content(content)
        yara_rules = sanitize_yara_content(text_content)
        
        if 'FAKE_' in yara_rules or 'REPLACE_WITH_REAL_SIGNATURE' in yara_rules:
            raise HTTPException(status_code=400, detail="Template strings detected. Write authentic YARA rules with real malware signatures.")
        
        if re.search(r'condition:\s*true\s*$', yara_rules, re.MULTILINE | re.IGNORECASE):
            raise HTTPException(status_code=400, detail="Generic 'condition: true' rules are not allowed. Write specific detection logic.")
        
        rule_names = re.findall(r'rule\s+(\w+)', yara_rules, re.IGNORECASE)
        if len(rule_names) > 50:
            raise HTTPException(status_code=400, detail="Too many rules. Maximum 50 rules allowed.")
        
        signature_counts = {}
        
        for rule_name in rule_names:
            if len(rule_name) > 128:
                raise HTTPException(status_code=400, detail=f"Rule name too long: {rule_name[:50]}...")
            
            rule_match = re.search(rf'rule\s+{rule_name}.*?(?=rule\s+\w+|$)', yara_rules, re.IGNORECASE | re.DOTALL)
            if rule_match:
                rule_content = rule_match.group(0)
                
                if len(rule_content) > 100000:
                    raise HTTPException(status_code=400, detail=f"Rule '{rule_name}' is too large")
                
                for malware in MALWARE_SAMPLES.keys():
                    if malware in rule_name.lower():
                        validate_rule_quality(rule_content, malware)
                        signature_counts[malware] = {
                            'matched': count_matching_signatures(rule_content, malware),
                            'required': MALWARE_CONFIG[malware]['min_signatures']
                        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as tmp:
            tmp.write(yara_rules)
            tmp_path = tmp.name
        
        os.chmod(tmp_path, 0o600)
        
        try:
            rules = yara.compile(filepath=tmp_path)
        except yara.SyntaxError as e:
            raise HTTPException(status_code=400, detail=f"YARA syntax error: {str(e)}")
        except yara.Error as e:
            raise HTTPException(status_code=400, detail=f"YARA error: {str(e)}")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid YARA rules: {str(e)}")
        
        results = {}
        matched_count_per_rule = {}
        
        for malware_name, malware_content in MALWARE_SAMPLES.items():
            try:
                matches = rules.match(data=malware_content, timeout=5)
            except yara.TimeoutError:
                raise HTTPException(status_code=400, detail="YARA rule execution timeout. Rules may be too complex.")
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Error scanning {malware_name}: {str(e)}")
            
            detected = False
            for match in matches:
                rule_name_lower = match.rule.lower()
                
                if rule_name_lower not in matched_count_per_rule:
                    matched_count_per_rule[rule_name_lower] = 0
                matched_count_per_rule[rule_name_lower] += 1
                
                valid_names = [
                    f'detect_{malware_name}',
                    f'{malware_name}_detection',
                    f'{malware_name}_detect',
                    f'{malware_name}_rule',
                    f'{malware_name}'
                ]
                
                if rule_name_lower in valid_names:
                    detected = True
                    break
            
            results[malware_name] = detected
        
        for rule_name, count in matched_count_per_rule.items():
            if count >= 4:
                raise HTTPException(status_code=400, detail=f"Rule '{rule_name}' is too generic, matching {count}/6 samples. Each rule must target specific malware.")
        
        detected_count = sum(results.values())
        total_count = len(MALWARE_SAMPLES)
        
        response_data = {
            'success': True,
            'results': results,
            'signature_counts': signature_counts,
            'detected': detected_count,
            'total': total_count
        }
        
        if detected_count == total_count:
            response_data['flag'] = FLAG
            response_data['message'] = "Congratulations! All malware detected!"
        
        return JSONResponse(content=response_data)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except:
                pass

@app.get("/api/malware-info")
async def get_malware_info():
    info = {}
    for key, config in MALWARE_CONFIG.items():
        info[key] = {
            'name': config['name'],
            'type': config['type'],
            'difficulty': config['difficulty'],
            'year': config['year']
        }
    return JSONResponse(content=info)

@app.get("/template.yar")
async def download_template():
    template_path = "template.yar"
    if os.path.exists(template_path):
        return FileResponse(
            template_path,
            media_type="application/octet-stream",
            filename="template.yar"
        )
    raise HTTPException(status_code=404, detail="Template file not found")

app.mount("/assets", StaticFiles(directory="assets", html=True), name="assets")

@app.get("/")
async def read_root():
    return FileResponse("index.html")



if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)