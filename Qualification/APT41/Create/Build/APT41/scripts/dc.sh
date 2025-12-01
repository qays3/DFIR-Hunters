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
