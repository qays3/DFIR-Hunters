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
