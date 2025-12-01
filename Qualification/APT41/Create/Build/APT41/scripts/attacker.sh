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
