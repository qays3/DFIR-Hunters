#!/bin/bash

PCAP_FILE="sample.pcap"
OUTPUT_DIR="./770c7d50-126d-481a-80d5-a04d076d3aa8"

mkdir -p "$OUTPUT_DIR"

tshark -r "$PCAP_FILE" -Y 'tcp.port == 22 and frame contains "Failed password"' -T fields -e frame.time_epoch -e ip.src -e tcp.payload 2>/dev/null | \
while IFS=$'\t' read -r timestamp src payload; do
    if [ -n "$payload" ]; then
        if echo "$payload" | grep -qE '^[0-9A-Fa-f]+$'; then
            echo "$payload" | xxd -r -p 2>/dev/null | grep -ao 'Failed password.*' | head -1
        else
            echo "$payload" | grep -ao 'Failed password.*' | head -1
        fi
    fi
done | sort -u > "$OUTPUT_DIR/ssh_bruteforce.txt"

tshark -r "$PCAP_FILE" -Y 'http.request and http.request.uri' -T fields -e http.request.uri 2>/dev/null | \
python3 -c "import sys, urllib.parse; [print(urllib.parse.unquote(line.strip())) for line in sys.stdin if line.strip()]" > "$OUTPUT_DIR/sql_injection.txt"

tshark -r "$PCAP_FILE" -Y 'dns.qry.name' -T fields -e dns.qry.name 2>/dev/null | \
grep -v '^$' | \
awk -F'.' '
{
    sub(/^ +| +$/,"");
    if(length($1) > 20) print $1;
    n=NF;
    if(n>=2){
        tld=$(n-1)"."$n;
        if(tolower(tld) ~ /(tk|ml|ga|cf)$/) print tld;
    }
}' | \
grep -Eio 'exfil|tunnel|tk$|ml$|ga$|cf$|[a-z0-9]{30,}' | \
sort -u > "$OUTPUT_DIR/dns_tunneling.txt"

tshark -r "$PCAP_FILE" -Y 'http.request or http.cookie or http.user_agent' -T fields -e http.request.uri -e http.cookie -e http.user_agent 2>/dev/null | \
tr '\t' '\n' | \
grep -Eio 'activity|submit|pixel|load|__utm|__cfduid|MSIE|Windows NT' | \
sort -u > "$OUTPUT_DIR/cobalt_strike.txt"

tshark -r "$PCAP_FILE" -Y 'http' -T fields -e http.file_data -e http.request.uri -e http.user_agent 2>/dev/null | \
tr '\t' '\n' | \
grep -Eio 'victim_id|victim|btc=|bitcoin|encrypt|decrypt|ransom|payment|[13][a-km-zA-HJ-NP-Z1-9]{25,34}' | \
sort -u > "$OUTPUT_DIR/ransomware_c2.txt"

tshark -r "$PCAP_FILE" -Y 'http.request' -T fields -e http.content_type -e http.file_data -e tcp.payload -e http.request.method 2>/dev/null | \
while IFS=$'\t' read -r content_type filedata tcppayload method; do
    if [[ -z "$content_type" && -z "$filedata" && -z "$tcppayload" ]]; then
        continue
    fi
    if [[ -n "$method" && "$method" != "POST" && "$content_type" != *multipart* ]]; then
        continue
    fi
    src=""
    if [ -n "$filedata" ]; then
        src="$filedata"
    elif [ -n "$tcppayload" ]; then
        src="$tcppayload"
    else
        src=""
    fi
    if [ -z "$src" ]; then
        continue
    fi
    if echo "$src" | grep -qE '^[0-9A-Fa-f]+$'; then
        decoded=$(echo "$src" | xxd -r -p 2>/dev/null || echo "")
    else
        decoded="$src"
    fi
    if [ -n "$decoded" ]; then
        echo "$decoded" | grep -Eao 'Content-Disposition|filename=|multipart/form-data|password|credential|customer|financial|[0-9]{3}-[0-9]{2}-[0-9]{4}|[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}' || true
    fi
done | sort -u > "$OUTPUT_DIR/data_exfiltration.txt"

ls -lh "$OUTPUT_DIR/"
