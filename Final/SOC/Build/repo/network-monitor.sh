#!/bin/bash

INTERVAL=60
LOG_FILE="/var/log/sysadmin-toolkit/network.log"

echo "=========================================="
echo "  Network Monitor"
echo "=========================================="
echo ""

mkdir -p /var/log/sysadmin-toolkit

if [ "$1" = "--interval" ] && [ -n "$2" ]; then
    INTERVAL=$2
fi

echo "[*] Monitoring network (interval: ${INTERVAL}s)"
echo "[*] Press Ctrl+C to stop"
echo ""

while true; do
    TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
    
    CONNECTIONS=$(netstat -an 2>/dev/null | grep ESTABLISHED | wc -l)
    
    RX_BYTES=$(cat /sys/class/net/eth0/statistics/rx_bytes 2>/dev/null || echo 0)
    TX_BYTES=$(cat /sys/class/net/eth0/statistics/tx_bytes 2>/dev/null || echo 0)
    
    echo "[$TIMESTAMP] Connections: $CONNECTIONS | RX: $RX_BYTES | TX: $TX_BYTES"
    echo "[$TIMESTAMP] Connections: $CONNECTIONS | RX: $RX_BYTES | TX: $TX_BYTES" >> $LOG_FILE
    
    sleep $INTERVAL
done