#!/bin/bash

LOG_DIRS="/var/log"
RETENTION_DAYS=30

echo "=========================================="
echo "  Log Cleaner - Log Management Tool"
echo "=========================================="
echo ""

if [ "$EUID" -ne 0 ]; then 
    echo "[!] Please run as root"
    exit 1
fi

echo "[*] Scanning for old log files (older than ${RETENTION_DAYS} days)..."

FOUND_FILES=$(find $LOG_DIRS -type f -name "*.log" -mtime +$RETENTION_DAYS 2>/dev/null | wc -l)

echo "[*] Found $FOUND_FILES log files to clean"

if [ $FOUND_FILES -gt 0 ]; then
    echo "[*] Cleaning old logs..."
    find $LOG_DIRS -type f -name "*.log" -mtime +$RETENTION_DAYS -delete 2>/dev/null
    echo "[+] Log cleanup completed"
else
    echo "[*] No old logs to clean"
fi

echo "[*] Compressing recent logs..."
find $LOG_DIRS -type f -name "*.log" -mtime +7 ! -name "*.gz" -exec gzip {} \; 2>/dev/null

echo "[*] Current log directory sizes:"
du -sh $LOG_DIRS/* 2>/dev/null | head -10

echo ""
echo "[+] Log cleanup finished"