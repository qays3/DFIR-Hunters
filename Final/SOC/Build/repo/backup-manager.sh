#!/bin/bash

BACKUP_DIR="/var/backups/system"
DATE=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/sysadmin-toolkit/backup.log"

show_help() {
    echo "Backup Manager - System Backup Utility"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --schedule daily|weekly    Schedule automated backups"
    echo "  --run                      Run backup immediately"
    echo "  --list                     List available backups"
    echo "  --restore <backup_name>    Restore from backup"
    echo "  --help                     Show this help message"
    echo ""
}

run_backup() {
    echo "[$(date)] Starting backup..." | tee -a $LOG_FILE
    
    mkdir -p $BACKUP_DIR
    
    BACKUP_FILE="$BACKUP_DIR/system_backup_${DATE}.tar.gz"
    
    echo "[*] Backing up /etc..." | tee -a $LOG_FILE
    tar -czf $BACKUP_FILE /etc 2>/dev/null
    
    echo "[*] Backing up /var/www..." | tee -a $LOG_FILE
    tar -czf "$BACKUP_DIR/www_backup_${DATE}.tar.gz" /var/www 2>/dev/null
    
    echo "[+] Backup completed: $BACKUP_FILE" | tee -a $LOG_FILE
    echo "[$(date)] Backup finished" | tee -a $LOG_FILE
}

list_backups() {
    echo "Available backups:"
    ls -lh $BACKUP_DIR 2>/dev/null || echo "No backups found"
}

case "$1" in
    --schedule)
        echo "[*] Scheduling $2 backups..."
        ;;
    --run)
        run_backup
        ;;
    --list)
        list_backups
        ;;
    --help)
        show_help
        ;;
    *)
        show_help
        ;;
esac