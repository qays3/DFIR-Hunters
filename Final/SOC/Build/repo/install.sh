#!/bin/bash

clear
echo "=========================================="
echo "  Linux SysAdmin Toolkit - Installer"
echo "  Version 2.1.0"
echo "=========================================="
echo ""

if [ "$EUID" -ne 0 ]; then 
    echo "[!] Please run as root or with sudo"
    exit 1
fi

echo "[*] Checking system compatibility..."
sleep 1

if [ -f /etc/debian_version ]; then
    DISTRO="debian"
    echo "[+] Detected: Debian/Ubuntu"
elif [ -f /etc/redhat-release ]; then
    DISTRO="redhat"
    echo "[+] Detected: RHEL/CentOS"
else
    echo "[!] Unsupported distribution"
    exit 1
fi

echo "[*] Creating configuration directories..."
mkdir -p /etc/sysadmin-toolkit
mkdir -p /var/log/sysadmin-toolkit
mkdir -p /opt/sysadmin-toolkit

echo "[*] Installing dependencies..."
if [ "$DISTRO" = "debian" ]; then
    apt-get update -qq
    apt-get install -y curl wget net-tools sysstat >/dev/null 2>&1
else
    yum install -y curl wget net-tools sysstat -q >/dev/null 2>&1
fi

echo "[*] Copying scripts to /opt/sysadmin-toolkit..."
cp *.sh /opt/sysadmin-toolkit/
chmod +x /opt/sysadmin-toolkit/*.sh

echo "[*] Creating default configuration..."
cat > /etc/sysadmin-toolkit/config.conf <<EOF
# SysAdmin Toolkit Configuration
BACKUP_PATH="/var/backups"
LOG_RETENTION_DAYS=30
MONITOR_INTERVAL=300
ALERT_EMAIL=""
ENABLE_HEALTH_CHECKS=true
AUTO_UPDATES=true
EOF

echo "[*] Setting up PATH..."
if ! grep -q "/opt/sysadmin-toolkit" /etc/profile; then
    echo "export PATH=\$PATH:/opt/sysadmin-toolkit" >> /etc/profile
fi

echo "[*] Running initial health check..."
sleep 2
/opt/sysadmin-toolkit/health-check.sh

echo ""
echo "=========================================="
echo "  Installation Complete!"
echo "=========================================="
echo ""
echo "Available commands:"
echo "  - health-check.sh"
echo "  - backup-manager.sh"
echo "  - log-cleaner.sh"
echo "  - network-monitor.sh"
echo "  - security-audit.sh"
echo ""
echo "Configuration: /etc/sysadmin-toolkit/config.conf"
echo "Logs: /var/log/sysadmin-toolkit/"
echo ""