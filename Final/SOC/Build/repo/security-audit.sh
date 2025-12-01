#!/bin/bash

echo "=========================================="
echo "  Security Audit Tool"
echo "=========================================="
echo ""

if [ "$EUID" -ne 0 ]; then 
    echo "[!] Please run as root"
    exit 1
fi

echo "[*] Running security checks..."
echo ""

echo "[*] Checking for users with UID 0..."
awk -F: '($3 == 0) {print $1}' /etc/passwd

echo ""
echo "[*] Checking for empty passwords..."
awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null | head -5

echo ""
echo "[*] Checking listening ports..."
netstat -tuln 2>/dev/null | grep LISTEN | head -10

echo ""
echo "[*] Checking failed login attempts..."
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5

echo ""
echo "[*] Checking SSH configuration..."
if [ -f /etc/ssh/sshd_config ]; then
    echo "PermitRootLogin: $(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')"
    echo "PasswordAuthentication: $(grep "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}')"
fi

echo ""
echo "[*] Checking firewall status..."
ufw status 2>/dev/null || iptables -L -n 2>/dev/null | head -10

echo ""
echo "[+] Security audit completed"