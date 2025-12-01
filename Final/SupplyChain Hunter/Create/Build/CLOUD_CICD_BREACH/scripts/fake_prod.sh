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
