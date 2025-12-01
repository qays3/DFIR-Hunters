
## Question 1: Initial Compromise Analysis
**What is the exact timestamp (UTC) when the initial malicious payload was first downloaded?**

**Answer Format:** YYYY-MM-DD_HH:MM:SS UTC

**tshark Command:**
```bash
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.method == GET and http.request.uri contains \".exe\"" -T fields -e http.request.uri
/campaign/invoice_Q4_2024.pdf.exe


┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.method == GET and http.request.uri contains \"invoice_Q4_2024.pdf.exe\"" -T fields -e frame.time_utc
Sep 19, 2025 23:28:14.251671000 UTC


```

Answer: 2025-09-19_23:28:14

---

## Question 2: C2 Infrastructure Discovery
**How many unique C2 domains were contacted during the attack, and what is the total number of HTTP requests sent to ALL C2 domains combined?**

**Answer Format:** X domains, Y total requests X:Y

**tshark Commands:**
```bash
           
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.host and (http.host contains \"update\" or http.host contains \"microsoft\" or http.host contains \"adobe\")" -T fields -e http.host | sort -u        
adobe.com
adobe-security-updates.org:8082
chrome-extension-update.net:8083
microsoft.com
microsoft-update-service.net:8081
windows-defender-updates.com:8082
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request and (http.host contains \"adobe-security-updates.org\" or http.host contains \"chrome-extension-update.net\" or http.host contains \"microsoft-update-service.net\" or http.host contains \"windows-defender-updates.com\")" | wc -l
 
10


```

4 unique C2 domains (excluding legitimate adobe.com and microsoft.com)
10 total HTTP requests to those malicious domains
Answer: 4:10

---

## Question 3: Session Tracking Analysis
**What is the X-Session-ID header value used in the primary C2 communication channel, and how many beacons used this exact session ID?**

**Answer Format:** Session-ID:X (Count beacons)

**tshark Commands:**
```bash

                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request" -O http | grep -A5 "X-Session-ID" | head -10
    X-Session-ID: 8887f071f3c3e5a5583e19d737f52f1a\r\n
    Content-Type: application/x-www-form-urlencoded\r\n
    X-Request-ID: 9a12a9c184bc45a7f809874124354194\r\n
    Content-Length: 117\r\n
        [Content length: 117]
    \r\n
--
    X-Session-ID: 8887f071f3c3e5a5583e19d737f52f1a\r\n
    Content-Type: application/x-www-form-urlencoded\r\n
    X-Request-ID: c1a54294fa6eba34b912cce18a9ef609\r\n



┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "frame contains \"8887f071f3c3e5a5583e19d737f52f1a\"" | wc -l
5

         
```

Answer: 8887f071f3c3e5a5583e19d737f52f1a:5

---

## Question 4: Credential Harvesting Detection
**What are the exact usernames and passwords stolen from the browser credential store? List them in the order they appear in the network traffic.**

**Answer Format:** username1:password1_username2:password2_username3:password3

**tshark Command:**
```bash
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request and frame contains \"X-Password-Key\"" -O http
Frame 61: 221 bytes on wire (1768 bits), 221 bytes captured (1768 bits)
Ethernet II, Src: 02:42:ac:19:01:64 (02:42:ac:19:01:64), Dst: 02:42:ac:19:01:c8 (02:42:ac:19:01:c8)
Internet Protocol Version 4, Src: 172.25.1.100, Dst: 172.25.1.200
Transmission Control Protocol, Src Port: 51516, Dst Port: 8084, Seq: 1, Ack: 1, Len: 155
Hypertext Transfer Protocol
    GET /tools/decrypt.php?key=qaysuruncle HTTP/1.1\r\n
        Request Method: GET
        Request URI: /tools/decrypt.php?key=qaysuruncle
            Request URI Path: /tools/decrypt.php
            Request URI Query: key=qaysuruncle
                Request URI Query Parameter: key=qaysuruncle
        Request Version: HTTP/1.1
    Host: 172.25.1.200:8084\r\n
    Accept: */*\r\n
    User-Agent: CredentialHarvester/2.1\r\n
    X-Password-Key: qaysuruncle\r\n
    \r\n
    [Full request URI: http://172.25.1.200:8084/tools/decrypt.php?key=qaysuruncle]


tshark: The file "APT41.pcap" appears to have been cut short in the middle of a packet.
                                                                                                    

┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request and frame contains \"X-Data-Type: credentials\"" -T fields -e http.file_data | xxd -r -p | openssl enc -aes-256-cbc -d -a -pass pass:qaysuruncle
*** WARNING : deprecated key derivation used.
Using -iter or -pbkdf2 would be better.
{
        "type":"chrome_passwords",
        "data":[
            {"url":"https://portal.corp.internal","username":"shosho.ahmed","password":"Summer2024!","date_created":"2024-01-15"},
            {"url":"https://payroll.corp.internal","username":"shosho.ahmed","password":"HR_P@ss123","date_created":"2024-02-20"},
            {"url":"https://banking.chase.com","username":"s.ahmed.personal","password":"MyPersonal$2024","date_created":"2024-03-10"}
        ]
    }
       
```

Answer: shosho.ahmed:Summer2024!_shosho.ahmed:HR_P@ss123_s.ahmed.personal:MyPersonal$2024
---

## Question 5: DNS Tunneling Command Extraction
**What are the Base64-encoded commands sent via DNS tunneling, and what do they decode to? List the first 3 commands in chronological order.**

**Answer Format:** command1_command2_command3

**tshark Commands:**
```bash
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y 'dns.qry.name contains "microsoft-update-service.net" and dns.flags.response == 0' -T fields -e dns.qry.name -e frame.time_epoch | head -10

d2hvYW1p.update.microsoft-update-service.net    1758308082.910364000
d2hvYW1p.update.microsoft-update-service.net    1758308087.935801000
d2hvYW1p.update.microsoft-update-service.net    1758308087.935846000
d2hvYW1p.update.microsoft-update-service.net    1758308087.935934000
d2hvYW1p.update.microsoft-update-service.net    1758308087.935944000
response.d2hvYW1p.microsoft-update-service.net  1758308114.959017000
response.d2hvYW1p.microsoft-update-service.net  1758308114.959085000
response.d2hvYW1p.microsoft-update-service.net  1758308114.959137000
response.d2hvYW1p.microsoft-update-service.net  1758308114.959146000
response.d2hvYW1p.microsoft-update-service.net  1758308114.959166000


                                                                                         
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y 'dns.qry.name contains "microsoft-update-service.net" and dns.flags.response == 0' -T fields -e dns.qry.name -e frame.time_epoch | grep -v "response\." | sort -k2 -n | cut -d'.' -f1 | awk '!seen[$1]++'          
d2hvYW1p
bmV0X3VzZXI
aXBjb25maWc
c3lzdGVtaW5mbw
dGFza2xpc3Q
bmV0X2dyb3VwX2RvbWFpbl9hZG1pbnM


┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y 'dns.qry.name contains "microsoft-update-service.net" and dns.flags.response == 0' -T fields -e dns.qry.name -e frame.time_epoch | grep -v "response\." | sort -k2 -n | cut -d'.' -f1 | awk '!seen[$1]++' | head -3

d2hvYW1p
bmV0X3VzZXI
aXBjb25maWc
              

```

Answer: whoami_net_user_ipconfig

---

## Question 6: Lateral Movement Timeline
**At what exact time (UTC) did the attacker begin network reconnaissance scanning, and which three IP addresses were the primary targets?**
Time: YYYY-MM-DD HH:MM:SS UTC, Targets: IP1,IP2,IP3, IPs from small to larg

**Answer Format:**  YYYY-MM-DD_HH:MM:SS_IP1_IP2_IP3



**tshark Commands:**
```bash
 
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.src == 172.25.1.100 and ip.dst_host matches \"172.25.1.*\" and ip.dst != 172.25.1.200 and ip.dst != 172.25.1.3" -T fields -e frame.time_utc -e ip.dst | head -1
Sep 19, 2025 23:28:34.249622000 UTC     172.25.1.10

                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.src == 172.25.1.100 and ip.dst_host matches \"172.25.1.*\" and ip.dst != 172.25.1.200 and ip.dst != 172.25.1.3" -T fields -e ip.dst | sort | uniq -c | sort -nr | head -3
      7 172.25.1.11
      7 172.25.1.101
      7 172.25.1.10


```

Answer: 2025-09-19_23:28:34_172.25.1.10_172.25.1.11_172.25.1.101

---

## Question 7: Malware Hash Correlation
**What is the MD5 hash value transmitted in the 'malware_deploy' POST request, and what malware family name is associated with it?**

**Answer Format:**  Hash_FamilyName

**tshark Command:**
```bash
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.method == POST and http.request.uri contains \"malware_deploy\"" -T fields -e http.file_data
7b2268617368223a223034666230636366336566333039623163643538376636303961623065383165222c2266616d696c79223a22435241434b53484f54222c226465706c6f796d656e74223a226c61746572616c5f737072656164227d
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.method == POST and http.request.uri contains \"malware_deploy\"" -T fields -e http.file_data | xxd -r -p | jq -r '"\(.hash),\(.family)"'
04fb0ccf3ef309b1cd587f609ab0e81e,CRACKSHOT
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.method == POST and http.request.uri contains \"malware_deploy\"" -O http
Frame 350: 308 bytes on wire (2464 bits), 308 bytes captured (2464 bits)
Ethernet II, Src: 02:42:ac:19:01:64 (02:42:ac:19:01:64), Dst: 02:42:ac:19:01:c8 (02:42:ac:19:01:c8)
Internet Protocol Version 4, Src: 172.25.1.100, Dst: 172.25.1.200
Transmission Control Protocol, Src Port: 52152, Dst Port: 8081, Seq: 1, Ack: 56, Len: 242
Hypertext Transfer Protocol
    POST /malware_deploy HTTP/1.1\r\n
        Request Method: POST
        Request URI: /malware_deploy
        Request Version: HTTP/1.1
    Host: 172.25.1.200:8081\r\n
    User-Agent: curl/7.68.0\r\n
    Accept: */*\r\n
    Content-Type: application/json\r\n
    Content-Length: 94\r\n
        [Content length: 94]
    \r\n
    [Full request URI: http://172.25.1.200:8081/malware_deploy]
    File Data: 94 bytes
JavaScript Object Notation: application/json

```

Answer: 04fb0ccf3ef309b1cd587f609ab0e81e_CRACKSHOT


## Question 8: Data Exfiltration Quantification
**What is the total amount of data exfiltrated via HTTP uploads (in bytes), and through how many different destination ports?**
Total: X bytes, Ports: Y unique ports
**Answer Format:**  X:Y



---

## Question 9: Incident Response Contact Analysis
**What is the exact email address contacted for incident response, and how many bytes of data were transmitted containing this email address?**
Email: address@domain.com, Bytes: XXXX
**Answer Format:** address@domain.com_XXXX

**tshark Commands:**
```bash
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http" -T fields -e http.file_data | xxd -r -p 2>/dev/null 
.........
info@qayssarayra.com


┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "frame contains \"info@qayssarayra.com\"" -T fields -e frame.len | awk '{sum+=$1} END {print sum}'
3255

                      
                              
```

Answer: info@qayssarayra.com_3255

---

## Question 10: Golden Ticket Attack Details
**What is the KRBTGT hash used in the Golden Ticket attack, and what is the Domain SID?**
KRBTGT: [hash], SID: [sid]

**Answer Format:** Hash_sid

**tshark Command:**
 
```bash
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.method == POST and http contains \"krbtgt_hash\"" -T fields -e http.file_data
7b2261747461636b223a22676f6c64656e5f7469636b6574222c226b72627467745f68617368223a223530326332626135633465313233343536373839306162636465663132333435222c22646f6d61696e223a22434f5250222c22736964223a22532d312d352d32312d313233343536373839302d313233343536373839302d31323334353637383930222c2275736572223a2241646d696e6973747261746f72222c2274696d657374616d70223a22467269205365702031392032333a32383a3539205554432032303235227d
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.method == POST and http contains \"krbtgt_hash\"" -T fields -e http.file_data | xxd -r -p
{"attack":"golden_ticket","krbtgt_hash":"502c2ba5c4e1234567890abcdef12345","domain":"CORP","sid":"S-1-5-21-1234567890-1234567890-1234567890","user":"Administrator","timestamp":"Fri Sep 19 23:28:59 UTC 2025"}                                                                                                                                              

```

KRBTGT: 502c2ba5c4e1234567890abcdef12345, SID: S-1-5-21-1234567890-1234567890-1234567890

Answer: 502c2ba5c4e1234567890abcdef12345_S-1-5-21-1234567890-1234567890-1234567890
---

## Question 11: Anti-Forensics Timeline
**At what time did the anti-forensics activities begin, and what specific action was reported to the C2 server?**

**Answer Format:** YYYY-MM-DD_HH:MM:SS_ActionName

**tshark Command:**
```bash
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.method == POST and http contains \"cleanup\"" -T fields -e frame.time -e http.file_data
Sep 19, 2025 19:29:04.260530000 EDT     7b22616374696f6e223a22636c65616e7570222c22737461747573223a22636f6d706c657465222c2274696d657374616d70223a22467269205365702031392032333a32393a3034205554432032303235227d
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.method == POST and http contains \"cleanup\"" -T fields -e frame.time -e http.file_data | while read time data; do echo "$time"; echo "$data" | xxd -r -p 2>/dev/null; done
Sep
 %)&0{"action":"cleanup","status":"complete","timestamp":"Fri Sep 19 23:29:04 UTC 2025"}                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.uri contains \"cleanup\"" -T fields -e frame.time -e http.file_data
Sep 19, 2025 19:29:04.260530000 EDT     7b22616374696f6e223a22636c65616e7570222c22737461747573223a22636f6d706c657465222c2274696d657374616d70223a22467269205365702031392032333a32393a3034205554432032303235227d
Sep 19, 2025 19:29:04.260576000 EDT     4e6f7420466f756e64,0a
                                                                                                                                              

```

Answer: 2025-09-19_19:29:04_cleanup

---

 

## Question 12: Persistence Mechanism Analysis
**How many different persistence mechanisms were deployed, and what is the total time span (in seconds) between the first and last persistence installation?**
Mechanisms: X, Timespan: Y seconds
**Answer Format:**  X:Y

**tshark Commands:**
```bash
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.method == POST and (http contains \"golden_ticket\" or http contains \"persistence\" or http contains \"cleanup\")" -T fields -e frame.time -e http.request.uri -e http.file_data
Sep 19, 2025 19:28:59.253845000 EDT     /api/v1/persistence     7b2261747461636b223a22676f6c64656e5f7469636b6574222c226b72627467745f68617368223a223530326332626135633465313233343536373839306162636465663132333435222c22646f6d61696e223a22434f5250222c22736964223a22532d312d352d32312d313233343536373839302d313233343536373839302d31323334353637383930222c2275736572223a2241646d696e6973747261746f72222c2274696d657374616d70223a22467269205365702031392032333a32383a3539205554432032303235227d
Sep 19, 2025 19:29:04.260530000 EDT     /api/v1/cleanup 7b22616374696f6e223a22636c65616e7570222c22737461747573223a22636f6d706c657465222c2274696d657374616d70223a22467269205365702031392032333a32393a3034205554432032303235227d
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.method == POST and (http contains \"golden_ticket\" or http contains \"cleanup\")" -T fields -e frame.time_epoch
1758324539.253845000
1758324544.260530000
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.uri contains \"persistence\" or http.request.uri contains \"cleanup\"" -T fields -e frame.time -e http.request.uri
Sep 19, 2025 19:28:59.253845000 EDT     /api/v1/persistence
Sep 19, 2025 19:28:59.253943000 EDT     /api/v1/persistence
Sep 19, 2025 19:29:04.260530000 EDT     /api/v1/cleanup
Sep 19, 2025 19:29:04.260576000 EDT     /api/v1/cleanup
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.method == POST and (http contains \"golden_ticket\" or http contains \"cleanup\")" -T fields -e frame.time_epoch
1758324539.253845000
1758324544.260530000
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ # 1758324544.260530000 - 1758324539.253845000 = 5.006685 seconds
                                                                     
```

Answer:  1:5

---

## Question 13: File Server Compromise
**Which classified document was accessed first on the file server, and how many total file access events were logged?**
First File: [filename], Total Events: X
**Answer Format:** Filename_X

**tshark Commands:**
```bash 
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.uri contains \"stage\"" -T fields -e frame.time -e http.file_data
Sep 19, 2025 19:28:39.272813000 EDT     7b0a2020202020202020226f7065726174696f6e223a22646174615f636f6c6c656374696f6e222c0a20202020202020202266696c6573223a5b0a2020202020202020202020207b2270617468223a22433a5c5c55736572735c5c73686f73686f5c5c446f63756d656e74735c5c456d706c6f7965655f44617461626173652e786c7378222c2273697a65223a22322e344d42222c2268617368223a226434316438636439386630306232303465393830303939386563663834323765227d2c0a2020202020202020202020207b2270617468223a22433a5c5c55736572735c5c616d6565645c5c4465736b746f705c5c53616c6172795f5265706f72745f323032342e646f6378222c2273697a65223a223835364b42222c2268617368223a226539396131386334323863623338643566323630383533363738393232653033227d2c0a2020202020202020202020207b2270617468223a22433a5c5c55736572735c5c5075626c69635c5c5368617265645c5c48525f506f6c69636965732e706466222c2273697a65223a22312e324d42222c2268617368223a226162383764323462646337343532653535373338646562356638363865316637227d0a20202020202020205d2c0a202020202020202022746f74616c5f73697a65223a22342e354d42222c0a20202020202020202273746167696e675f74696d65223a22323032352d30392d31395f32333a32383a3339220a202020207d
Sep 19, 2025 19:28:39.272856000 EDT     7b22737461747573223a22737461676564,227d0a
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.uri contains \"stage\"" -T fields -e http.file_data | xxd -r -p
{
        "operation":"data_collection",
        "files":[
            {"path":"C:\\Users\\shosho\\Documents\\Employee_Database.xlsx","size":"2.4MB","hash":"d41d8cd98f00b204e9800998ecf8427e"},
            {"path":"C:\\Users\\ameed\\Desktop\\Salary_Report_2024.docx","size":"856KB","hash":"e99a18c428cb38d5f260853678922e03"},
            {"path":"C:\\Users\\Public\\Shared\\HR_Policies.pdf","size":"1.2MB","hash":"ab87d24bdc7452e55738deb5f868e1f7"}
        ],
        "total_size":"4.5MB",
        "staging_time":"2025-09-19_23:28:39"
    }{"status":"staged"}
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.uri contains \"stage\"" -T fields -e frame.time | wc -l
2
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.uri contains \"stage\" and http.request.method == POST" -T fields -e frame.time
Sep 19, 2025 19:28:39.272813000 EDT
                                      

```
First File: Employee_Database.xlsx, Total Events: 1

Answer: Employee_Database.xlsx_1

---

## Question 14: Complete Attack Chain Reconstruction
**Arrange these attack phases in chronological order based on the network evidence: [A] Credential Harvesting, [B] Initial Compromise, [C] Data Exfiltration, [D] Lateral Movement, [E] C2 Establishment, [F] Persistence Installation**

**Answer Format:** B_E_A_D_F_C  

**tshark Command:**
```bash
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.method == POST or http.request.method == GET" -T fields -e frame.time -e http.request.uri -e ip.src -e ip.dst | head -20
Sep 19, 2025 19:28:11.780705000 EDT     /       172.25.1.100    172.64.155.249
Sep 19, 2025 19:28:14.251671000 EDT     /campaign/invoice_Q4_2024.pdf.exe       172.25.1.100    172.25.1.200
Sep 19, 2025 19:28:19.284331000 EDT     /api/v1/check   172.25.1.100    172.25.1.200
Sep 19, 2025 19:28:24.251231000 EDT     /tools/vaultkey?key=qaysuruncle 172.25.1.100    172.25.1.200
Sep 19, 2025 19:28:26.282065000 EDT     /api/upload     172.25.1.100    172.25.1.200
Sep 19, 2025 19:28:27.309115000 EDT     /api/v1/check   172.25.1.100    172.25.1.200
Sep 19, 2025 19:28:35.325961000 EDT     /api/v1/check   172.25.1.100    172.25.1.200
Sep 19, 2025 19:28:39.272813000 EDT     /api/stage      172.25.1.100    172.25.1.200
Sep 19, 2025 19:28:44.257005000 EDT     /malware_deploy 172.25.1.100    172.25.1.200
Sep 19, 2025 19:28:45.345782000 EDT     /api/v1/check   172.25.1.100    172.25.1.200
Sep 19, 2025 19:28:47.565941000 EDT     /api/v1/recon   172.25.1.100    172.25.1.200
Sep 19, 2025 19:28:49.274453000 EDT     /api/upload     172.25.1.100    172.25.1.200
Sep 19, 2025 19:28:55.367771000 EDT     /api/v1/check   172.25.1.100    172.25.1.200
Sep 19, 2025 19:28:59.253845000 EDT     /api/v1/persistence     172.25.1.100    172.25.1.200
Sep 19, 2025 19:29:04.260530000 EDT     /api/v1/cleanup 172.25.1.100    172.25.1.200
Sep 19, 2025 19:29:09.261834000 EDT     /       172.25.1.100    172.25.1.3
Sep 19, 2025 19:29:11.295249000 EDT     /       172.25.1.100    172.25.1.3
Sep 19, 2025 19:29:14.807262000 EDT     /       172.25.1.100    172.25.1.3
Sep 19, 2025 19:29:26.916610000 EDT     /       172.25.1.100    140.82.121.3
Sep 19, 2025 19:30:36.539155000 EDT     /       172.25.1.100    172.64.155.249
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.uri contains \"invoice_Q4_2024.pdf.exe\"" -T fields -e frame.time
Sep 19, 2025 19:28:14.251671000 EDT
Sep 19, 2025 19:28:14.251682000 EDT
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.uri contains \"check\"" -T fields -e frame.time | head -1
Sep 19, 2025 19:28:19.284331000 EDT
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.uri contains \"vaultkey\"" -T fields -e frame.time
Sep 19, 2025 19:28:24.251231000 EDT
Sep 19, 2025 19:28:24.251337000 EDT
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "(tcp.dstport == 22 or tcp.dstport == 445) and ip.src == 172.25.1.100 and ip.dst != 172.25.1.200" -T fields -e frame.time | head -1
Sep 19, 2025 19:28:34.249622000 EDT
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.uri contains \"persistence\"" -T fields -e frame.time | head -1
Sep 19, 2025 19:28:59.253845000 EDT
                                                                                                                                              
┌──(hidden㉿Ultra)-[~/…/Network/ss/APT41/pcaps]
└─$ tshark -r APT41.pcap -Y "http.request.uri contains \"upload\" or tcp.dstport == 9001" -T fields -e frame.time | head -1
Sep 19, 2025 19:28:26.282065000 EDT

```
Initial Compromise (B): Sep 19, 2025 19:28:14 (invoice download)
C2 Establishment (E): Sep 19, 2025 19:28:19 (first /api/v1/check)
Credential Harvesting (A): Sep 19, 2025 19:28:24 (vaultkey request)
Data Exfiltration (C): Sep 19, 2025 19:28:26 (first upload)
Lateral Movement (D): Sep 19, 2025 19:28:34 (port scanning)
Persistence Installation (F): Sep 19, 2025 19:28:59 (persistence endpoint)


Answer: B_E_A_C_D_F

