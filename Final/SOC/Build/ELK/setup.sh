#!/bin/bash

sudo apt update && sudo apt upgrade -y
sudo hostnamectl set-hostname elk-siem
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

sudo ufw allow 22/tcp
sudo ufw allow 5044/tcp
sudo ufw allow 9200/tcp
sudo ufw allow 5601/tcp
sudo ufw --force enable

sudo apt install -y wget curl apt-transport-https gnupg2 software-properties-common

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

sudo apt update
sudo apt install -y elasticsearch

sudo tee /etc/elasticsearch/elasticsearch.yml > /dev/null <<'EOF'
cluster.name: elk-siem-cluster
node.name: elk-node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
xpack.security.enabled: true
xpack.security.enrollment.enabled: true
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
EOF

sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
sleep 90

ELASTIC_PASS=$(sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -b | grep "New value:" | awk '{print $3}')
KIBANA_PASS=$(sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -b | grep "New value:" | awk '{print $3}')

echo "ELASTIC_PASS=$ELASTIC_PASS" > /tmp/elk_creds.txt
echo "KIBANA_PASS=$KIBANA_PASS" >> /tmp/elk_creds.txt

sudo apt install -y kibana

sudo tee /etc/kibana/kibana.yml > /dev/null <<EOF
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://127.0.0.1:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "$KIBANA_PASS"
EOF

sudo systemctl daemon-reload
sudo systemctl enable kibana
sudo systemctl start kibana
sleep 120

sudo apt install -y filebeat auditbeat

sudo tee /etc/filebeat/filebeat.yml > /dev/null <<EOF
filebeat.inputs:
- type: filestream
  id: auth
  enabled: true
  paths:
    - /var/log/auth.log
  tags: ["auth"]

- type: filestream
  id: syslog
  enabled: true
  paths:
    - /var/log/syslog
  tags: ["system"]

output.elasticsearch:
  hosts: ["http://127.0.0.1:9200"]
  username: "elastic"
  password: "$ELASTIC_PASS"

setup.kibana:
  host: "http://127.0.0.1:5601"

processors:
  - add_host_metadata: ~
EOF

sudo tee /etc/auditbeat/auditbeat.yml > /dev/null <<EOF
auditbeat.modules:

- module: auditd
  audit_rules: |
    -w /etc/passwd -p wa -k identity
    -w /etc/shadow -p wa -k identity
    -w /etc/sudoers -p wa -k sudoers
    -w /etc/crontab -p wa -k cron
    -a always,exit -F arch=b64 -S execve -k exec

- module: file_integrity
  paths:
  - /bin
  - /usr/bin
  - /usr/local/bin
  - /etc

- module: system
  datasets:
    - process
    - socket
    - user
  period: 10s

output.elasticsearch:
  hosts: ["http://127.0.0.1:9200"]
  username: "elastic"
  password: "$ELASTIC_PASS"

setup.kibana:
  host: "http://127.0.0.1:5601"

processors:
  - add_host_metadata: ~
EOF

sudo systemctl enable filebeat
sudo systemctl start filebeat
sudo systemctl enable auditbeat
sudo systemctl start auditbeat

sleep 60

curl -X PUT "http://127.0.0.1:9200/_security/role/player_role" \
  -u elastic:$ELASTIC_PASS \
  -H "Content-Type: application/json" \
  -d '{
    "cluster": [],
    "indices": [
      {
        "names": ["filebeat-*", "auditbeat-*", "packetbeat-*"],
        "privileges": ["read"]
      }
    ],
    "applications": [
      {
        "application": "kibana-.kibana",
        "privileges": ["feature_discover.read"],
        "resources": ["*"]
      }
    ],
    "run_as": [],
    "metadata": {
      "version": 1
    }
  }'

curl -X POST "http://127.0.0.1:9200/_security/user/player" \
  -u elastic:$ELASTIC_PASS \
  -H "Content-Type: application/json" \
  -d '{
    "password" : "q4y$_h3r333333",
    "roles" : ["player_role"],
    "full_name" : "Player"
  }'

sudo systemctl restart kibana
sleep 60

echo "========================================="
echo "ELK INSTALLATION COMPLETE"
echo "========================================="
echo ""
echo "KIBANA: http://84.247.162.93:5601"
echo ""
echo "ADMIN: elastic / $ELASTIC_PASS"
echo "PLAYER: player / q4y\$_h3r333333 (DISCOVER ONLY)"
echo ""
echo "Saved: /tmp/elk_creds.txt"
echo "========================================="