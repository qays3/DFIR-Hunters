#!/bin/bash

echo "REMOVING ELK STACK"

sudo systemctl stop filebeat auditbeat kibana elasticsearch
sudo systemctl disable filebeat auditbeat kibana elasticsearch

sudo apt remove --purge -y filebeat auditbeat kibana elasticsearch
sudo apt autoremove -y
sudo apt autoclean

sudo rm -rf /var/lib/elasticsearch
sudo rm -rf /var/lib/kibana
sudo rm -rf /var/log/elasticsearch
sudo rm -rf /var/log/kibana
sudo rm -rf /etc/elasticsearch
sudo rm -rf /etc/kibana
sudo rm -rf /etc/filebeat
sudo rm -rf /etc/auditbeat
sudo rm -rf /var/lib/filebeat
sudo rm -rf /var/lib/auditbeat

sudo rm -f /etc/apt/sources.list.d/elastic-8.x.list
sudo rm -f /usr/share/keyrings/elasticsearch-keyring.gpg
sudo rm -f /tmp/elk_creds.txt

sudo apt update

echo "ELK REMOVED"