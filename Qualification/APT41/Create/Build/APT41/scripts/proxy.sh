#!/bin/bash

echo "Internal proxy server starting..."

cat > /etc/squid/squid.conf << 'SQUID_EOF'
http_port 3128
access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log

acl internal_net src 172.25.1.0/24
http_access allow internal_net
http_access deny all

cache_dir ufs /var/spool/squid 100 16 256
SQUID_EOF

service squid start

tail -f /var/log/squid/access.log &

tail -f /dev/null
