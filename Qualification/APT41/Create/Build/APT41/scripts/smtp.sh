#!/bin/bash

echo "Mail server initializing..."

echo "myhostname = mail-internal.corp.local" >> /etc/postfix/main.cf
echo "mydomain = corp.local" >> /etc/postfix/main.cf

service postfix start

email_exfil_listener() {
    while true; do
        {
            read line
            if [[ "$line" == *"MAIL FROM"* ]]; then
                echo "250 OK"
            elif [[ "$line" == *"RCPT TO"* ]]; then
                echo "250 OK"
            elif [[ "$line" == "DATA" ]]; then
                echo "354 Start mail input"
                while read email_line; do
                    if [[ "$email_line" == "." ]]; then
                        break
                    fi
                    echo "[$(date)] EMAIL: $email_line" >> /var/log/mail_intercept.log
                done
                echo "250 OK"
            elif [[ "$line" == "QUIT" ]]; then
                echo "221 Bye"
                break
            else
                echo "250 OK"
            fi
        } | nc -l -p 25 || true
        sleep 1
    done
}

email_exfil_listener &

tail -f /dev/null
