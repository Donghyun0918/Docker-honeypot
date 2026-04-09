#!/bin/bash
# 시나리오 01: 정상 트래픽
# Label: Etc
# 도구: curl, wget, nc
# 설명: 정상적인 HTTP 브라우징, SSH 배너 확인, FTP 배너 확인

LABEL="Etc"
SCENARIO="normal_traffic"
echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"start\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"

# Heralding HTTP - 정상 웹 브라우징 시뮬레이션
curl -s --max-time 5 http://172.30.0.11/ > /dev/null
curl -s --max-time 5 http://172.30.0.11/index.html > /dev/null
curl -s --max-time 5 http://172.30.0.11/robots.txt > /dev/null
curl -s --max-time 5 http://172.30.0.11/favicon.ico > /dev/null
wget -q --timeout=5 -O /dev/null http://172.30.0.11/ 2>/dev/null || true
wget -q --timeout=5 -O /dev/null http://172.30.0.11/about 2>/dev/null || true

# SNARE HTTP - 정상 웹 탐색
curl -s --max-time 5 http://172.30.0.13:8080/ > /dev/null
curl -s --max-time 5 http://172.30.0.13:8080/index.html > /dev/null

# OpenCanary FTP 배너만 확인 (인증 없이)
curl -s ftp://172.30.0.12/ --max-time 3 > /dev/null 2>/dev/null || true

# Cowrie SSH 배너 확인 (인증 없이 연결 종료)
nc -w 3 172.30.0.10 2222 < /dev/null 2>/dev/null || true

# Conpot - Modbus 포트 간단 탐색
nc -w 2 172.30.0.16 502 < /dev/null 2>/dev/null || true

sleep 2

echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"end\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
