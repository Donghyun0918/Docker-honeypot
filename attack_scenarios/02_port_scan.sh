#!/bin/bash
# 시나리오 02: 포트 스캔
# Label: Recon
# 도구: nmap
# 설명: OpenCanary의 포트스캔 탐지 모듈을 트리거하는 다양한 nmap 스캔

LABEL="Recon"
SCENARIO="port_scan"
echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"start\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"

# SYN 스캔 - OpenCanary portscan 모듈 트리거
nmap -sS -T4 -p 21,22,23,25,80,443,445,1433,3306,3389,5900,8080 172.30.0.12 2>/dev/null

# OS 핑거프린팅 스캔 - nmaposrate 임계값 트리거
nmap -O -T3 172.30.0.12 2>/dev/null

# 전체 허니팟 서비스 버전 스캔
nmap -sV -T3 -p 2222,80,445,8080 \
    172.30.0.10 \
    172.30.0.11 \
    172.30.0.13 \
    172.30.0.14 2>/dev/null

# UDP SNMP 스캔 (Conpot)
nmap -sU -p 161 172.30.0.16 2>/dev/null

# 전체 네트워크 호스트 탐색
nmap -sn 172.30.0.0/24 2>/dev/null

# Aggressive 스캔 (스크립트 + 버전 + OS)
nmap -A -T4 -p 21,22,80,445,3389 172.30.0.12 2>/dev/null

echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"end\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
