#!/bin/bash
# setup.sh — HoneyForge 초기 설정 스크립트
# 사용법: bash setup.sh

set -e

echo "=================================================="
echo " HoneyForge - 초기 설정"
echo "=================================================="

# 1. .env 생성
if [ -f ".env" ]; then
    echo "[!] .env 파일이 이미 존재합니다. 덮어쓰지 않습니다."
else
    cp .env.example .env
    echo "[+] .env 파일 생성 완료"
fi

# 2. 로그 디렉터리 생성
# HONEYPOT_LOGS_HOST 값 추출 (줄 끝 \r 제거)
LOG_DIR=$(grep -m1 "^HONEYPOT_LOGS_HOST=" .env | cut -d'=' -f2- | tr -d '\r')

# Windows 경로(D:/... 또는 D:\...) → WSL 경로(/mnt/d/...) 자동 변환
if [[ "$LOG_DIR" =~ ^([A-Za-z]):[/\\](.*) ]]; then
    drive="${BASH_REMATCH[1],,}"
    rest="${BASH_REMATCH[2]//\\//}"
    LOG_DIR="/mnt/${drive}/${rest}"
fi

echo "[+] 로그 디렉터리 생성: ${LOG_DIR}"
mkdir -p "${LOG_DIR}"/{cowrie,heralding,opencanary,snare,dionaea,mailoney,conpot}
echo "[+] 완료"

echo ""
echo "=================================================="
echo " 완료! 다음 단계:"
echo ""
echo "  1. .env 파일에서 경로 확인/수정"
echo "     PROJECT_HOST       = 클론한 경로  (예: /mnt/d/HoneyForge)"
echo "     HONEYPOT_LOGS_HOST = 로그 저장 경로 (예: /mnt/d/honeypot_logs)"
echo "     SECRET_KEY         = 반드시 변경"
echo ""
echo "  2. docker compose up -d --build"
echo "  3. docker compose ps  (11개 컨테이너 Up 확인)"
echo ""
echo "  대시보드: http://localhost:3000"
echo ""
echo "  관리자 계정 설정 (회원가입 후):"
echo "  docker exec honeyforge-backend sqlite3 /app/data/dashboard.db \\"
echo "    \"UPDATE users SET is_admin=1 WHERE username='계정명';\""
echo "=================================================="
