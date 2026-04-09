#!/bin/bash
# setup.sh — Docker Honeypot Lab 초기 설정 스크립트
# 사용법: bash setup.sh

set -e

echo "=================================================="
echo " Docker Honeypot Lab - 초기 설정"
echo "=================================================="

# 1. .env 생성
if [ -f ".env" ]; then
    echo "[!] .env 파일이 이미 존재합니다. 덮어쓰지 않습니다."
else
    cp .env.example .env
    echo "[+] .env 파일 생성 완료"
    echo "    로그 경로를 수정하세요: HONEYPOT_LOGS 변수"
fi

# 2. 로그 디렉터리 생성
LOG_DIR=$(grep HONEYPOT_LOGS .env | cut -d'=' -f2)
echo "[+] 로그 디렉터리 생성: ${LOG_DIR}"
mkdir -p "${LOG_DIR}"/{cowrie,heralding,opencanary,snare,dionaea,mailoney,conpot}

echo ""
echo "=================================================="
echo " 완료! 다음 단계:"
echo ""
echo "  1. .env 파일에서 HONEYPOT_LOGS 경로 확인/수정"
echo "  2. docker compose build"
echo "  3. docker compose up -d"
echo "  4. docker compose ps  (8개 컨테이너 Up 확인)"
echo ""
echo "  공격 시나리오 실행:"
echo "  docker exec -it kali-attacker bash /scripts/run_scenarios.sh"
echo ""
echo "  데이터셋 생성:"
echo "  docker exec kali-attacker bash -c \"python3 /scripts/parse_logs.py && python3 /scripts/label_data.py\""
echo "=================================================="
