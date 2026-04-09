#!/bin/bash
# run_scenarios.sh
# 6종 공격 시나리오를 순서대로 실행하고 타임스탬프를 기록한다.
# 실행 위치: kali-attacker 컨테이너 내부
# 사용법: bash /scripts/run_scenarios.sh

set -euo pipefail

TIMEFILE="/honeypot_logs/scenario_times.json"
LOG_DIR="/honeypot_logs"
SCENARIO_DIR="/attack_scenarios"
SLEEP_BETWEEN=30   # 시나리오 간 대기 시간 (초) - 로그 flush 보장

# ── 시작 메시지 ──────────────────────────────────────────────────────────────
echo "=============================================="
echo " Docker Honeypot - Attack Scenario Runner"
echo " $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=============================================="
echo ""

mkdir -p "$LOG_DIR"

# ── 타이밍 파일 초기화 ───────────────────────────────────────────────────────
echo "[" > "$TIMEFILE"
FIRST_ENTRY=true

# ── 시나리오 실행 함수 ───────────────────────────────────────────────────────
run_scenario() {
    local num=$1
    local label=$2
    local description=$3

    # 스크립트 파일 찾기
    local script
    script=$(ls "${SCENARIO_DIR}/0${num}_"*.sh 2>/dev/null | head -1)
    if [ -z "$script" ]; then
        echo "[!] Scenario ${num} script not found, skipping"
        return
    fi
    local name
    name=$(basename "$script" .sh)

    echo ""
    echo "----------------------------------------------"
    echo " [${num}/6] ${description}"
    echo " Script: ${script}"
    echo " Label:  ${label}"
    echo "----------------------------------------------"

    local start
    start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    echo " Start:  ${start}"

    # 시나리오 실행 (오류가 있어도 계속 진행)
    bash "$script" 2>&1 | tee "${LOG_DIR}/scenario_${num}_$(date +%Y%m%d_%H%M%S).log" || true

    local end
    end=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    echo " End:    ${end}"

    # JSON 항목 추가 (쉼표 처리)
    if [ "$FIRST_ENTRY" = true ]; then
        FIRST_ENTRY=false
    else
        echo "," >> "$TIMEFILE"
    fi
    printf '  {"scenario": "%s", "label": "%s", "start": "%s", "end": "%s"}' \
        "$name" "$label" "$start" "$end" >> "$TIMEFILE"

    echo " Waiting ${SLEEP_BETWEEN}s before next scenario..."
    sleep "$SLEEP_BETWEEN"
}

# ── 6종 시나리오 실행 ────────────────────────────────────────────────────────
run_scenario 1 "Etc"          "정상 트래픽 (curl/wget/nc)"
run_scenario 2 "Recon"        "포트 스캔 (nmap)"
run_scenario 3 "Brute Force"  "SSH/HTTP/MySQL 브루트포스 (hydra)"
run_scenario 4 "Intrusion"    "웹 공격 (sqlmap/curl → SNARE)"
run_scenario 5 "Intrusion"    "침투 후 명령어 실행 (SSH → Cowrie)"
run_scenario 6 "Intrusion"    "리버스 셸 / C2 (SSH + nc/python3)"

# ── JSON 배열 닫기 ───────────────────────────────────────────────────────────
echo "" >> "$TIMEFILE"
echo "]" >> "$TIMEFILE"

# ── 완료 메시지 ──────────────────────────────────────────────────────────────
echo ""
echo "=============================================="
echo " 모든 시나리오 완료!"
echo " 타이밍 파일: ${TIMEFILE}"
echo ""
echo " 다음 단계:"
echo "   python3 /scripts/parse_logs.py"
echo "   python3 /scripts/label_data.py"
echo ""
echo " 결과 파일:"
echo "   ${LOG_DIR}/auth.csv"
echo "   ${LOG_DIR}/sessions.csv"
echo "   ${LOG_DIR}/input.csv"
echo "=============================================="
