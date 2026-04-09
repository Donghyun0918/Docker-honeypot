#!/bin/bash
# run_loop.sh - 전체 9종 시나리오를 N회 반복하여 대용량 데이터셋 수집
# 실행 위치: kali-attacker 컨테이너 내부
# 사용법: bash /scripts/run_loop.sh [반복횟수] [시나리오간대기초]
# 예시:   bash /scripts/run_loop.sh 40 5

set -euo pipefail

RUNS=${1:-40}
SLEEP_BETWEEN=${2:-5}
TIMEFILE="/honeypot_logs/scenario_times.json"
LOG_DIR="/honeypot_logs"
SCENARIO_DIR="/attack_scenarios"

echo "=============================================="
echo " Docker Honeypot - Loop Runner"
echo " 목표: ${RUNS}회 × 9종 시나리오"
echo " 시나리오간 대기: ${SLEEP_BETWEEN}초"
echo " 시작: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=============================================="

mkdir -p "$LOG_DIR"

# 타이밍 파일 초기화 (기존 로그는 유지, 타이밍만 리셋)
echo "[" > "$TIMEFILE"
FIRST_ENTRY=true
TOTAL_SCENARIOS=0

# 시나리오 정보 테이블 (번호:레이블)
declare -A SCENARIO_LABELS
SCENARIO_LABELS[1]="Etc"
SCENARIO_LABELS[2]="Recon"
SCENARIO_LABELS[3]="Brute Force"
SCENARIO_LABELS[4]="Intrusion"
SCENARIO_LABELS[5]="Intrusion"
SCENARIO_LABELS[6]="Intrusion"
SCENARIO_LABELS[7]="Malware"
SCENARIO_LABELS[8]="Brute Force"
SCENARIO_LABELS[9]="Recon"

for run in $(seq 1 "$RUNS"); do
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " RUN ${run} / ${RUNS}  [$(date -u +%Y-%m-%dT%H:%M:%SZ)]"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    for num in 1 2 3 4 5 6 7 8 9; do
        script=$(ls "${SCENARIO_DIR}/0${num}_"*.sh 2>/dev/null | head -1 || true)
        if [ -z "$script" ]; then
            continue
        fi

        label="${SCENARIO_LABELS[$num]}"
        name=$(basename "$script" .sh)

        start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        echo " [run${run}] scenario ${num}/9: ${name} (${label})"

        # suppress output for speed; errors ignored
        bash "$script" > /dev/null 2>&1 || true

        end=$(date -u +%Y-%m-%dT%H:%M:%SZ)

        # JSON 타이밍 항목 추가
        if [ "$FIRST_ENTRY" = true ]; then
            FIRST_ENTRY=false
        else
            printf ',' >> "$TIMEFILE"
        fi
        printf '\n  {"scenario": "%s", "label": "%s", "start": "%s", "end": "%s"}' \
            "$name" "$label" "$start" "$end" >> "$TIMEFILE"

        TOTAL_SCENARIOS=$((TOTAL_SCENARIOS + 1))
        sleep "$SLEEP_BETWEEN"
    done

    # 매 5회마다 중간 파싱 실행 (진행 상황 확인)
    if [ $((run % 5)) -eq 0 ]; then
        echo ""
        echo " [중간 파싱] Run ${run} 완료, 로그 파싱 중..."
        python3 /scripts/parse_logs.py 2>/dev/null | tail -5 || true
        python3 /scripts/label_data.py 2>/dev/null | tail -10 || true
        echo ""
    fi
done

# JSON 닫기
printf '\n]\n' >> "$TIMEFILE"

# 최종 파싱 + 레이블링
echo ""
echo "=============================================="
echo " 루프 완료! 총 ${TOTAL_SCENARIOS}회 시나리오 실행"
echo " 최종 파싱 시작..."
echo "=============================================="

python3 /scripts/parse_logs.py
python3 /scripts/label_data.py

echo ""
echo "=============================================="
echo " 완료!"
echo " 종료: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=============================================="
