#!/bin/bash
# 시나리오 04: 웹 공격
# Label: Intrusion
# 설명: SQLi/XSS/LFI/RFI/CMD injection/웹스캐너 - 매 실행마다 전술 랜덤

LABEL="Intrusion"
SCENARIO="web_attacks"
echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"start\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"

source /attack_scenarios/lib/common.sh
source /attack_scenarios/lib/tactics_intrusion.sh

ALL_TACTICS=(
    tactic_sqli_manual
    tactic_sqli_sqlmap
    tactic_xss
    tactic_lfi
    tactic_web_scanner
    tactic_path_traversal
    tactic_rfi
    tactic_cmd_injection
)

N=$(rand_int 4 6)
mapfile -t SELECTED < <(rand_subset $N "${ALL_TACTICS[@]}")

for tactic in "${SELECTED[@]}"; do
    echo "[*] $tactic"
    $tactic || true
    rand_sleep 1 3
done

echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"end\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
