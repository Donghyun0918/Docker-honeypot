#!/bin/bash
# 시나리오 05: 침투 후 명령어 실행
# Label: Intrusion
# 설명: SSH 로그인 후 시스템 정찰/권한상승 - 매 실행마다 명령어 랜덤 조합

LABEL="Intrusion"
SCENARIO="post_intrusion"
echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"start\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"

source /attack_scenarios/lib/common.sh
source /attack_scenarios/lib/tactics_intrusion.sh

ALL_TACTICS=(
    tactic_ssh_post_intrusion
    tactic_ssh_post_intrusion
    tactic_ssh_privilege_escalation
    tactic_ssh_post_intrusion
    tactic_ssh_privilege_escalation
)

N=$(rand_int 3 5)
mapfile -t SELECTED < <(rand_subset $N "${ALL_TACTICS[@]}")

for tactic in "${SELECTED[@]}"; do
    echo "[*] $tactic"
    $tactic || true
    rand_sleep 1 4
done

echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"end\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
