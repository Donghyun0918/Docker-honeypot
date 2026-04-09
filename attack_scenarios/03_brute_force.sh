#!/bin/bash
# 시나리오 03: 브루트포스 / 자격증명 스터핑
# Label: Brute Force
# 설명: SSH/HTTP/MySQL/FTP/RDP/SMTP 등 - 매 실행마다 전술 + 타겟 + 패스워드 랜덤

LABEL="Brute Force"
SCENARIO="brute_force"
echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"start\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"

source /attack_scenarios/lib/common.sh
source /attack_scenarios/lib/tactics_brute.sh

ALL_TACTICS=(
    tactic_ssh_brute_single
    tactic_ssh_brute_multi
    tactic_ssh_brute_targeted
    tactic_telnet_brute
    tactic_http_brute
    tactic_mysql_brute
    tactic_ftp_brute
    tactic_rdp_brute
    tactic_mssql_brute
    tactic_smtp_brute
    tactic_credential_spray
)

N=$(rand_int 4 7)
mapfile -t SELECTED < <(rand_subset $N "${ALL_TACTICS[@]}")

for tactic in "${SELECTED[@]}"; do
    echo "[*] $tactic"
    $tactic || true
    rand_sleep 1 3
done

echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"end\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
