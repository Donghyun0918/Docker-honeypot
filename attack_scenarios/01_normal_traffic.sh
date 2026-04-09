#!/bin/bash
# 시나리오 01: 정상 트래픽
# Label: Etc
# 설명: 정상 웹 브라우징, 배너 확인 등 - 매 실행마다 전술 랜덤 선택

LABEL="Etc"
SCENARIO="normal_traffic"
echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"start\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"

source /attack_scenarios/lib/common.sh
source /attack_scenarios/lib/tactics_normal.sh

ALL_TACTICS=(
    tactic_http_browse
    tactic_snare_browse
    tactic_ftp_banner_grab
    tactic_ssh_banner_grab
    tactic_smtp_banner_grab
    tactic_modbus_probe
    tactic_generic_port_knock
    tactic_wget_download
)

N=$(rand_int 4 7)
mapfile -t SELECTED < <(rand_subset $N "${ALL_TACTICS[@]}")

for tactic in "${SELECTED[@]}"; do
    echo "[*] $tactic"
    $tactic || true
    rand_sleep 1 3
done

echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"end\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
