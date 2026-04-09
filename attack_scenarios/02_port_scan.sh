#!/bin/bash
# 시나리오 02: 포트 스캔 / 정찰
# Label: Recon
# 설명: 다양한 nmap 스캔 + SNMP 열거 - 매 실행마다 전술 랜덤 선택

LABEL="Recon"
SCENARIO="port_scan"
echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"start\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"

source /attack_scenarios/lib/common.sh
source /attack_scenarios/lib/tactics_recon.sh

ALL_TACTICS=(
    tactic_syn_scan
    tactic_version_scan
    tactic_os_detection
    tactic_aggressive_scan
    tactic_host_discovery
    tactic_udp_scan
    tactic_script_scan
    tactic_snmp_enum
    tactic_banner_grab_all
    tactic_web_dir_scan
    tactic_rdp_probe
    tactic_vuln_scan
)

N=$(rand_int 4 7)
mapfile -t SELECTED < <(rand_subset $N "${ALL_TACTICS[@]}")

for tactic in "${SELECTED[@]}"; do
    echo "[*] $tactic"
    $tactic || true
    rand_sleep 1 3
done

echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"end\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
