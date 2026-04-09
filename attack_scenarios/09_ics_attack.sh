#!/bin/bash
# 시나리오 09: ICS/SCADA 공격
# Label: Recon
# 설명: Modbus/SNMP/S7/BACnet/DNP3 - 매 실행마다 전술 + 강도 랜덤

LABEL="Recon"
SCENARIO="ics_attack"
echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"start\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"

source /attack_scenarios/lib/common.sh
source /attack_scenarios/lib/tactics_ics.sh

ALL_TACTICS=(
    tactic_modbus_read
    tactic_modbus_write
    tactic_modbus_flood
    tactic_snmp_enum
    tactic_s7_attack
    tactic_ics_nmap_scan
    tactic_bacnet_probe
    tactic_dnp3_probe
)

N=$(rand_int 4 6)
mapfile -t SELECTED < <(rand_subset $N "${ALL_TACTICS[@]}")

for tactic in "${SELECTED[@]}"; do
    echo "[*] $tactic"
    $tactic || true
    rand_sleep 1 3
done

echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"end\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
