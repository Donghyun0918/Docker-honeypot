#!/bin/bash
# lib/tactics_recon.sh - 정찰 전술 함수

tactic_syn_scan() {
    local target
    target=$(rand_pick "${ALL_HONEYPOT_IPS[@]}")
    local speed="T$(rand_int 2 4)"
    # 랜덤 포트 목록 선택
    local all_ports=(21 22 23 25 80 110 143 443 445 1433 3306 3389 5432 5900 6379 8080 8443 27017)
    local n=$(rand_int 6 12)
    local ports
    ports=$(printf '%s\n' "${all_ports[@]}" | shuf | head -n $n | tr '\n' ',' | sed 's/,$//')
    nmap -sS "$speed" -p "$ports" "$target" 2>/dev/null || true
}

tactic_version_scan() {
    local target
    target=$(rand_pick "${ALL_HONEYPOT_IPS[@]}")
    local ports=(21 22 25 80 445 3306 3389)
    local n=$(rand_int 3 5)
    local sel
    sel=$(printf '%s\n' "${ports[@]}" | shuf | head -n $n | tr '\n' ',' | sed 's/,$//')
    nmap -sV -T3 -p "$sel" "$target" 2>/dev/null || true
}

tactic_os_detection() {
    local target
    target=$(rand_pick "${ALL_HONEYPOT_IPS[@]}")
    nmap -O -T3 "$target" 2>/dev/null || true
}

tactic_aggressive_scan() {
    local target
    target=$(rand_pick "$OPENCANARY_IP" "$COWRIE_IP" "$DIONAEA_IP")
    local ports=(21 22 80 445 3389)
    local n=$(rand_int 3 5)
    local sel
    sel=$(printf '%s\n' "${ports[@]}" | shuf | head -n $n | tr '\n' ',' | sed 's/,$//')
    nmap -A -T4 -p "$sel" "$target" 2>/dev/null || true
}

tactic_host_discovery() {
    # 네트워크 호스트 탐색
    nmap -sn 172.30.0.0/24 2>/dev/null || true
}

tactic_udp_scan() {
    local target
    target=$(rand_pick "${ALL_HONEYPOT_IPS[@]}")
    local udp_ports=(53 69 123 161 500 514 1900 5353)
    local n=$(rand_int 3 6)
    local sel
    sel=$(printf '%s\n' "${udp_ports[@]}" | shuf | head -n $n | tr '\n' ',' | sed 's/,$//')
    nmap -sU -T3 -p "$sel" "$target" 2>/dev/null || true
}

tactic_script_scan() {
    local target
    target=$(rand_pick "$OPENCANARY_IP" "$COWRIE_IP" "$HERALDING_IP")
    local scripts=("banner" "ssh-hostkey" "ftp-anon" "http-title" "smb-os-discovery" "snmp-info")
    local script
    script=$(rand_pick "${scripts[@]}")
    nmap -sV --script "$script" -T3 "$target" 2>/dev/null || true
}

tactic_snmp_enum() {
    local target
    target=$(rand_pick "$OPENCANARY_IP" "$CONPOT_IP")
    local communities=("public" "private" "community" "admin" "default")
    local comm
    comm=$(rand_pick "${communities[@]}")
    nmap -sU -p 161 --script snmp-info "$target" 2>/dev/null || true
    snmpwalk -v2c -c "$comm" "$target" 2>/dev/null | head -20 || true
}

tactic_banner_grab_all() {
    local n=$(rand_int 3 7)
    local targets=("${COWRIE_IP}:2222" "${HERALDING_IP}:80" "${OPENCANARY_IP}:21"
                   "${DIONAEA_IP}:445" "${MAILONEY_IP}:25" "${CONPOT_IP}:502")
    for target in $(printf '%s\n' "${targets[@]}" | shuf | head -n $n); do
        local ip="${target%%:*}"
        local port="${target##*:}"
        nc -w 2 "$ip" "$port" < /dev/null 2>/dev/null || true
    done
}

tactic_web_dir_scan() {
    local target="http://${SNARE_IP}:8080"
    local ua
    ua=$(rand_pick "${UA_POOL[@]}")
    local n=$(rand_int 5 12)
    for path in $(printf '%s\n' "${WEB_PATH_POOL[@]}" | shuf | head -n $n); do
        curl -s --max-time 3 -A "$ua" "${target}${path}" -o /dev/null 2>/dev/null || true
    done
}

tactic_rdp_probe() {
    nmap -sV -p 3389 "$OPENCANARY_IP" 2>/dev/null || true
    nc -w 2 "$OPENCANARY_IP" 3389 < /dev/null 2>/dev/null || true
}

tactic_vuln_scan() {
    local target
    target=$(rand_pick "$COWRIE_IP" "$HERALDING_IP" "$DIONAEA_IP")
    local scripts=("vuln" "exploit" "auth" "default")
    local script
    script=$(rand_pick "${scripts[@]}")
    nmap --script "$script" -T3 -p 22,80,445,3306 "$target" 2>/dev/null || true
}
