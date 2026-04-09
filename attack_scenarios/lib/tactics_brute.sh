#!/bin/bash
# lib/tactics_brute.sh - 브루트포스 / 자격증명 스터핑 전술 함수

_make_wordlist() {
    # PASS_POOL에서 랜덤 N개 선택해 임시 파일 생성
    local n=${1:-20}
    local tmpfile="/tmp/wl_$$.txt"
    printf '%s\n' "${PASS_POOL[@]}" | shuf | head -n "$n" > "$tmpfile"
    echo "$tmpfile"
}

_make_userlist() {
    local n=${1:-10}
    local tmpfile="/tmp/ul_$$.txt"
    printf '%s\n' "${USER_POOL[@]}" | shuf | head -n "$n" > "$tmpfile"
    echo "$tmpfile"
}

tactic_ssh_brute_single() {
    local user
    user=$(rand_pick "${USER_POOL[@]}")
    local wl
    wl=$(_make_wordlist "$(rand_int 15 40)")
    local threads=$(rand_int 2 6)
    hydra -l "$user" -P "$wl" -t "$threads" -f \
        -o "/honeypot_logs/hydra_ssh_${user}_$$.txt" \
        ssh://${COWRIE_IP}:2222 -e nsr 2>/dev/null || true
    rm -f "$wl"
}

tactic_ssh_brute_multi() {
    local ul
    ul=$(_make_userlist "$(rand_int 5 12)")
    local wl
    wl=$(_make_wordlist "$(rand_int 20 50)")
    local threads=$(rand_int 2 4)
    hydra -L "$ul" -P "$wl" -t "$threads" \
        -o "/honeypot_logs/hydra_ssh_multi_$$.txt" \
        ssh://${COWRIE_IP}:2222 -e nsr 2>/dev/null || true
    rm -f "$ul" "$wl"
}

tactic_ssh_brute_targeted() {
    # 특정 알려진 계정 집중 공격
    local targets=("root" "admin" "pi" "ubuntu" "vagrant" "ec2-user")
    local user
    user=$(rand_pick "${targets[@]}")
    local wl
    wl=$(_make_wordlist "$(rand_int 30 60)")
    hydra -l "$user" -P "$wl" -t 4 -f \
        ssh://${COWRIE_IP}:2222 -e nsr 2>/dev/null || true
    rm -f "$wl"
}

tactic_telnet_brute() {
    local user
    user=$(rand_pick "${USER_POOL[@]}")
    local wl
    wl=$(_make_wordlist "$(rand_int 10 25)")
    hydra -l "$user" -P "$wl" -t 4 -f \
        telnet://${COWRIE_IP}:2223 2>/dev/null || true
    rm -f "$wl"
}

tactic_http_brute() {
    local user
    user=$(rand_pick "admin" "administrator" "root" "user" "guest")
    local wl
    wl=$(_make_wordlist "$(rand_int 20 40)")
    hydra -l "$user" -P "$wl" -t 4 -f \
        -o "/honeypot_logs/hydra_http_$$.txt" \
        "http-post-form://${HERALDING_IP}/:username=^USER^&password=^PASS^:F=Invalid" \
        2>/dev/null || true
    # 수동 curl 추가
    local n=$(rand_int 5 15)
    for i in $(seq 1 $n); do
        local pass
        pass=$(rand_pick "${PASS_POOL[@]}")
        curl -s --max-time 3 -X POST "http://${HERALDING_IP}/" \
            -d "username=${user}&password=${pass}" -o /dev/null 2>/dev/null || true
    done
    rm -f "$wl"
}

tactic_mysql_brute() {
    local user
    user=$(rand_pick "root" "admin" "mysql" "dba" "dbuser")
    local wl
    wl=$(_make_wordlist "$(rand_int 15 35)")
    hydra -l "$user" -P "$wl" -t 4 -f \
        mysql://${HERALDING_IP}:3306 2>/dev/null || true
    rm -f "$wl"
}

tactic_ftp_brute() {
    local target
    target=$(rand_pick "$OPENCANARY_IP" "$DIONAEA_IP")
    local user
    user=$(rand_pick "${USER_POOL[@]}")
    local wl
    wl=$(_make_wordlist "$(rand_int 15 30)")
    hydra -l "$user" -P "$wl" -t 4 -f \
        -o "/honeypot_logs/hydra_ftp_$$.txt" \
        ftp://${target} 2>/dev/null || true
    rm -f "$wl"
}

tactic_rdp_brute() {
    local user
    user=$(rand_pick "administrator" "admin" "user" "guest" "rdpuser")
    local wl
    wl=$(_make_wordlist "$(rand_int 15 30)")
    hydra -l "$user" -P "$wl" -t 4 \
        -o "/honeypot_logs/hydra_rdp_$$.txt" \
        rdp://${OPENCANARY_IP} 2>/dev/null || true
    rm -f "$wl"
}

tactic_mssql_brute() {
    local user
    user=$(rand_pick "sa" "admin" "dbo" "mssql")
    local wl
    wl=$(_make_wordlist "$(rand_int 15 30)")
    hydra -l "$user" -P "$wl" -t 4 \
        mssql://${DIONAEA_IP} 2>/dev/null || true
    rm -f "$wl"
}

tactic_smtp_brute() {
    local user
    user=$(rand_pick "admin" "mail" "postmaster" "root" "support")
    local wl
    wl=$(_make_wordlist "$(rand_int 20 40)")
    hydra -l "$user" -P "$wl" -t 4 -f \
        -o "/honeypot_logs/hydra_smtp_$$.txt" \
        smtp://${MAILONEY_IP}:25 2>/dev/null || true
    rm -f "$wl"
}

tactic_credential_spray() {
    # 여러 서비스에 동일 자격증명 뿌리기 (credential spraying)
    local user
    user=$(rand_pick "${USER_POOL[@]}")
    local pass
    pass=$(rand_pick "${PASS_POOL[@]}")
    local services=(
        "ssh://${COWRIE_IP}:2222"
        "ftp://${OPENCANARY_IP}"
        "ftp://${DIONAEA_IP}"
        "mysql://${HERALDING_IP}:3306"
    )
    local n=$(rand_int 2 4)
    for svc in $(printf '%s\n' "${services[@]}" | shuf | head -n $n); do
        hydra -l "$user" -p "$pass" -t 2 "$svc" 2>/dev/null || true
    done
}
