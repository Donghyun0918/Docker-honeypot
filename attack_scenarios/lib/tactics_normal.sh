#!/bin/bash
# lib/tactics_normal.sh - 정상 트래픽 전술 함수

tactic_http_browse() {
    local target="$HERALDING_IP"
    local ua
    ua=$(rand_pick "${UA_POOL[@]:0:3}")  # 정상 UA만
    local n=$(rand_int 3 10)
    local paths=("/" "/index.html" "/about" "/contact" "/robots.txt" "/favicon.ico" "/sitemap.xml" "/style.css" "/logo.png")
    for i in $(seq 1 $n); do
        local path
        path=$(rand_pick "${paths[@]}")
        curl -s --max-time 5 -A "$ua" "http://${target}${path}" -o /dev/null 2>/dev/null || true
        rand_sleep 0 1
    done
}

tactic_snare_browse() {
    local ua
    ua=$(rand_pick "${UA_POOL[@]:0:3}")
    local n=$(rand_int 2 6)
    local paths=("/" "/index.html" "/about" "/products" "/contact" "/blog")
    for i in $(seq 1 $n); do
        local path
        path=$(rand_pick "${paths[@]}")
        curl -s --max-time 5 -A "$ua" "http://${SNARE_IP}:8080${path}" -o /dev/null 2>/dev/null || true
        rand_sleep 0 1
    done
}

tactic_ftp_banner_grab() {
    local target
    target=$(rand_pick "$OPENCANARY_IP" "$DIONAEA_IP")
    nc -w 3 "$target" 21 < /dev/null 2>/dev/null || true
    curl -s --max-time 3 "ftp://${target}/" -o /dev/null 2>/dev/null || true
}

tactic_ssh_banner_grab() {
    local n=$(rand_int 2 5)
    for i in $(seq 1 $n); do
        nc -w 3 "$COWRIE_IP" 2222 < /dev/null 2>/dev/null || true
        rand_sleep 0 1
    done
}

tactic_smtp_banner_grab() {
    nc -w 3 "$MAILONEY_IP" 25 < /dev/null 2>/dev/null || true
    echo -e "EHLO test.com\nQUIT" | nc -w 3 "$MAILONEY_IP" 25 2>/dev/null || true
}

tactic_modbus_probe() {
    # 단순 포트 탐색 (정상 장비가 상태 확인하는 것처럼)
    nc -w 2 "$CONPOT_IP" 502 < /dev/null 2>/dev/null || true
    nc -w 2 "$CONPOT_IP" 161 < /dev/null 2>/dev/null || true
}

tactic_generic_port_knock() {
    local target
    target=$(rand_pick "${ALL_HONEYPOT_IPS[@]}")
    local ports=(80 443 22 21 25 3306 5432 8080 8443)
    local n=$(rand_int 2 4)
    for port in $(printf '%s\n' "${ports[@]}" | shuf | head -n $n); do
        nc -w 2 "$target" "$port" < /dev/null 2>/dev/null || true
    done
}

tactic_wget_download() {
    local paths=("/index.html" "/robots.txt" "/favicon.ico")
    local path
    path=$(rand_pick "${paths[@]}")
    wget -q --timeout=5 -O /dev/null "http://${SNARE_IP}:8080${path}" 2>/dev/null || true
    wget -q --timeout=5 -O /dev/null "http://${HERALDING_IP}/" 2>/dev/null || true
}
