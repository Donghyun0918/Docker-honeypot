FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    hydra \
    netcat-traditional \
    sqlmap \
    curl \
    wget \
    python3 \
    python3-pip \
    python3-pymysql \
    openssh-client \
    sshpass \
    smbclient \
    ftp \
    telnet \
    iputils-ping \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# rockyou.txt 생성 (상위 1000개 공통 패스워드)
RUN mkdir -p /usr/share/wordlists && \
    printf '%s\n' \
      password 123456 12345678 qwerty abc123 monkey 1234567 \
      letmein trustno1 dragon baseball iloveyou master sunshine \
      ashley bailey passw0rd shadow 123123 654321 superman \
      qazwsx michael football password1 196812 computer \
      admin root toor test pass 1234 12345 123456789 \
      password123 admin123 root123 qwerty123 iloveyou1 \
      princess starwars welcome login hello google \
      charlie donald password2 qwerty1 abc1234 \
      1q2w3e4r 1qaz2wsx zxcvbnm asdfgh \
      raspberry pi ubuntu debian kali \
      changeme default system oracle mysql postgres \
      operator support guest user demo \
      secret secure access network server \
    > /usr/share/wordlists/rockyou.txt

WORKDIR /attack_scenarios

CMD ["/bin/bash"]
