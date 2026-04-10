# Docker Honeypot Lab — 프로젝트 정리

## 개요

Docker 기반 허니팟 7종 + Kali 공격자 컨테이너로 구성한 **완전 격리형 사이버 공격 시뮬레이션 랩**.  
9종 공격 시나리오를 자동 반복 실행하여 허니팟 로그를 수집하고, ML 학습용 단일 CSV 데이터셋으로 변환한다.

---

## 시스템 구성

### 네트워크

```
honeypot-net: 172.30.0.0/24 (Docker bridge, 외부 차단)

cowrie      172.30.0.10   SSH(2222) / Telnet(2223)
heralding   172.30.0.11   HTTP(80) / MySQL(3306)
opencanary  172.30.0.12   FTP(21) / RDP(3389) / VNC(5900)
snare       172.30.0.13   HTTP(8080)
tanner      172.30.0.17   SNARE 분석 서버
dionaea     172.30.0.14   SMB(445) / FTP(21) / MSSQL(1433)
mailoney    172.30.0.15   SMTP(25)
conpot      172.30.0.16   Modbus(502) / S7(102) / SNMP(161)
kali        172.30.0.20   공격자 컨테이너
```

### 허니팟 역할

| 허니팟 | 수집 내용 | 로그 |
|--------|----------|------|
| cowrie | SSH/Telnet 브루트포스, 실행 명령어, 리버스 셸, 파일 다운로드 | JSON |
| heralding | HTTP Basic Auth, MySQL 인증 시도 | CSV |
| opencanary | 포트스캔, FTP/RDP/VNC 접근 | JSON |
| snare | SQLi, XSS, LFI, 웹 공격 경로 | Text |
| dionaea | SMB/FTP/MSSQL 연결 이벤트 | Text (dionaea.log) |
| mailoney | SMTP AUTH 브루트포스, 스팸 | JSON |
| conpot | ICS/SCADA 프로토콜 (Modbus, S7comm, SNMP) | JSON |

---

## 공격 시나리오

총 9종, 각 시나리오는 **전술 라이브러리에서 랜덤 샘플링**하여 실행마다 다른 패턴 생성.

| # | 시나리오 | 레이블 | 핵심 전술 |
|---|---------|--------|----------|
| 01 | 정상 트래픽 | Etc | HTTP GET, SSH 연결, Modbus 정상 읽기 |
| 02 | 포트 스캔 | Recon | nmap 다양한 스캔 모드, UDP, SYN 등 |
| 03 | 브루트포스 | Brute Force | SSH/Telnet/HTTP/MySQL/FTP/SMTP hydra·pymysql |
| 04 | 웹 공격 | Intrusion | SQLi, XSS, LFI, RFI, 명령어 인젝션 |
| 05 | 침투 후 정찰 | Intrusion | 권한상승, 파일 열람, persistence |
| 06 | 리버스 셸 | Intrusion | nc, python, perl, php, ruby, bash /dev/tcp |
| 07 | 악성코드 업로드 | Malware | wget/curl C2 다운로드, FTP 업로드 |
| 08 | 자격증명 스터핑 | Brute Force | 다중 서비스 동일 자격증명 시도 |
| 09 | ICS 공격 | Recon | Modbus 레지스터 읽기/쓰기, S7 통신, BACnet |

**랜덤화 풀 규모:**
- 유저명 50+, 패스워드 60+, SQLi 13종, XSS 10종, LFI 10종, 리버스셸 7종, C2 URL 7종

---

## 데이터셋

### 현재 수집 현황

| 항목 | 값 |
|------|---|
| 총 행 수 | **30,966행** |
| 컬럼 수 | 15개 (레이블 없음) |
| 수집 기간 | 약 40회 × 9종 시나리오 |

### 허니팟별 분포

| source_honeypot | 행 수 | 비율 |
|----------------|------|------|
| snare | 20,949 | 67.7% |
| cowrie | 4,668 | 15.1% |
| opencanary | 2,020 | 6.5% |
| conpot | 1,380 | 4.5% |
| dionaea | 1,281 | 4.1% |
| mailoney | 576 | 1.9% |
| heralding | 92 | 0.3% |

### event_type 분포

| event_type | 행 수 |
|-----------|------|
| command | 21,108 |
| auth | 4,366 |
| session | 3,472 |
| scan | 2,020 |

### protocol 분포 (대문자 정규화)

```
HTTP: 21,252   SSH: 4,668    FTP: 1,577    MODBUS: 982
RDP: 604       SMTP: 576     MSSQL: 533    S7COMM: 398
UNKNOWN: 179   PORTSCAN: 84  MYSQL: 60     SMB: 53
```

### 컬럼 스키마

```
timestamp         ISO 8601 UTC
src_ip            공격자 IP
dst_port          대상 포트
protocol          대문자 정규화 (HTTP, SSH, MYSQL, RDP ...)
source_honeypot   7종 허니팟 중 하나
event_type        auth / session / command / scan
username          인증 시도 사용자명
password          인증 시도 패스워드
login_success     0 / 1
duration          세션 길이(초)
login_attempts    세션 내 로그인 시도 수
command           실행 명령어 또는 HTTP 경로
has_wget          0 / 1
has_curl          0 / 1
has_reverse_shell 0 / 1
```

---

## 핵심 파일

```
attack_scenarios/lib/common.sh       IP 상수, 랜덤화 풀, 유틸 함수
attack_scenarios/lib/tactics_*.sh   전술 함수 라이브러리 (6종)
attack_scenarios/01~09_*.sh         시나리오 실행 스크립트
scripts/run_loop.sh                 N회 반복 수집 루프
scripts/parse_logs.py               7종 로그 → dataset.csv 파서
scripts/label_data.py               선택적 레이블 추가
```

---

## 실행 명령어

```bash
# 시나리오 1회 실행
docker exec -it kali-attacker bash /scripts/run_scenarios.sh

# 대량 수집 (40회 반복, 시나리오 사이 5초 대기)
docker exec -it kali-attacker bash /scripts/run_loop.sh 40 5

# 로그 파싱 → dataset.csv
docker exec kali-attacker python3 /scripts/parse_logs.py

# 레이블 추가 (선택)
docker exec kali-attacker python3 /scripts/label_data.py
```

---

## 트러블슈팅 기록

### WSL2 bind mount 끊김

**증상:** kali-attacker의 `/honeypot_logs`가 `D:\` 9p가 아닌 `/dev/sdf` ext4로 마운트됨  
**원인:** 컨테이너 재생성 시 Docker Desktop이 WSL2 9p 마운트 수립 실패  
**해결:**
```powershell
wsl --shutdown          # WSL2 완전 종료
docker compose up -d    # 컨테이너 재시작 (자동 마운트 재수립)
```
**추가 조치:** kali 볼륨 경로를 `/mnt/d/honeypot_logs` → `D:/honeypot_logs`로 변경

### heralding 로그 미수집

**원인 1:** `heralding.yml`이 구버전 `options:` 형식을 사용 → heralding 1.0.7이 무시함  
**해결:** `activity_logging.file` 형식으로 재작성, 절대 경로 지정

**원인 2:** heralding의 `/var/log/heralding` bind mount가 항상 ext4로 fallback  
**해결:** Docker named volume `heralding_logs` 사용, kali에서도 같은 볼륨 마운트

### heralding HTTP 로그 미수집

**원인:** `tactic_http_brute`가 POST 방식 사용 → heralding은 HTTP Basic Auth만 지원  
**해결:** `curl -u user:pass http://...` 방식으로 변경

### heralding MySQL 로그 미수집

**원인:** hydra가 MySQL에 COM_QUIT만 전송하고 자격증명 교환 없이 종료  
**해결:** pymysql을 직접 사용하는 Python 스크립트로 교체

### dionaea 로그 미수집

**원인:** parse_logs.py가 SQLite(`logsql.sqlite`)를 찾았으나 실제로는 텍스트 로그(`dionaea.log`)만 생성됨  
**해결:** `dionaea.log` 텍스트 파서 추가
```
파싱 패턴: accepted connection from <IP>:<port> to <IP>:<port>
날짜 형식: [DDMMYYYY HH:MM:SS]
```

### protocol 대소문자 불일치

**원인:** heralding → `mysql`(소문자), dionaea → `MySQL`(혼합) 반환  
**해결:** `make_row()`에서 `protocol.upper()` 정규화, opencanary logtype `14001` → `RDP` 매핑 추가
