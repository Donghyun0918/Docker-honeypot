# Docker Honeypot Lab — 프로젝트 정리

## 프로젝트 개요

Windows 11 로컬 PC (Ryzen 7 7735HS, RAM 32GB) 에서 Docker Desktop + WSL2 기반으로 허니팟 7종을 컨테이너로 구축하고, Kali Linux 공격자 컨테이너로 6종의 공격 시나리오를 실행하여 ML 학습용 레이블된 공격 로그 데이터셋(CSV)을 수집한다.

---

## 환경 정보

| 항목 | 내용 |
|------|------|
| OS | Windows 11 Home |
| CPU | Ryzen 7 7735HS |
| RAM | 32GB |
| 런타임 | Docker Desktop + WSL2 |
| 프로젝트 경로 | `D:\docker_honeypot` (WSL2: `/mnt/d/docker_honeypot`) |
| 로그 경로 | `D:\honeypot_logs` (WSL2: `/mnt/d/honeypot_logs`) |

---

## 네트워크 구성

- 브릿지 네트워크: `honeypot-net` (subnet: `172.30.0.0/24`)
- 모든 컨테이너가 동일 네트워크에서 상호 통신
- 공격 스크립트는 항상 **내부 IP:내부 포트** 기준으로 동작

---

## 컨테이너 구성 (8종)

### 허니팟 7종

| 컨테이너 | 이미지 | 내부 IP | 호스트 포트 | 수집 공격 | 로그 포맷 |
|----------|--------|---------|------------|----------|-----------|
| cowrie | `cowrie/cowrie:latest` | 172.30.0.10 | 2222, 2223 | SSH/Telnet 브루트포스, 명령어, 리버스 셸 | JSON |
| heralding | 커스텀 빌드 | 172.30.0.11 | 8880, 33306 | HTTP/MySQL 인증 시도 | CSV |
| opencanary | 커스텀 빌드 | 172.30.0.12 | 2121, 33389, 55900 | 포트스캔, RDP, VNC, FTP | JSON |
| snare | 커스텀 빌드 | 172.30.0.13 | 8080 | SQLi, XSS, LFI, 디렉터리 트래버설 | JSON |
| dionaea | `dinotools/dionaea:latest` | 172.30.0.14 | 4445, 4421, 14433 | SMB 익스플로잇, 멀웨어 페이로드 | SQLite |
| mailoney | 커스텀 구현 (Python asyncio) | 172.30.0.15 | 2525 | SMTP 스팸, AUTH 시도 | JSON |
| conpot | 커스텀 구현 (Python asyncio) | 172.30.0.16 | 10102, 5502, 16100/udp | ICS/SCADA Modbus, S7comm, SNMP | JSON |

### 공격자 컨테이너

| 컨테이너 | 베이스 | 내부 IP | 설치 도구 |
|----------|--------|---------|-----------|
| kali-attacker | `debian:bookworm-slim` | 172.30.0.20 | nmap, hydra, netcat, sqlmap, curl, wget, sshpass, smbclient |

---

## 디렉터리 구조

```
D:\docker_honeypot\
├── docker-compose.yml              # 8개 컨테이너 오케스트레이션
├── .env                            # IP/서브넷 환경변수
├── PROJECT_SUMMARY.md              # 이 파일
│
├── honeypots\
│   ├── cowrie\
│   │   ├── cowrie.cfg              # log_path=/tmp/cowrie_logs, jsonlog 활성화
│   │   └── userdb.txt              # root:*, admin:admin, pi:raspberry 등
│   ├── heralding\
│   │   ├── Dockerfile              # psycopg2-binary + pip install --no-deps heralding
│   │   └── heralding.yml          # HTTP/MySQL 활성화, CSV 로그 경로 설정
│   ├── opencanary\
│   │   ├── Dockerfile              # pip install opencanary
│   │   └── opencanary.conf        # FTP/RDP/VNC 활성화, logging.FileHandler
│   ├── snare\
│   │   └── Dockerfile              # GitHub 클론 + pip install, --host-ip 옵션 사용
│   ├── dionaea\
│   │   └── dionaea.cfg            # SMB/FTP/MSSQL 모듈 설정
│   ├── mailoney\
│   │   ├── Dockerfile              # python:3.11-slim
│   │   └── honeypot.py            # 직접 구현한 SMTP 허니팟 (asyncio)
│   └── conpot\
│       ├── Dockerfile              # python:3.11-slim
│       └── honeypot.py            # 직접 구현한 ICS 허니팟 (Modbus/S7/SNMP)
│
├── kali\
│   └── Dockerfile                  # debian:bookworm-slim + 공격 도구 + 미니 wordlist
│
├── attack_scenarios\
│   ├── 01_normal_traffic.sh        # 정상 트래픽 (curl/wget/nc) → label: Etc
│   ├── 02_port_scan.sh             # 포트스캔 (nmap) → label: Recon
│   ├── 03_brute_force.sh           # 브루트포스 (hydra SSH/HTTP/MySQL) → label: Brute Force
│   ├── 04_web_attacks.sh           # 웹 공격 (sqlmap/curl) → label: Intrusion
│   ├── 05_post_intrusion.sh        # 침투 후 명령어 (sshpass + ssh) → label: Intrusion
│   └── 06_reverse_shell.sh         # 리버스 셸 (nc/python3) → label: Intrusion
│
└── scripts\
    ├── run_scenarios.sh            # 6종 시나리오 순서 실행 + 타임스탬프 기록
    ├── parse_logs.py               # 7종 로그 포맷 파싱 → 3개 CSV
    └── label_data.py               # 타임스탬프 + rule-based 레이블링

D:\honeypot_logs\                   # 로그 저장소 (컨테이너 bind mount)
├── cowrie\
│   └── cowrie.json                 # Cowrie SSH/Telnet 로그 (JSON Lines)
├── heralding\
│   ├── auth.csv                    # Heralding 인증 로그
│   └── session.csv                 # Heralding 세션 로그
├── opencanary\
│   └── opencanary.log              # OpenCanary 이벤트 로그
├── snare\                          # SNARE 웹 공격 로그
├── dionaea\
│   └── logsql.sqlite               # Dionaea SQLite DB
├── mailoney\                       # Mailoney SMTP 로그
├── conpot\
│   └── conpot.json                 # Conpot ICS/SCADA 로그 (JSON Lines)
├── scenario_times.json             # 시나리오별 시작/종료 타임스탬프
├── auth.csv                        # 최종 데이터셋: 인증 시도
├── sessions.csv                    # 최종 데이터셋: 세션 정보
└── input.csv                       # 최종 데이터셋: 명령어/페이로드
```

---

## 출력 데이터셋 (3개 CSV)

| 파일 | 행 수 | 주요 피처 |
|------|-------|-----------|
| `auth.csv` | 16행 | timestamp, src_ip, dst_port, protocol, username, password, login_success, source_honeypot, label |
| `sessions.csv` | 35행 | timestamp, src_ip, dst_port, protocol, duration, login_attempts, login_success, source_honeypot, label |
| `input.csv` | 52행 | timestamp, src_ip, dst_port, protocol, command, has_wget, has_curl, has_reverse_shell, source_honeypot, label |

### 레이블 분포

| 레이블 | auth | sessions | input |
|--------|------|----------|-------|
| Etc | 3 | 3 | 6 |
| Recon | 0 | 16 | 0 |
| Brute Force | 8 | 10 | 0 |
| Intrusion | 5 | 6 | 44 |
| Malware | 0 | 0 | 2 |
| **합계** | **16** | **35** | **52** |

---

## 레이블링 방식

### 1차: 타임스탬프 기반
- `run_scenarios.sh` 실행 시 각 시나리오의 시작/종료 시각을 `scenario_times.json`에 기록
- 각 로그 이벤트의 타임스탬프가 어느 시나리오 윈도우에 속하는지 매칭

### 2차: Rule-based 보완

| 조건 | 레이블 |
|------|--------|
| `has_reverse_shell == 1` | Intrusion |
| `has_wget == 1` OR `has_curl == 1` | Malware |
| `login_attempts >= 10` | Brute Force |
| `protocol == PORTSCAN` | Recon |
| `protocol == SMTP` | Brute Force |
| `source_honeypot == conpot` | Recon |
| 매칭 없음 | Etc |

---

## ML 타겟 클래스

| 클래스 | 설명 | 해당 시나리오 |
|--------|------|---------------|
| **Etc** | 정상 트래픽 | 01_normal_traffic |
| **Recon** | 포트스캔 / 정찰 | 02_port_scan |
| **Brute Force** | 무차별 대입 | 03_brute_force |
| **Intrusion** | 침투 / 리버스 셸 | 04_web_attacks, 05_post_intrusion, 06_reverse_shell |
| **Malware** | 악성코드 다운로드/실행 | rule-based 자동 분류 (has_wget/has_curl) |

---

## 실행 명령어

```bash
# 컨테이너 상태 확인
cd /mnt/d/docker_honeypot
docker compose ps

# 공격 시나리오 실행 (Kali 컨테이너 내부)
docker exec -it kali-attacker bash
bash /scripts/run_scenarios.sh

# 데이터셋 생성 (반드시 docker exec로 실행)
docker exec kali-attacker bash -c "python3 /scripts/parse_logs.py && python3 /scripts/label_data.py"

# 결과 확인
wc -l /mnt/d/honeypot_logs/*.csv
```

> **주의:** `parse_logs.py`와 `label_data.py`는 반드시 `docker exec kali-attacker bash -c "..."` 형태로 실행해야 한다.
> WSL2 직접 실행 시 `/honeypot_logs/` 경로를 인식하지 못해 빈 CSV가 생성된다.

---

## 트러블슈팅 기록

| 문제 | 원인 | 해결 |
|------|------|------|
| `opencanary/opencanary` 이미지 없음 | Docker Hub에 없는 이름 | `pip install opencanary` 커스텀 빌드 |
| `mushorg/heralding` 이미지 없음 | Docker Hub에 없는 이름 | `pip install heralding` 커스텀 빌드 |
| `mushorg/conpot` 이미지 없음 | Docker Hub에 없는 이름 | Python asyncio로 직접 구현 |
| heralding `psycopg2` 빌드 실패 | pg_config 없음 | `psycopg2-binary` 먼저 설치 후 `--no-deps` |
| conpot Python 버전 오류 | GitHub HEAD가 `>=3.12` 요구 | Python asyncio 직접 구현으로 대체 |
| Kali apt exit code 100 | `metasploit-framework`, `wordlists` 패키지 문제 | 제거 후 `debian:bookworm-slim` 베이스로 변경 |
| mailoney `ModuleNotFoundError` | 저장소 구조 변경으로 import 경로 깨짐 | Python asyncio SMTP 허니팟으로 직접 구현 |
| OpenCanary 설정 파일 못 찾음 | `/.opencanary.conf` 경로 불일치 | `/root/.opencanary.conf`에 복사 |
| OpenCanary `RotatingFileHandler` 오류 | Docker 환경에서 rotating 불가 | `logging.FileHandler`로 변경 |
| SNARE `--log-path` 옵션 없음 | CLI 인수 변경됨 | `--log-path` 제거, `--host` → `--host-ip` 수정 |
| 볼륨 경로 오류 `D:\honeypot_logs` | WSL2에서 Windows 경로 형식 불가 | `/mnt/d/honeypot_logs` 로 변경 |
| Docker 자격증명 오류 | `credsStore: desktop.exe` WSL2 미지원 | `~/.docker/config.json` → `{}` 초기화 |
| Cowrie `Unknown command: cowrie` | cowrie.cfg 설정 과다로 로드 실패 | 최소 설정(log_path + jsonlog)만 남김 |
| Cowrie 로그 볼륨 충돌 | `/cowrie/cowrie-git/var` 익명 볼륨과 bind mount 충돌 | 로그 경로를 `/tmp/cowrie_logs`로 변경 |
| parse_logs.py 빈 CSV 생성 | WSL2에서 직접 실행 시 `/honeypot_logs/` 경로 미인식 | `docker exec kali-attacker bash -c "..."` 로 실행 |

---

## 현재 상태

- [x] Docker Desktop + WSL2 환경 구성
- [x] docker-compose.yml 작성 (8개 서비스)
- [x] 허니팟 7종 컨테이너 빌드 및 실행
- [x] Kali 공격자 컨테이너 빌드 및 실행
- [x] 공격 시나리오 6종 실행
- [x] parse_logs.py 실행 → auth.csv (16행), sessions.csv (35행), input.csv (52행) 생성
- [x] label_data.py 실행 → 103행 레이블링 완료
- [ ] ML 모델 학습 (랜덤포레스트 / XGBoost)
