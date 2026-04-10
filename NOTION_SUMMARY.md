# Docker Honeypot Lab — 프로젝트 정리

## 개요

Docker 기반 허니팟 7종 + Kali 공격자 컨테이너로 구성한 **완전 격리형 사이버 공격 시뮬레이션 랩**.
9종 공격 시나리오를 자동 반복 실행하여 허니팟 로그를 수집하고, 원시 로그 CSV와 ML 학습용 CSV 두 단계로 변환한다.

---

## 시스템 구성

### 네트워크

```
honeypot-net: 172.30.0.0/24 (Docker bridge, 외부 차단)

cowrie      172.30.0.10   SSH(2222) / Telnet(2223)
heralding   172.30.0.11   HTTP(80) / MySQL(3306)
opencanary  172.30.0.12   FTP(21) / RDP(3389) / VNC(5900)
snare       172.30.0.13   HTTP(8080)
tanner      172.30.0.17   SNARE 분석 서버 스텁
dionaea     172.30.0.14   SMB(445) / FTP(21) / MSSQL(1433)
mailoney    172.30.0.15   SMTP(25)
conpot      172.30.0.16   Modbus(502) / S7(102) / SNMP(161)
kali        172.30.0.20   공격자 컨테이너
```

### 허니팟 역할

| 허니팟 | 수집 내용 | 로그 포맷 |
|--------|----------|----------|
| cowrie | SSH/Telnet 브루트포스, 명령어 실행, 리버스 셸, 파일 다운로드 | JSON |
| heralding | HTTP Basic Auth, MySQL 인증 시도 | CSV |
| opencanary | 포트스캔, FTP/RDP/VNC 접근 탐지 | JSON |
| snare | SQLi, XSS, LFI, 웹 공격 경로 | Text |
| dionaea | SMB/FTP/MSSQL 연결 이벤트 | Text (dionaea.log) |
| mailoney | SMTP AUTH 브루트포스, 스팸 | JSON |
| conpot | ICS/SCADA 프로토콜 (Modbus, S7comm, SNMP) | JSON |

---

## 공격 시나리오

총 9종. 각 시나리오는 **전술 라이브러리에서 랜덤 샘플링**하여 실행마다 다른 패턴 생성.

| # | 시나리오 | ML 레이블 | 핵심 전술 |
|---|---------|----------|----------|
| 01 | 정상 트래픽 | Etc | HTTP GET, SSH 연결, Modbus 정상 읽기 |
| 02 | 포트 스캔 | Recon | nmap 다양한 스캔 모드, UDP, SYN 등 |
| 03 | 브루트포스 | Brute Force | SSH/Telnet/HTTP/MySQL/FTP/SMTP — hydra·pymysql |
| 04 | 웹 공격 | Intrusion | SQLi, XSS, LFI, RFI, 명령어 인젝션 |
| 05 | 침투 후 정찰 | Intrusion | 권한상승, 파일 열람, persistence |
| 06 | 리버스 셸 | Intrusion | nc, python, perl, php, ruby, bash /dev/tcp |
| 07 | 악성코드 업로드 | Malware | wget/curl C2 다운로드, FTP 업로드 |
| 08 | 자격증명 스터핑 | Brute Force | 다중 서비스 동일 자격증명 시도 |
| 09 | ICS 공격 | Recon | Modbus 레지스터 읽기/쓰기, S7 통신, BACnet |

**랜덤화 풀 규모:** 유저명 50+, 패스워드 60+, SQLi 13종, XSS 10종, LFI 10종, 리버스셸 7종, C2 URL 7종

---

## 데이터 파이프라인

```
허니팟 로그 (7종)
    │
    ▼  parse_logs.py  (parser v3.0)
dataset.csv          ← 원시 로그, 27컬럼, 이벤트 1개 = 행 1개
    │
    ▼  feature_engineering.py
dataset_ml.csv       ← ML 학습용, 17컬럼, 수치형 + is_attack 타겟
```

---

## 원시 로그: dataset.csv

### 수집 현황

| 항목 | 값 |
|------|---|
| 총 행 수 | **30,966행** |
| 컬럼 수 | **27개** |
| 파서 버전 | v3.0 |
| 수집 | 약 40회 × 9종 시나리오 |

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

### event_result 분포

| event_result | 의미 | 행 수 |
|-------------|------|------|
| executed | 명령 실행됨 | 21,108 |
| fail | 인증 실패 | 4,241 |
| closed | 세션 종료 | 3,472 |
| detected | 스캔 탐지 | 2,020 |
| success | 인증 성공 | 125 |

### protocol 분포

| protocol | 행 수 |
|---------|------|
| HTTP | 21,252 |
| SSH | 4,668 |
| FTP | 1,577 |
| MODBUS | 982 |
| RDP | 604 |
| SMTP | 576 |
| MSSQL | 533 |
| S7COMM | 398 |
| UNKNOWN | 179 |
| PORTSCAN | 84 |
| MYSQL | 60 |
| SMB | 53 |

### 컬럼 스키마 (27컬럼)

**[식별]**

| 컬럼 | 설명 |
|------|------|
| `event_id` | UUID v4 — 행별 고유 식별자 |
| `session_id` | 세션 식별자 (cowrie/heralding: native ID / 그 외: src_ip+port+ts MD5 앞 12자) |

**[시각]**

| 컬럼 | 설명 |
|------|------|
| `timestamp` | ISO 8601 UTC — 이벤트 발생 시각 |
| `ingest_time` | ISO 8601 UTC — 파싱 실행 시각 |

**[네트워크 5-튜플]**

| 컬럼 | 설명 |
|------|------|
| `src_ip` | 공격자 IP |
| `src_port` | 공격자 출발 포트 (cowrie, heralding, dionaea에서 수집) |
| `dst_ip` | 허니팟 IP (허니팟별 고정값) |
| `dst_port` | 허니팟 대상 포트 |
| `transport` | TCP / UDP (protocol에서 자동 결정) |

**[서비스]**

| 컬럼 | 설명 |
|------|------|
| `protocol` | SSH / HTTP / FTP / SMTP / MYSQL / RDP / SMB / MSSQL / MODBUS / S7COMM / SNMP / PORTSCAN 등 (대문자 정규화) |
| `source_honeypot` | cowrie / heralding / opencanary / snare / dionaea / mailoney / conpot |
| `event_type` | auth / session / command / scan |
| `event_result` | auth: **success/fail** · session: **closed** · command: **executed** · scan: **detected** |

**[인증]**

| 컬럼 | 설명 |
|------|------|
| `username` | 인증 시도 사용자명 |
| `password` | 인증 시도 패스워드 |
| `login_success` | 0 / 1 |
| `attempt_no` | 세션 내 인증 시도 순번 (1, 2, 3 ...) |

**[세션]**

| 컬럼 | 설명 |
|------|------|
| `duration` | 세션 길이 (초) |
| `login_attempts` | 세션 내 총 로그인 시도 수 |

**[HTTP 세부]**

| 컬럼 | 설명 |
|------|------|
| `http_method` | GET / POST / PUT / DELETE / HEAD / OPTIONS / PATCH |
| `http_path` | URL 경로 (`/login`, `/admin` ...) |
| `http_query` | 쿼리 문자열 원문 — SQLi/XSS/LFI 페이로드 그대로 보존 |

**[명령]**

| 컬럼 | 설명 |
|------|------|
| `command` | 실행 명령어 또는 HTTP 전체 원본 문자열 (raw) |
| `has_wget` | 0 / 1 |
| `has_curl` | 0 / 1 |
| `has_reverse_shell` | 0 / 1 |

**[메타]**

| 컬럼 | 설명 |
|------|------|
| `parser_version` | 파서 버전 (현재 `3.0`) — 규칙 변경 시 재현성 추적 |

---

## ML 학습용: dataset_ml.csv

`dataset.csv`를 수치형으로 변환한 ML 학습 전용 파일.

### 스펙

| 항목 | 값 |
|------|---|
| 행 수 | 30,966행 |
| 컬럼 수 | 17개 |
| 타겟 | `is_attack` (0=정상 / 1=공격) |
| is_attack=1 (공격) | 4,363건 (14.1%) |
| is_attack=0 (정상) | 26,603건 (85.9%) |

> 클래스 불균형(14:86) → 학습 시 `class_weight='balanced'` 또는 SMOTE 적용 권장

### 변환 내용

| 작업 | 상세 |
|------|------|
| **제거** | `event_id`, `session_id`, `ingest_time` (메타) / `src_ip`, `src_port`, `dst_ip`, `transport` (과적합·중복) / `timestamp`, `username`, `password`, `command` (raw 텍스트) |
| **시간 피처** | `hour` (0~23), `is_night` (22:00~06:00 → 1), `day_of_week` (0=월~6=일) |
| **커맨드 피처** | `cmd_length`, `special_char_cnt` (`\|;&><$` 등), `pipe_count` |
| **결측 처리** | `duration` / `login_attempts` / `login_success` → 0 |
| **인코딩** | `protocol` / `source_honeypot` / `event_type` → Label Encoding |
| **타겟** | rule-based `is_attack` 생성 |

### is_attack 판정 규칙

| 조건 | is_attack |
|------|-----------|
| has_reverse_shell = 1 | 1 |
| event_type = command + (has_wget=1 또는 has_curl=1) | 1 |
| snare + SQLi/XSS/LFI/RFI/명령어 인젝션 패턴 탐지 | 1 |
| event_type = scan 또는 protocol = PORTSCAN | 1 |
| source_honeypot = conpot | 1 |
| protocol = SMTP | 1 |
| login_attempts ≥ 10 | 1 |
| 그 외 (시나리오 01 정상 트래픽) | 0 |

### 컬럼 목록

| # | 컬럼 | 설명 |
|---|------|------|
| 0 | hour | 접속 시각 (0~23) |
| 1 | is_night | 야간 여부 |
| 2 | day_of_week | 요일 |
| 3 | dst_port | 대상 포트 |
| 4 | protocol | 프로토콜 (Label Encoded) |
| 5 | source_honeypot | 허니팟 종류 (Label Encoded) |
| 6 | event_type | 이벤트 유형 (Label Encoded) |
| 7 | login_success | 로그인 성공 여부 |
| 8 | duration | 세션 길이(초) |
| 9 | login_attempts | 로그인 시도 횟수 |
| 10 | cmd_length | 명령어 길이 |
| 11 | special_char_cnt | 특수문자 개수 |
| 12 | pipe_count | 파이프 개수 |
| 13 | has_wget | wget 포함 여부 |
| 14 | has_curl | curl 포함 여부 |
| 15 | has_reverse_shell | 리버스 셸 여부 |
| 16 | **is_attack** | **타겟 (0=정상 / 1=공격)** |

인코딩 맵은 `dataset_ml_encoders.json`에 저장.

---

## 핵심 파일

```
attack_scenarios/
├── lib/common.sh            IP 상수, 랜덤화 풀 (유저 50+, 패스워드 60+, 페이로드 다수)
├── lib/tactics_normal.sh    정상 트래픽 전술 8종
├── lib/tactics_recon.sh     정찰 전술 12종
├── lib/tactics_brute.sh     브루트포스 전술 11종
├── lib/tactics_intrusion.sh 침투 전술 9종
├── lib/tactics_malware.sh   악성코드 전술 8종
├── lib/tactics_ics.sh       ICS/SCADA 전술 8종
└── 01~09_*.sh               시나리오 실행 스크립트

scripts/
├── run_scenarios.sh         9종 시나리오 1회 순차 실행
├── run_loop.sh              N회 반복 수집 루프
├── parse_logs.py            7종 로그 → dataset.csv (원시, 27컬럼, v3.0)
├── feature_engineering.py  dataset.csv → dataset_ml.csv (ML 전처리)
└── label_data.py            타임스탬프 + rule-based 레이블링 (선택)
```

---

## 실행 명령어

```bash
# 시나리오 1회 실행 (9종 순차)
docker exec -it kali-attacker bash /scripts/run_scenarios.sh

# 대량 수집 (40회 반복, 시나리오 사이 5초 대기)
docker exec -it kali-attacker bash /scripts/run_loop.sh 40 5

# 원시 로그 파싱 → dataset.csv (27컬럼)
docker exec kali-attacker python3 /scripts/parse_logs.py

# ML 전처리 → dataset_ml.csv (17컬럼)
docker exec kali-attacker python3 /scripts/feature_engineering.py

# 레이블 추가 (선택)
docker exec kali-attacker python3 /scripts/label_data.py
```

---

## 트러블슈팅 기록

### WSL2 bind mount 끊김

**증상:** kali-attacker의 `/honeypot_logs`가 `/dev/sdf` ext4로 마운트됨 (9p 아님)  
**원인:** 컨테이너 재생성 시 Docker Desktop이 WSL2 9p 마운트 수립 실패  
**해결:**
```powershell
wsl --shutdown        # WSL2 완전 종료
docker compose up -d  # 컨테이너 재시작 (마운트 재수립)
```
**추가 조치:** kali 볼륨 경로를 `/mnt/d/honeypot_logs` → `D:/honeypot_logs` (Windows 경로 형식)로 변경

---

### heralding 로그 미수집

**원인 1:** `heralding.yml`이 구버전 `options:` 형식 → heralding 1.0.7이 무시  
**해결:** `activity_logging.file` 형식으로 재작성, 절대 경로 지정

**원인 2:** `/var/log/heralding` bind mount가 ext4로 fallback  
**해결:** Docker named volume `heralding_logs` 사용, kali에서 별도 경로(`/heralding_logs`)로 마운트

---

### heralding HTTP / MySQL 로그 미수집

| 원인 | 해결 |
|------|------|
| HTTP: `tactic_http_brute`가 POST 방식 → heralding은 Basic Auth만 지원 | `curl -u user:pass http://...` 방식으로 변경 |
| MySQL: hydra가 COM_QUIT만 전송, 자격증명 교환 없이 종료 | pymysql 직접 사용 Python 스크립트로 교체 |

pymysql 설치: `python3-pymysql`을 kali Dockerfile에 추가 (honeypot 네트워크에서 pip 불가)

---

### dionaea 로그 미수집

**원인:** parse_logs.py가 SQLite(`logsql.sqlite`)를 기대했으나 실제로는 텍스트 로그만 생성  
**해결:** `dionaea.log` 텍스트 파서 추가
```
파싱 패턴: accepted connection from <IP>:<PORT> to <IP>:<PORT>
날짜 형식: [DDMMYYYY HH:MM:SS]
```

---

### protocol 대소문자 불일치

**원인:** heralding → `mysql`(소문자), dionaea → `MySQL`(혼합) 반환  
**해결:** `make_row()`에서 `protocol.upper()` 정규화 / opencanary logtype `14001` → `RDP` 매핑 추가
