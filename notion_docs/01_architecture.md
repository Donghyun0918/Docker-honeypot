# 01. 아키텍처

## 전체 구조

```
┌─────────────────────────────────────────────────────────────┐
│                   HoneyForge Platform                        │
│                                                             │
│  ┌──────────────┐      ┌──────────────────────────────┐    │
│  │  Web Browser │◄────►│  Dashboard (FastAPI + React) │    │
│  └──────────────┘      └──────────────────────────────┘    │
│                                    │ Docker SDK             │
│                         ┌──────────▼─────────────────┐     │
│                         │     Docker Engine           │     │
│                         │                             │     │
│   hp_net_{username}     │  hp_{user}_cowrie           │     │
│   (유저별 독립 네트워크) │  hp_{user}_heralding        │     │
│                         │  hp_{user}_opencanary       │     │
│                         │  hp_{user}_snare            │     │
│                         │  hp_{user}_tanner           │     │
│                         │  hp_{user}_dionaea          │     │
│                         │  hp_{user}_mailoney         │     │
│                         │  hp_{user}_conpot           │     │
│                         │                             │     │
│                         │  kali-attacker (공유)       │     │
│                         └─────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

---

## 허니팟 컨테이너 8종

| 컨테이너 | 이미지 | 프로토콜 | 수집 공격 유형 | 로그 포맷 |
| --- | --- | --- | --- | --- |
| cowrie | `cowrie/cowrie:latest` | SSH(2222), Telnet(2223) | 브루트포스, 명령어 실행, 리버스 셸 | JSON |
| heralding | 커스텀 빌드 | HTTP(80), FTP(21), MySQL(3306), RDP(3389) 등 | 인증 시도, 세션 | CSV |
| opencanary | 커스텀 빌드 | FTP, RDP, VNC, SMB, MSSQL, SNMP 등 | 포트스캔, 서비스 접근 탐지 | JSON |
| snare | 커스텀 빌드 | HTTP(8080) | SQLi, XSS, LFI, 디렉터리 트래버설 | Text/JSON |
| tanner | 커스텀 스텁 | HTTP(8090) | SNARE 분석 서버 | — |
| dionaea | `dinotools/dionaea:latest` | SMB(445), FTP, MSSQL, HTTP | 익스플로잇 시도, 파일 업로드 | Text |
| mailoney | 커스텀 구현 | SMTP(25) | 스팸, AUTH 브루트포스 | JSON |
| conpot | 커스텀 구현 | Modbus(502), S7(102), SNMP(161) | ICS/SCADA 공격, 정찰 | JSON |

---

## 유저별 격리 구조

유저가 가입하면 **전용 Docker 네트워크 + 컨테이너 8종**이 자동 생성된다.

```
회원가입 요청
    │
    ▼
DB User 생성
    │
    ▼
docker network create hp_net_{username}
    │
    ▼
docker run hp_{username}_cowrie
docker run hp_{username}_heralding
... (8종)
    │
    ▼
로그 경로: D:\honeypot_logs\{username}\{honeypot}\
```

계정 비활성화 시 해당 유저의 컨테이너 + 네트워크만 삭제된다.

---

## 네트워킹

- kali-attacker는 시나리오 실행 시 유저 네트워크에 **임시 연결** → 완료 후 **자동 해제**
- 각 유저 네트워크는 완전히 격리되어 다른 유저 컨테이너에 접근 불가

---

## 기술 스택

| 레이어 | 기술 |
| --- | --- |
| 컨테이너 | Docker, Docker Compose |
| 백엔드 | FastAPI, SQLAlchemy (aiosqlite), python-jose, passlib |
| 프론트엔드 | React 18, Vite, Recharts, axios |
| 인증 | JWT (Bearer Token) |
| 실시간 통신 | WebSocket (asyncio + threading + Queue) |
| DB | SQLite (User, ScenarioRun 테이블) |
| 공격 도구 | nmap, hydra, sqlmap, curl, netcat (kali-attacker 컨테이너) |
