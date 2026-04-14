# 05. 설치 및 실행

## 요구사항

| 항목 | 내용 |
| --- | --- |
| OS | Windows 11 (WSL2 필수) |
| 런타임 | Docker Desktop (WSL2 백엔드 설정) |
| RAM | 8GB 이상 권장 |
| 저장공간 | 이미지 빌드 포함 약 5~8GB |
| Python | 3.10+ (WSL2 내부) |
| Node.js | 18+ |

---

## 초기 설치

### 1. 저장소 클론

```bash
git clone https://github.com/Donghyun0918/Docker-honeypot.git
cd Docker-honeypot
```

### 2. 로그 디렉터리 설정

```bash
# Windows PowerShell
mkdir D:\honeypot_logs
```

### 3. 허니팟 컨테이너 빌드 및 실행

```bash
docker compose build
docker compose up -d

# 상태 확인 (9개 컨테이너 모두 Up)
docker compose ps
```

---

## 대시보드 실행

### 백엔드

```bash
# WSL2 터미널
cd /mnt/d/docker_honeypot/dashboard/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 실행
uvicorn main:app --reload --port 8000
```

### 프론트엔드

```bash
cd dashboard/frontend
npm install
npm run dev
# → http://localhost:5173
```

---

## 관리자 계정 설정

최초 실행 후 DB에서 직접 관리자 권한을 부여해야 한다.

```bash
# WSL2에서
cd /mnt/d/docker_honeypot/dashboard/backend
sqlite3 dashboard.db "UPDATE users SET is_admin = 1 WHERE username = '관리자아이디';"
```

변경 후 로그아웃 → 재로그인 필요.

---

## 로그 경로 구조

```
D:\honeypot_logs\
├── {username}\          ← 유저별 디렉터리 (가입 시 자동 생성)
│   ├── cowrie\
│   ├── heralding\
│   ├── opencanary\
│   ├── snare\
│   ├── tanner\
│   ├── dionaea\
│   ├── mailoney\
│   ├── conpot\
│   ├── dataset.csv           ← 데이터셋 생성 후
│   └── dataset_meta.json
└── (기존 docker-compose 구조)
    ├── cowrie\
    ├── heralding\
    └── ...
```

---

## 주요 트러블슈팅

| 증상 | 원인 | 해결 |
| --- | --- | --- |
| 백엔드 포트 충돌 | 8000번 포트 이미 사용 중 | `fuser -k 8000/tcp` |
| 컨테이너 not_found | 이미지명 불일치 | `docker images` 로 실제 이미지명 확인 |
| 스네어 재시작 루프 | tanner 연결 실패 | `--tanner hp_{username}_tanner` 명령어 확인 |
| 오픈카나리 실행 실패 | twistd.pid 잔존 | Dockerfile CMD에서 PID 파일 삭제 처리 |
| WebSocket 서버 다운 | Docker 스트림이 이벤트 루프 블록 | threading + Queue 패턴으로 비동기 분리 |
| 시나리오 실행 실패 | kali-attacker 미실행 | scenario_runner에서 자동 시작 처리 |
| 관리자 로그인 후 권한 없음 | is_admin 컬럼 추가 전 발급된 JWT | 로그아웃 → 재로그인 |

---

## 디렉터리 구조

```
Docker-honeypot/
├── docker-compose.yml
├── setup.sh
├── README.md
│
├── honeypots/             허니팟별 Dockerfile + 설정
├── kali/                  공격자 컨테이너 Dockerfile
├── attack_scenarios/      시나리오 스크립트 + 전술 라이브러리
├── scripts/               파이프라인 스크립트 (parse, validate, ML)
├── dashboard/
│   ├── .gitignore
│   ├── backend/           FastAPI 앱
│   └── frontend/          React + Vite 앱
└── notion_docs/           이 문서들
```
