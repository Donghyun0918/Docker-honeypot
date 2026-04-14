# Honeypot Dashboard

유저 가입/탈퇴 이벤트에 따라 허니팟 컨테이너를 자동 제어하는 웹 대시보드.

## 구조

```
dashboard/
├── backend/
│   ├── main.py          # FastAPI 앱 (API 엔드포인트)
│   ├── docker_ops.py    # Docker SDK 컨테이너 제어
│   ├── auth.py          # JWT 인증
│   ├── database.py      # SQLite ORM (SQLAlchemy)
│   └── requirements.txt
└── frontend/
    ├── src/
    │   ├── pages/       # Login / Register / Dashboard
    │   ├── App.jsx
    │   ├── api.js       # axios 인스턴스
    │   └── index.css
    └── package.json
```

## 실행 방법

### 백엔드

```bash
cd dashboard/backend
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 프론트엔드

```bash
cd dashboard/frontend
npm install
npm run dev
```

브라우저에서 http://localhost:5173 접속

## 오퍼레이션 흐름

| 이벤트 | 동작 |
|--------|------|
| 회원가입 (`POST /api/auth/register`) | DB 유저 생성 → 모든 허니팟 컨테이너 start |
| 유저 비활성화 (`DELETE /api/users/:id`) | DB 비활성화 → 활성 유저 0명이면 모든 컨테이너 stop |
| 수동 전체 활성화 (`POST /api/containers/activate`) | 모든 컨테이너 start |
| 수동 전체 정지 (`POST /api/containers/deactivate`) | 모든 컨테이너 stop |
