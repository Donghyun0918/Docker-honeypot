# 04. 웹 대시보드

## 개요

| 항목 | 내용 |
| --- | --- |
| 백엔드 | FastAPI + SQLAlchemy (aiosqlite) + JWT 인증 |
| 프론트엔드 | React 18 + Vite + Recharts |
| 실시간 통신 | WebSocket (asyncio + threading + Queue) |
| DB | SQLite — User, ScenarioRun 테이블 |

---

## 실행 방법

```bash
# 백엔드 (WSL2 / Linux)
cd dashboard/backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# 프론트엔드
cd dashboard/frontend
npm install
npm run dev    # http://localhost:5173
```

---

## 기능 목록

### 일반 유저 대시보드

| 기능 | 설명 |
| --- | --- |
| 내 계정 | 사용자명·이메일·상태·가입일 |
| 허니팟 컨테이너 상태 | 8종 컨테이너 실행 상태 실시간 표시 |
| 실시간 로그 스트리밍 | 컨테이너 카드 클릭 → WebSocket 오버레이 로그 뷰어 |
| 공격 시나리오 실행 | 9종 시나리오 원클릭 실행 |
| ScenarioMonitor | 시나리오 실행 중 허니팟별 로그 수신 활성 시각화 (펄스 애니메이션) |
| 시나리오 출력 확인 | 완료된 시나리오의 실행 로그 확인 |
| 데이터셋 생성 | parse_logs.py 실행 → dataset.csv 생성 |
| CSV 다운로드 | dataset.csv / dataset_meta.json 다운로드 |
| 통계 차트 | 허니팟별·프로토콜별·이벤트 타입·시간대별 Recharts 차트 |
| 시나리오 이력 | 실행한 시나리오 이력 테이블 (시각·결과·분류) |

### 관리자 대시보드

| 기능 | 설명 |
| --- | --- |
| 요약 카드 | 활성·비활성·전체 유저 수, 실행 중 컨테이너 수 |
| 유저별 컨테이너 | 모든 활성 유저의 컨테이너 상태 + 개별 제어 (시작/정지/재시작) |
| 공격 시나리오 현황 | 전체 유저의 시나리오 실행 상태 |
| 유저별 데이터셋 현황 | 유저별 CSV 행 수·크기·생성 시각·시나리오 완료/실패 횟수 |
| 전체 시나리오 이력 | 모든 유저의 시나리오 실행 이력 |
| 유저 관리 | 활성화/비활성화 (비활성화 시 컨테이너 자동 정리) |

---

## API 엔드포인트

### 인증

| 메서드 | 경로 | 설명 |
| --- | --- | --- |
| POST | `/api/auth/register` | 회원가입 (허니팟 컨테이너 자동 생성) |
| POST | `/api/auth/login` | 로그인 → JWT 토큰 발급 |

### 유저

| 메서드 | 경로 | 설명 |
| --- | --- | --- |
| GET | `/api/users/me` | 내 정보 |
| GET | `/api/users` | 전체 유저 목록 (관리자) |
| DELETE | `/api/users/{id}` | 유저 비활성화 (관리자) |
| POST | `/api/users/{id}/activate` | 유저 재활성화 (관리자) |

### 컨테이너

| 메서드 | 경로 | 설명 |
| --- | --- | --- |
| GET | `/api/containers` | 내 컨테이너 상태 |
| GET | `/api/admin/containers` | 전체 유저 컨테이너 (관리자) |
| POST | `/api/containers/{name}/{action}` | 개별 제어 start/stop/restart (관리자) |

### 시나리오

| 메서드 | 경로 | 설명 |
| --- | --- | --- |
| GET | `/api/scenarios` | 내 시나리오 목록 + 상태 |
| POST | `/api/scenarios/{id}/run` | 시나리오 실행 |
| GET | `/api/scenarios/{id}` | 특정 시나리오 상태 + 출력 |
| GET | `/api/admin/scenarios` | 전체 유저 시나리오 현황 (관리자) |

### 이력

| 메서드 | 경로 | 설명 |
| --- | --- | --- |
| GET | `/api/history` | 내 시나리오 실행 이력 |
| GET | `/api/admin/history` | 전체 유저 실행 이력 (관리자) |

### 데이터셋

| 메서드 | 경로 | 설명 |
| --- | --- | --- |
| POST | `/api/dataset/generate` | 데이터셋 생성 (parse_logs.py 실행) |
| GET | `/api/dataset/status` | 파일 존재 여부·크기 |
| GET | `/api/dataset/download` | CSV / JSON 다운로드 |
| GET | `/api/stats` | 통계 차트용 데이터 |
| GET | `/api/admin/stats` | 유저별 통계 (관리자) |

### 실시간

| 메서드 | 경로 | 설명 |
| --- | --- | --- |
| WS | `/ws/logs/{container_name}?token=` | JWT 인증 로그 스트리밍 |

---

## 주요 컴포넌트

### LogViewer
- WebSocket 연결로 컨테이너 로그 실시간 수신
- 최대 500줄 버퍼, 자동 스크롤
- 연결 상태 표시 (초록/빨강 dot)
- 재연결·클리어 버튼

### ScenarioMonitor
- 시나리오 실행 시 자동 팝업
- 8개 허니팟 WebSocket 동시 연결
- 로그 수신 시 허니팟 카드 펄스 애니메이션 (3초 유지)
- 허니팟별 고유 색상 코드
- 카드 클릭 → 해당 컨테이너 LogViewer 오픈

### StatsCharts (Recharts)
- 허니팟별 이벤트 수 (세로 막대)
- 이벤트 타입 분포 (파이차트)
- 프로토콜별 이벤트 수 (가로 막대)
- 시간대별 이벤트 추이 (라인차트)

---

## DB 스키마

### users 테이블
| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER PK | |
| username | STRING UNIQUE | |
| email | STRING UNIQUE | |
| hashed_password | STRING | bcrypt |
| is_active | BOOLEAN | 기본값 true |
| is_admin | BOOLEAN | 기본값 false |
| created_at | DATETIME | |
| deactivated_at | DATETIME | nullable |

### scenario_runs 테이블
| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | INTEGER PK | |
| username | STRING | |
| scenario_id | STRING | 01~09 |
| scenario_name | STRING | |
| label | STRING | Recon / Brute Force 등 |
| state | STRING | done / failed |
| started_at | DATETIME | |
| finished_at | DATETIME | |
| output | TEXT | 최대 4KB |
