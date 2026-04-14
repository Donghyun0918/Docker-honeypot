# 03. 데이터 파이프라인

## 전체 흐름

```
허니팟 로그 수집
(D:\honeypot_logs\{username}\{honeypot}\)
    │
    ▼
[Step 1] parse_logs.py
허니팟 7종 로그 파싱 → dataset.csv (29컬럼)
    │
    ▼
[Step 2] validate.py
컬럼·도메인·null율 품질 검증
실패 시 파이프라인 중단
    │
    ▼
[Step 3] feature_engineering.py
ML 전처리 → dataset_ml.csv (17컬럼)
    │
    ▼
[선택] label_data.py
타임스탬프 매칭 + rule-based 레이블 컬럼 추가
```

---

## 출력 파일

| 파일 | 설명 | 생성 단계 |
| --- | --- | --- |
| `dataset.csv` | 원시 이벤트 로그 (29컬럼, v4.0) | parse_logs.py |
| `dataset_meta.json` | 스키마 버전·row_count·분포 통계 | parse_logs.py |
| `validate_report.json` | 컬럼·도메인·null율 품질 리포트 | validate.py |
| `dataset_ml.csv` | ML 학습용 전처리 데이터 (17컬럼) | feature_engineering.py |
| `dataset_ml_encoders.json` | 레이블 인코딩 맵 | feature_engineering.py |

---

## 파서 v4.0 스키마 (29컬럼)

### 식별
| 컬럼 | 설명 |
| --- | --- |
| event_id | UUID v4 (행별 고유 식별자) |
| session_id | 세션 식별자 (native 또는 src_ip+port+ts MD5) |
| seq_no | 전체 이벤트 순번 |
| session_seq_no | 세션 내 이벤트 순번 |

### 시각
| 컬럼 | 설명 |
| --- | --- |
| timestamp | ISO 8601 UTC (이벤트 발생 시각) |
| ingest_time | ISO 8601 UTC (파싱 실행 시각) |

### 네트워크
| 컬럼 | 설명 |
| --- | --- |
| src_ip | 공격자 IP |
| src_port | 공격자 출발 포트 |
| dst_ip | 허니팟 IP |
| dst_port | 허니팟 포트 |
| transport | TCP / UDP |

### 서비스
| 컬럼 | 설명 |
| --- | --- |
| protocol | SSH / HTTP / FTP / SMTP / MYSQL / RDP / MODBUS / S7COMM / SMB / PORTSCAN 등 |
| source_honeypot | cowrie / heralding / opencanary / snare / dionaea / mailoney / conpot |
| event_type | auth / session / command / scan |
| event_result | success / fail / closed / executed / detected |

### 인증
| 컬럼 | 설명 |
| --- | --- |
| username | 인증 시도 사용자명 |
| password | 인증 시도 패스워드 |
| login_success | 0 / 1 |
| attempt_no | 세션 내 인증 시도 순번 |

### 세션
| 컬럼 | 설명 |
| --- | --- |
| duration | 세션 길이 (초) |
| login_attempts | 세션 내 총 로그인 시도 수 |

### HTTP
| 컬럼 | 설명 |
| --- | --- |
| http_method | GET / POST / PUT 등 |
| http_path | URL 경로 |
| http_query | 쿼리 문자열 (SQLi·XSS·LFI 페이로드 포함) |

### 명령어
| 컬럼 | 설명 |
| --- | --- |
| command | 실행 명령어 또는 HTTP 원본 문자열 |
| derived_has_wget | 0 / 1 |
| derived_has_curl | 0 / 1 |
| derived_has_reverse_shell | 0 / 1 |

### 메타
| 컬럼 | 설명 |
| --- | --- |
| parser_version | 파서 버전 (재현성 보장) |

---

## 허니팟별 event_type 매핑

| 허니팟 | 생성되는 event_type |
| --- | --- |
| cowrie | auth, session, command |
| heralding | auth, session |
| opencanary | scan |
| snare | command |
| dionaea | session |
| mailoney | auth |
| conpot | session |

---

## ML 전처리 (feature_engineering.py)

| 작업 | 상세 |
| --- | --- |
| 컬럼 제거 | event_id, session_id, ingest_time, src_ip, src_port, dst_ip, transport, timestamp, username, password, command |
| 시간 파생 | hour, is_night(22시~06시), day_of_week |
| 명령어 파생 | cmd_length, special_char_cnt, pipe_count |
| 결측 처리 | duration / login_attempts / login_success → 0 |
| 인코딩 | protocol / source_honeypot / event_type → Label Encoding |
| 타겟 생성 | is_attack (0=정상 / 1=공격, rule-based) |

---

## 레이블링 전략 (label_data.py)

1. **타임스탬프 기반**: `scenario_times.json`의 시나리오 시작·종료 시각에 로그 타임스탬프 매칭
2. **Rule-based 보완** (매칭 실패 시):

| 조건 | 레이블 |
| --- | --- |
| derived_has_reverse_shell == 1 | Intrusion |
| event_type == command + has_wget/curl == 1 | Malware |
| event_type == scan / protocol == PORTSCAN | Recon |
| source_honeypot == conpot | Recon |
| protocol == SMTP | Brute Force |
| login_attempts ≥ 10 | Brute Force |
| 해당 없음 | Etc |
