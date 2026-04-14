# 02. 공격 시나리오

## 설계 철학

단순 반복 공격이 아닌 **전술 라이브러리 기반 랜덤화** 시스템으로,
같은 시나리오를 반복 실행해도 매번 다른 공격 패턴이 생성된다.

---

## 시나리오 목록

| 번호 | 이름 | ML 레이블 | 주요 대상 허니팟 | 설명 |
| --- | --- | --- | --- | --- |
| 01 | 정상 트래픽 | Etc | heralding, snare, cowrie | 일반 브라우징·로그인 패턴 모방 |
| 02 | 포트 스캔 | Recon | opencanary, 전체 네트워크 | nmap 다양한 스캔 기법 |
| 03 | 브루트포스 | Brute Force | cowrie, heralding, mailoney | SSH·HTTP·FTP·RDP Hydra |
| 04 | 웹 공격 | Intrusion | snare | SQLi, XSS, LFI, RFI, CMD Injection |
| 05 | 침투 후 명령어 | Intrusion | cowrie | 시스템 정찰, 권한 상승 시도 |
| 06 | 리버스 셸 | Intrusion | cowrie | nc, python, perl, php, ruby 기법 |
| 07 | 멀웨어 업로드 | Malware | cowrie, dionaea | wget/curl C2, FTP 업로드 |
| 08 | 크리덴셜 스터핑 | Brute Force | opencanary, dionaea, cowrie, heralding | 다중 서비스 동시 시도 |
| 09 | ICS/SCADA 공격 | Recon | conpot | Modbus, SNMP, S7, BACnet, DNP3 |

---

## 전술 라이브러리 구조

```
attack_scenarios/
├── lib/
│   ├── common.sh            # 공통 유틸 + IP/유저/패스워드/페이로드 풀
│   ├── tactics_normal.sh    # 정상 트래픽 전술 8종
│   ├── tactics_recon.sh     # 정찰 전술 12종
│   ├── tactics_brute.sh     # 브루트포스 전술 11종
│   ├── tactics_intrusion.sh # 침투 전술 9종
│   ├── tactics_malware.sh   # 악성코드 전술 8종
│   └── tactics_ics.sh       # ICS/SCADA 전술 8종
└── 01~09_*.sh               # 각 실행마다 전술 N개 랜덤 선택
```

---

## 랜덤화 요소

| 요소 | 범위 |
| --- | --- |
| 전술 조합 | 전술 풀에서 4~8종 무작위 선택 |
| 유저명 | 50+ 항목 풀 샘플링 |
| 패스워드 | 60+ 항목 풀 샘플링 |
| 페이로드 | SQLi 13종, XSS 10종, LFI 10종, 리버스셸 7종, C2 URL 7종 |
| 공격 강도 | 요청 수, Hydra 스레드 수 랜덤 |
| 타겟 | 복수 허니팟 중 랜덤 선택 |
| 타이밍 | 요청 간격 랜덤 sleep |

---

## 시나리오 실행 흐름

```
사용자가 대시보드에서 시나리오 실행
    │
    ▼
백엔드 스레드 생성
    │
    ▼
kali-attacker 상태 확인 (꺼져있으면 자동 시작)
    │
    ▼
kali → hp_net_{username} 네트워크 연결
    │
    ▼
유저 허니팟 IP 수집 (Docker inspect)
    │
    ▼
IP를 환경변수로 주입하여 시나리오 스크립트 실행
(COWRIE_IP=x.x.x.x HERALDING_IP=x.x.x.x bash scenario.sh)
    │
    ▼
완료 → DB(ScenarioRun)에 이력 저장
    │
    ▼
kali → 네트워크 해제
```

---

## ML 레이블 체계

| 레이블 | 의미 |
| --- | --- |
| **Etc** | 정상 트래픽 |
| **Recon** | 정찰 (포트 스캔, 서비스 탐지) |
| **Brute Force** | 인증 무차별 대입 |
| **Intrusion** | 침투 (웹 공격, 리버스 셸, 내부 명령) |
| **Malware** | 악성코드 (C2 통신, 파일 업로드) |
