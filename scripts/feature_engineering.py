#!/usr/bin/env python3
"""
feature_engineering.py — dataset.csv → dataset_ml.csv

dataset.csv (원시 로그)를 ML 학습 가능한 형태로 변환한다.

변환 내용:
  [제거]
    event_id         — 고유 식별자, ML 피처 불필요
    session_id       — 식별자, ML 피처 불필요
    ingest_time      — 파이프라인 메타데이터, ML 피처 불필요
    src_ip           — 단일 값(172.30.0.20), 과적합 원인
    src_port         — 에페메랄 포트, 정보 가치 없음
    dst_ip           — 허니팟별 고정값, 과적합 원인
    transport        — protocol로부터 파생, 중복
    timestamp        — 수치 피처 추출 후 제거
    username         — 고유값 과다, 직접 사용 불가
    password         — 고유값 과다, 직접 사용 불가
    command (raw)    — 수치 피처 추출 후 제거

  [시간 피처] timestamp →
    hour             0~23
    is_night         22:00~05:59 → 1, 그 외 → 0
    day_of_week      0(월) ~ 6(일)

  [커맨드 피처] command →
    cmd_length       문자열 길이
    special_char_cnt |  ;  &  >  <  $  `  \\ 개수
    pipe_count       | 개수 (파이프 체인 복잡도)
    has_wget         기존 유지
    has_curl         기존 유지
    has_reverse_shell 기존 유지

  [결측 처리]
    duration         NaN → 0.0
    login_attempts   NaN → 0
    login_success    NaN → 0

  [인코딩] Label Encoding (트리 계열 모델 기준)
    protocol         문자열 → 정수
    source_honeypot  문자열 → 정수
    event_type       문자열 → 정수

  [타겟] is_attack (이진)
    1 — 공격성 이벤트 (rule-based)
    0 — 정상 이벤트 (Etc)

인코딩 맵은 dataset_ml_encoders.json 에 별도 저장한다.
"""

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path

LOG_BASE = Path("/honeypot_logs")
IN_PATH  = LOG_BASE / "dataset.csv"
OUT_PATH = LOG_BASE / "dataset_ml.csv"
ENC_PATH = LOG_BASE / "dataset_ml_encoders.json"

SPECIAL_RE  = re.compile(r'[|;&><$`\\]')
# snare 웹 공격 패턴 (SQLi, XSS, LFI, RFI, 명령어 인젝션)
WEB_ATTACK_RE = re.compile(
    r"(?i)("
    r"union\s+select|select\s+.+from|or\s+1\s*=\s*1|and\s+1\s*=\s*1"
    r"|<script|javascript:|onerror=|onload="
    r"|\.\.\/|\.\.\\|etc/passwd|/proc/"
    r"|cmd=|exec=|system\(|passthru\(|eval\("
    r"|wget\s|curl\s|nc\s|bash\s+-[ci]"
    r"|phpinfo\(\)|base64_decode"
    r")"
)

OUT_FIELDS = [
    # 시간
    "hour", "is_night", "day_of_week",
    # 네트워크
    "dst_port", "protocol", "source_honeypot", "event_type",
    # 인증
    "login_success", "duration", "login_attempts",
    # 커맨드
    "cmd_length", "special_char_cnt", "pipe_count",
    "has_wget", "has_curl", "has_reverse_shell",
    # 타겟
    "is_attack",
]


# ── 이진 타겟 (label_data.py rule-based와 동일한 기준) ────────────────────────
def calc_is_attack(row: dict) -> int:
    if int(row.get("has_reverse_shell") or 0):
        return 1
    et    = row.get("event_type", "")
    proto = row.get("protocol", "")
    hp    = row.get("source_honeypot", "")
    if et == "command" and (int(row.get("has_wget") or 0) or int(row.get("has_curl") or 0)):
        return 1
    if et == "scan" or proto == "PORTSCAN":
        return 1
    if hp == "conpot":
        return 1
    if proto == "SMTP":
        return 1
    try:
        if int(row.get("login_attempts") or 0) >= 10:
            return 1
    except (ValueError, TypeError):
        pass
    # snare 웹 공격 패턴 감지 (SQLi / XSS / LFI / RFI / 명령어 인젝션)
    if row.get("source_honeypot") == "snare":
        cmd = row.get("command", "") or ""
        if WEB_ATTACK_RE.search(cmd):
            return 1
    return 0


# ── 카테고리 인코더 ────────────────────────────────────────────────────────────
def build_encoder(values: list) -> dict:
    unique = sorted(set(v for v in values if v))
    return {v: i for i, v in enumerate(unique)}


def encode(enc: dict, val: str) -> int:
    return enc.get(val, -1)


# ── 메인 ──────────────────────────────────────────────────────────────────────
def main():
    print("=" * 55)
    print(" Feature Engineering")
    print(f" 입력: {IN_PATH}")
    print("=" * 55)

    with open(IN_PATH, encoding="utf-8") as f:
        raw = list(csv.DictReader(f))

    print(f"원본: {len(raw):,}행")

    # 인코더 빌드
    protocol_enc = build_encoder(r.get("protocol", "") for r in raw)
    honeypot_enc = build_encoder(r.get("source_honeypot", "") for r in raw)
    event_enc    = build_encoder(r.get("event_type", "") for r in raw)

    out_rows = []
    for row in raw:
        # ── 시간 피처 ──────────────────────────────────────────────────────
        ts_str = row.get("timestamp", "")
        try:
            ts          = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            hour        = ts.hour
            is_night    = 1 if (hour >= 22 or hour < 6) else 0
            day_of_week = ts.weekday()
        except (ValueError, AttributeError):
            hour = is_night = day_of_week = 0

        # ── 커맨드 피처 ────────────────────────────────────────────────────
        cmd              = row.get("command", "") or ""
        cmd_length       = len(cmd)
        special_char_cnt = len(SPECIAL_RE.findall(cmd))
        pipe_count       = cmd.count("|")

        # ── 수치형 결측 처리 ────────────────────────────────────────────────
        dst_port       = int(row.get("dst_port") or 0)
        login_success  = int(row.get("login_success") or 0)
        login_attempts = int(row.get("login_attempts") or 0)
        duration       = float(row.get("duration") or 0.0)
        has_wget       = int(row.get("has_wget") or 0)
        has_curl       = int(row.get("has_curl") or 0)
        has_revshell   = int(row.get("has_reverse_shell") or 0)

        out_rows.append({
            "hour":             hour,
            "is_night":         is_night,
            "day_of_week":      day_of_week,
            "dst_port":         dst_port,
            "protocol":         encode(protocol_enc, row.get("protocol", "")),
            "source_honeypot":  encode(honeypot_enc, row.get("source_honeypot", "")),
            "event_type":       encode(event_enc,    row.get("event_type", "")),
            "login_success":    login_success,
            "duration":         duration,
            "login_attempts":   login_attempts,
            "cmd_length":       cmd_length,
            "special_char_cnt": special_char_cnt,
            "pipe_count":       pipe_count,
            "has_wget":         has_wget,
            "has_curl":         has_curl,
            "has_reverse_shell": has_revshell,
            "is_attack":        calc_is_attack(row),
        })

    # ── CSV 출력 ──────────────────────────────────────────────────────────────
    with open(OUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUT_FIELDS)
        writer.writeheader()
        writer.writerows(out_rows)

    # ── 인코더 맵 저장 ────────────────────────────────────────────────────────
    encoders = {
        "protocol":        protocol_enc,
        "source_honeypot": honeypot_enc,
        "event_type":      event_enc,
    }
    with open(ENC_PATH, "w", encoding="utf-8") as f:
        json.dump(encoders, f, ensure_ascii=False, indent=2)

    # ── 결과 출력 ─────────────────────────────────────────────────────────────
    n = len(out_rows)
    attack = sum(1 for r in out_rows if r["is_attack"] == 1)
    normal = n - attack

    print()
    print("=" * 55)
    print(f" 출력: {n:,}행 → {OUT_PATH}")
    print(f" 인코더:       {ENC_PATH}")
    print()
    print(f" is_attack=1 (공격): {attack:,}  ({attack/n*100:.1f}%)")
    print(f" is_attack=0 (정상): {normal:,}  ({normal/n*100:.1f}%)")
    print()
    print(" 인코딩 맵:")
    for name, enc in encoders.items():
        print(f"  {name}: {enc}")
    print()
    print(" 컬럼 목록:")
    for i, f in enumerate(OUT_FIELDS):
        print(f"  {i:2d}. {f}")
    print("=" * 55)
    print()
    if normal / n < 0.15:
        print("[주의] 정상 데이터 비율이 낮습니다 ({:.1f}%).".format(normal/n*100))
        print("       학습 시 class_weight='balanced' 또는 SMOTE 오버샘플링을 권장합니다.")


if __name__ == "__main__":
    main()
