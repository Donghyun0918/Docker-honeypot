#!/usr/bin/env python3
"""
label_data.py — auth.csv, sessions.csv, input.csv에 ML 레이블을 부여한다.

레이블링 전략:
  1. 타임스탬프 기반: scenario_times.json의 start/end 윈도우에 매칭
  2. Rule-based 보완: 필드 값 기반 규칙 적용

ML 클래스:
  Etc          — 정상 트래픽
  Recon        — 포트스캔 / 정찰
  Brute Force  — 무차별 대입 공격
  Intrusion    — 침투 후 행동, 리버스 셸
  Malware      — 악성코드 다운로드/실행

실행 위치: kali-attacker 컨테이너 내부
사용법: python3 /scripts/label_data.py
"""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

LOG_BASE = Path("/honeypot_logs")
TIMES_FILE = LOG_BASE / "scenario_times.json"

ALL_LABELS = ["Etc", "Recon", "Brute Force", "Intrusion", "Malware"]


# ── 타이밍 파일 로드 ──────────────────────────────────────────────────────────

def load_scenario_times():
    """
    scenario_times.json 로드.
    반환: [{scenario, label, start: datetime, end: datetime}, ...]
    """
    if not TIMES_FILE.exists():
        print(f"[!] {TIMES_FILE} 없음 - rule-based 레이블링만 사용")
        return []

    with open(TIMES_FILE, encoding="utf-8") as f:
        try:
            raw = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[!] scenario_times.json 파싱 오류: {e}")
            return []

    scenarios = []
    for s in raw:
        try:
            start_str = s["start"].replace("Z", "+00:00")
            end_str = s["end"].replace("Z", "+00:00")
            scenarios.append({
                "scenario": s["scenario"],
                "label": s["label"],
                "start": datetime.fromisoformat(start_str),
                "end": datetime.fromisoformat(end_str),
            })
        except (KeyError, ValueError) as e:
            print(f"[!] 시나리오 항목 파싱 오류: {e}, 항목: {s}")
            continue

    print(f"[timing] {len(scenarios)}개 시나리오 윈도우 로드")
    return scenarios


# ── 타임스탬프 매칭 ───────────────────────────────────────────────────────────

def parse_timestamp(ts_str):
    """다양한 타임스탬프 형식을 timezone-aware datetime으로 변환"""
    if not ts_str:
        return None
    ts_str = str(ts_str).strip()

    # ISO 8601 변형들
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    # fromisoformat 시도 (Python 3.7+)
    try:
        ts_clean = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts_clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass

    return None


def timestamp_label(ts_str, scenarios):
    """타임스탬프가 시나리오 윈도우에 속하면 해당 레이블 반환, 없으면 빈 문자열"""
    dt = parse_timestamp(ts_str)
    if dt is None:
        return ""
    for s in scenarios:
        if s["start"] <= dt <= s["end"]:
            return s["label"]
    return ""


# ── Rule-based 레이블 ─────────────────────────────────────────────────────────

def rule_based_label(row, current_label):
    """
    필드 값 기반 규칙으로 레이블 보완 또는 재지정.

    규칙 우선순위 (높을수록 먼저 적용):
      1. has_reverse_shell == 1         → Intrusion
      2. has_wget/has_curl (input에서)  → Malware (Intrusion 아닐 때)
      3. login_attempts >= 10           → Brute Force
      4. protocol == PORTSCAN           → Recon
      5. protocol == SMTP               → Brute Force
      6. 타임스탬프 레이블 사용
      7. 기본값                         → Etc
    """
    def intval(key):
        try:
            return int(row.get(key, 0) or 0)
        except (ValueError, TypeError):
            return 0

    proto = str(row.get("protocol", "")).upper()
    src_hp = str(row.get("source_honeypot", ""))

    # 규칙 1: 리버스 셸 → 항상 Intrusion
    if intval("has_reverse_shell") == 1:
        return "Intrusion"

    # 규칙 2: 악성코드 다운로드 지표
    if intval("has_wget") == 1 or intval("has_curl") == 1:
        if current_label not in ("Intrusion", "Brute Force"):
            return "Malware"

    # 규칙 3: 대량 로그인 시도
    if intval("login_attempts") >= 10:
        return "Brute Force"

    # 규칙 4: 포트스캔 프로토콜
    if proto == "PORTSCAN":
        return "Recon"

    # 규칙 5: SMTP → 브루트포스 / 스팸
    if proto == "SMTP":
        return "Brute Force"

    # 규칙 6: Conpot (ICS) → Recon
    if src_hp == "conpot":
        return "Recon"

    # 타임스탬프 레이블 또는 기본값
    return current_label if current_label else "Etc"


# ── CSV 레이블링 ──────────────────────────────────────────────────────────────

def label_csv(path, scenarios):
    """CSV 파일을 읽어 label 컬럼을 채우고 덮어씀"""
    if not path.exists():
        print(f"[!] 파일 없음, 건너뜀: {path}")
        return 0

    with open(path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        print(f"[!] 빈 파일: {path}")
        return 0

    label_counts = {lbl: 0 for lbl in ALL_LABELS}
    label_counts["Unknown"] = 0

    for row in rows:
        ts_lbl = timestamp_label(row.get("timestamp", ""), scenarios)
        row["label"] = rule_based_label(row, ts_lbl)
        label_counts[row["label"]] = label_counts.get(row["label"], 0) + 1

    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[label] {path.name}: {len(rows)}행 레이블링 완료")
    for lbl, cnt in sorted(label_counts.items(), key=lambda x: -x[1]):
        if cnt > 0:
            print(f"         {lbl:15s}: {cnt:5d}행")

    return len(rows)


# ── 메인 ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print(" 레이블링 시작")
    print(f" TIMES_FILE: {TIMES_FILE}")
    print("=" * 50)

    scenarios = load_scenario_times()

    total = 0
    for csv_name in ("auth.csv", "sessions.csv", "input.csv"):
        p = LOG_BASE / csv_name
        print(f"\n[처리] {p}")
        total += label_csv(p, scenarios)

    print("")
    print("=" * 50)
    print(f" 완료! 총 {total}행 레이블링")
    print("")
    print(" 레이블 분포 확인 (선택적):")
    print("   python3 -c \"import pandas as pd; \\")
    print("     [print(n, pd.read_csv(f'/honeypot_logs/{n}')['label'].value_counts().to_string()) \\")
    print("     for n in ['auth.csv','sessions.csv','input.csv']]\"")
    print("=" * 50)
