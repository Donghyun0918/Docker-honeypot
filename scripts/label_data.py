#!/usr/bin/env python3
"""
label_data.py — dataset.csv에 ML 레이블을 부여한다.

레이블링 전략:
  1. 타임스탬프 기반: scenario_times.json의 start/end 윈도우에 매칭
  2. Rule-based 보완: event_type / protocol / 필드값 기반 규칙

ML 클래스:
  Etc          — 정상 트래픽
  Recon        — 포트스캔 / 정찰
  Brute Force  — 무차별 대입 / 자격증명 스터핑
  Intrusion    — 침투 후 행동 / 리버스 셸 / 웹 공격
  Malware      — 악성코드 다운로드 / C2 / FTP 업로드

실행 위치: kali-attacker 컨테이너 내부
사용법: python3 /scripts/label_data.py
"""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

LOG_BASE   = Path("/honeypot_logs")
TIMES_FILE = LOG_BASE / "scenario_times.json"
DATASET    = LOG_BASE / "dataset.csv"

ALL_LABELS = ["Etc", "Recon", "Brute Force", "Intrusion", "Malware"]


# ── 타이밍 파일 로드 ──────────────────────────────────────────────────────────

def load_scenario_times():
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
            end_str   = s["end"].replace("Z", "+00:00")
            scenarios.append({
                "scenario": s["scenario"],
                "label":    s["label"],
                "start":    datetime.fromisoformat(start_str),
                "end":      datetime.fromisoformat(end_str),
            })
        except (KeyError, ValueError) as e:
            print(f"[!] 시나리오 항목 오류: {e}")
            continue

    print(f"[timing] {len(scenarios)}개 시나리오 윈도우 로드")
    return scenarios


# ── 타임스탬프 파싱 ───────────────────────────────────────────────────────────

def parse_timestamp(ts_str):
    if not ts_str:
        return None
    ts_str = str(ts_str).strip()

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

    try:
        ts_clean = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts_clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def timestamp_label(ts_str, scenarios):
    dt = parse_timestamp(ts_str)
    if dt is None:
        return ""
    for s in scenarios:
        if s["start"] <= dt <= s["end"]:
            return s["label"]
    return ""


# ── Rule-based 레이블 ─────────────────────────────────────────────────────────

def rule_based_label(row, ts_label):
    """
    우선순위:
      1. has_reverse_shell == 1              → Intrusion
      2. event_type == command + has_wget/curl → Malware (Intrusion 아닐 때)
      3. event_type == scan                  → Recon
      4. protocol == PORTSCAN                → Recon
      5. source_honeypot == conpot           → Recon
      6. protocol == SMTP                    → Brute Force
      7. login_attempts >= 10                → Brute Force
      8. 타임스탬프 레이블
      9. 기본값                              → Etc
    """
    def intval(k):
        try:
            return int(row.get(k, 0) or 0)
        except (ValueError, TypeError):
            return 0

    proto   = str(row.get("protocol", "")).upper()
    src_hp  = str(row.get("source_honeypot", ""))
    ev_type = str(row.get("event_type", ""))

    if intval("has_reverse_shell"):
        return "Intrusion"

    if ev_type == "command" and (intval("has_wget") or intval("has_curl")):
        if ts_label not in ("Intrusion", "Brute Force"):
            return "Malware"

    if ev_type == "scan" or proto == "PORTSCAN":
        return "Recon"

    if src_hp == "conpot":
        return "Recon"

    if proto == "SMTP":
        return "Brute Force"

    if intval("login_attempts") >= 10:
        return "Brute Force"

    return ts_label if ts_label else "Etc"


# ── 레이블링 ─────────────────────────────────────────────────────────────────

def label_dataset(scenarios):
    if not DATASET.exists():
        print(f"[!] {DATASET} 없음")
        return 0

    with open(DATASET, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        print("[!] dataset.csv 비어있음")
        return 0

    counts = {lbl: 0 for lbl in ALL_LABELS}

    for row in rows:
        ts_lbl     = timestamp_label(row.get("timestamp", ""), scenarios)
        row["label"] = rule_based_label(row, ts_lbl)
        counts[row["label"]] = counts.get(row["label"], 0) + 1

    fieldnames = list(rows[0].keys())
    with open(DATASET, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[label] {DATASET.name}: {len(rows)}행 완료")
    for lbl in ALL_LABELS:
        if counts[lbl] > 0:
            print(f"         {lbl:15s}: {counts[lbl]:6d}행")

    return len(rows)


# ── 메인 ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print(" 레이블링 시작")
    print(f" DATASET: {DATASET}")
    print("=" * 55)

    scenarios = load_scenario_times()
    total = label_dataset(scenarios)

    print()
    print("=" * 55)
    print(f" 완료! 총 {total}행 → {DATASET}")
    print("=" * 55)
