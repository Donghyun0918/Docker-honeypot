#!/usr/bin/env python3
"""
parse_logs.py — 허니팟 7종 로그 파서 → dataset.csv (단일 통합 파일)

실행 위치: kali-attacker 컨테이너 내부
사용법: python3 /scripts/parse_logs.py

출력 스키마 (16컬럼):
  timestamp         ISO 8601 UTC
  src_ip            공격자 IP
  dst_port          대상 포트 (정수)
  protocol          SSH / HTTP / FTP / SMTP / MySQL / RDP / VNC / SMB / MSSQL / Modbus / SNMP / S7 / PORTSCAN
  source_honeypot   cowrie / heralding / opencanary / snare / dionaea / mailoney / conpot
  event_type        auth / session / command / scan
  username          인증 시도 사용자명 (없으면 빈칸)
  password          인증 시도 패스워드 (없으면 빈칸)
  login_success     0 / 1 (auth 이벤트만, 나머지 빈칸)
  duration          세션 길이 초 (session 이벤트만)
  login_attempts    세션 내 로그인 시도 수
  command           실행 명령어 또는 HTTP 요청 경로
  has_wget          0 / 1
  has_curl          0 / 1
  has_reverse_shell 0 / 1
  label             레이블링 전 빈칸 (label_data.py가 채움)
"""

import csv
import glob
import json
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path

LOG_BASE = Path("/honeypot_logs")
OUT_BASE = LOG_BASE

DATASET_FIELDS = [
    "timestamp", "src_ip", "dst_port", "protocol",
    "source_honeypot", "event_type",
    "username", "password", "login_success",
    "duration", "login_attempts",
    "command", "has_wget", "has_curl", "has_reverse_shell",
    "label",
]

REVERSE_SHELL_PATTERNS = [
    "nc ", "/dev/tcp", "python3 -c", "python -c",
    "bash -i", "perl -e", "ruby -r", "mkfifo",
]


def make_row(
    timestamp="", src_ip="", dst_port="", protocol="",
    source_honeypot="", event_type="",
    username="", password="", login_success="",
    duration="", login_attempts="",
    command="", has_wget=0, has_curl=0, has_reverse_shell=0,
    label="",
):
    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "source_honeypot": source_honeypot,
        "event_type": event_type,
        "username": username,
        "password": password,
        "login_success": login_success,
        "duration": duration,
        "login_attempts": login_attempts,
        "command": command,
        "has_wget": has_wget,
        "has_curl": has_curl,
        "has_reverse_shell": has_reverse_shell,
        "label": label,
    }


def cmd_flags(cmd):
    c = str(cmd)
    return (
        int("wget" in c),
        int("curl" in c),
        int(any(p in c for p in REVERSE_SHELL_PATTERNS)),
    )


# ── Cowrie ────────────────────────────────────────────────────────────────────

def parse_cowrie():
    rows = []
    sessions = {}

    log_files = sorted(glob.glob(str(LOG_BASE / "cowrie" / "cowrie.json*")))
    if not log_files:
        print("[cowrie] 로그 파일 없음")
        return rows

    for logfile in log_files:
        print(f"[cowrie] {logfile}")
        with open(logfile, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue

                eid  = e.get("eventid", "")
                ts   = e.get("timestamp", "")
                sid  = e.get("session", "")
                src  = e.get("src_ip", "")
                port = e.get("dst_port", 2222)

                if eid in ("cowrie.login.success", "cowrie.login.failed"):
                    success = 1 if eid == "cowrie.login.success" else 0
                    rows.append(make_row(
                        timestamp=ts, src_ip=src, dst_port=port,
                        protocol="SSH", source_honeypot="cowrie", event_type="auth",
                        username=e.get("username", ""), password=e.get("password", ""),
                        login_success=success,
                    ))
                    sess = sessions.setdefault(sid, {
                        "start": ts, "src_ip": src, "port": port,
                        "attempts": 0, "successes": 0,
                    })
                    sess["attempts"] += 1
                    sess["successes"] += success

                elif eid == "cowrie.session.connect":
                    sessions.setdefault(sid, {
                        "start": ts, "src_ip": src, "port": port,
                        "attempts": 0, "successes": 0,
                    })

                elif eid == "cowrie.session.closed":
                    s = sessions.get(sid, {})
                    rows.append(make_row(
                        timestamp=s.get("start", ts),
                        src_ip=s.get("src_ip", src),
                        dst_port=s.get("port", port),
                        protocol="SSH", source_honeypot="cowrie", event_type="session",
                        duration=round(float(e.get("duration", 0)), 3),
                        login_attempts=s.get("attempts", 0),
                    ))

                elif eid in ("cowrie.command.input", "cowrie.session.file_download"):
                    cmd = e.get("input", e.get("url", ""))
                    w, c, r = cmd_flags(cmd)
                    rows.append(make_row(
                        timestamp=ts, src_ip=src, dst_port=port,
                        protocol="SSH", source_honeypot="cowrie", event_type="command",
                        command=cmd, has_wget=w, has_curl=c, has_reverse_shell=r,
                    ))

    print(f"[cowrie] {len(rows)}행")
    return rows


# ── Heralding ─────────────────────────────────────────────────────────────────

def parse_heralding():
    rows = []

    auth_file = LOG_BASE / "heralding" / "auth.csv"
    if auth_file.exists():
        print(f"[heralding] {auth_file}")
        with open(auth_file, encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                rows.append(make_row(
                    timestamp=row.get("timestamp", ""),
                    src_ip=row.get("source_ip", ""),
                    dst_port=row.get("destination_port", ""),
                    protocol=row.get("protocol", "").upper(),
                    source_honeypot="heralding", event_type="auth",
                    username=row.get("username", ""),
                    password=row.get("password", ""),
                    login_success=0,
                ))

    session_file = LOG_BASE / "heralding" / "session.csv"
    if session_file.exists():
        print(f"[heralding] {session_file}")
        with open(session_file, encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                rows.append(make_row(
                    timestamp=row.get("timestamp", ""),
                    src_ip=row.get("source_ip", ""),
                    dst_port=row.get("destination_port", ""),
                    protocol=row.get("protocol", "").upper(),
                    source_honeypot="heralding", event_type="session",
                    duration=row.get("duration", ""),
                    login_attempts=1,
                ))

    print(f"[heralding] {len(rows)}행")
    return rows


# ── OpenCanary ────────────────────────────────────────────────────────────────

def parse_opencanary():
    LOGTYPE_MAP = {
        1001: "PORTSCAN",
        2000: "FTP",
        6001: "RDP",
        5001: "VNC",
        3001: "HTTP",
        4001: "TELNET",
        9001: "SNMP",
    }
    rows = []

    log_files = sorted(glob.glob(str(LOG_BASE / "opencanary" / "*.log*")))
    if not log_files:
        print("[opencanary] 로그 파일 없음")
        return rows

    for logfile in log_files:
        print(f"[opencanary] {logfile}")
        with open(logfile, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue

                logtype  = e.get("logtype", 0)
                protocol = LOGTYPE_MAP.get(logtype, f"UNKNOWN_{logtype}")
                rows.append(make_row(
                    timestamp=e.get("utc_time", ""),
                    src_ip=e.get("src_host", ""),
                    dst_port=e.get("dst_port", ""),
                    protocol=protocol,
                    source_honeypot="opencanary", event_type="scan",
                ))

    print(f"[opencanary] {len(rows)}행")
    return rows


# ── SNARE ─────────────────────────────────────────────────────────────────────

def parse_snare():
    rows = []

    def add(ts, src_ip, path):
        w, c, r = cmd_flags(path)
        rows.append(make_row(
            timestamp=ts, src_ip=src_ip, dst_port=8080,
            protocol="HTTP", source_honeypot="snare", event_type="command",
            command=path, has_wget=w, has_curl=c, has_reverse_shell=r,
        ))

    for logfile in sorted(glob.glob(str(LOG_BASE / "snare" / "*.json*"))):
        print(f"[snare] {logfile}")
        with open(logfile, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                path = e.get("path", e.get("request_path", ""))
                ts   = e.get("timestamp", e.get("time", ""))
                src  = e.get("peer", e.get("remote_ip", e.get("src_ip", "")))
                add(ts, src, path)

    text_log = LOG_BASE / "snare" / "snare.log"
    if text_log.exists():
        print(f"[snare] {text_log}")
        pattern = re.compile(
            r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'
            r'.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            r'.*?(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)'
        )
        with open(text_log, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = pattern.search(line)
                if m:
                    ts, src, method, path = m.group(1), m.group(2), m.group(3), m.group(4)
                    add(ts, src, f"{method} {path}")

    print(f"[snare] {len(rows)}행")
    return rows


# ── Dionaea ───────────────────────────────────────────────────────────────────

def parse_dionaea():
    rows = []
    db_path = LOG_BASE / "dionaea" / "logsql.sqlite"

    if not db_path.exists():
        print(f"[dionaea] DB 없음, 건너뜀")
        return rows

    print(f"[dionaea] {db_path}")
    try:
        conn = sqlite3.connect(str(db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        cur = conn.cursor()

        cur.execute("""
            SELECT
                c.connection_timestamp,
                c.remote_host,
                c.local_port,
                c.connection_protocol,
                l.login_username,
                l.login_password
            FROM connections c
            LEFT JOIN logins l ON l.connection = c.id
        """)
        for row in cur.fetchall():
            try:
                ts = datetime.fromtimestamp(float(row["connection_timestamp"])).isoformat()
            except Exception:
                ts = str(row["connection_timestamp"] or "")

            proto = (row["connection_protocol"] or "UNKNOWN").upper()
            src   = row["remote_host"] or ""
            port  = row["local_port"] or ""

            rows.append(make_row(
                timestamp=ts, src_ip=src, dst_port=port,
                protocol=proto, source_honeypot="dionaea", event_type="session",
                login_attempts=1 if row["login_username"] else 0,
            ))

            if row["login_username"]:
                rows.append(make_row(
                    timestamp=ts, src_ip=src, dst_port=port,
                    protocol=proto, source_honeypot="dionaea", event_type="auth",
                    username=row["login_username"] or "",
                    password=row["login_password"] or "",
                    login_success=0,
                ))

        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"[dionaea] DB 오류: {e}")

    print(f"[dionaea] {len(rows)}행")
    return rows


# ── Mailoney ──────────────────────────────────────────────────────────────────

def parse_mailoney():
    rows = []

    log_files = sorted(glob.glob(str(LOG_BASE / "mailoney" / "*.json*")))
    if not log_files:
        print("[mailoney] 로그 파일 없음")
        return rows

    for logfile in log_files:
        print(f"[mailoney] {logfile}")
        with open(logfile, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rows.append(make_row(
                    timestamp=e.get("timestamp", e.get("time", "")),
                    src_ip=e.get("src_ip", e.get("remote_ip", e.get("ip", ""))),
                    dst_port=25,
                    protocol="SMTP", source_honeypot="mailoney", event_type="auth",
                    username=e.get("username", e.get("user", "")),
                    password=e.get("password", e.get("pass", "")),
                    login_success=0,
                ))

    print(f"[mailoney] {len(rows)}행")
    return rows


# ── Conpot ────────────────────────────────────────────────────────────────────

def parse_conpot():
    rows = []

    log_files = sorted(glob.glob(str(LOG_BASE / "conpot" / "*.json*")))
    if not log_files:
        print("[conpot] 로그 파일 없음")
        return rows

    for logfile in log_files:
        print(f"[conpot] {logfile}")
        with open(logfile, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue

                remote = e.get("remote", {})
                local  = e.get("local", {})
                rows.append(make_row(
                    timestamp=e.get("timestamp", ""),
                    src_ip=remote.get("ip", e.get("remote_ip", "")),
                    dst_port=local.get("port", e.get("local_port", "")),
                    protocol=e.get("data_type", e.get("type", "ICS")).upper(),
                    source_honeypot="conpot", event_type="session",
                    duration=e.get("session_length", e.get("duration", "")),
                ))

    print(f"[conpot] {len(rows)}행")
    return rows


# ── CSV 출력 ──────────────────────────────────────────────────────────────────

def write_csv(rows, fields, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})
    print(f"[output] {len(rows)}행 → {path}")


# ── 메인 ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print(" 허니팟 로그 파서 시작")
    print(f" LOG_BASE: {LOG_BASE}")
    print("=" * 55)

    all_rows = []
    parsers = [
        parse_cowrie,
        parse_heralding,
        parse_opencanary,
        parse_snare,
        parse_dionaea,
        parse_mailoney,
        parse_conpot,
    ]

    for parser in parsers:
        try:
            all_rows.extend(parser())
        except Exception as ex:
            print(f"[!] {parser.__name__} 오류: {ex}")

    print()
    print("=" * 55)
    write_csv(all_rows, DATASET_FIELDS, OUT_BASE / "dataset.csv")
    print()
    print(" 완료! 다음 단계:")
    print("   python3 /scripts/label_data.py")
    print("=" * 55)
