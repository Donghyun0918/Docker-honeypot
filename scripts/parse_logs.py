#!/usr/bin/env python3
"""
parse_logs.py — 허니팟 7종 로그 파서 → auth.csv, sessions.csv, input.csv

실행 위치: kali-attacker 컨테이너 내부
사용법: python3 /scripts/parse_logs.py

출력 스키마:
  auth.csv:     timestamp, src_ip, dst_port, protocol, username, password,
                login_success, source_honeypot, label
  sessions.csv: timestamp, src_ip, dst_port, protocol, duration, login_attempts,
                login_success, source_honeypot, label
  input.csv:    timestamp, src_ip, dst_port, protocol, command,
                has_wget, has_curl, has_reverse_shell, source_honeypot, label
"""

import csv
import glob
import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path

LOG_BASE = Path("/honeypot_logs")
OUT_BASE = LOG_BASE

AUTH_FIELDS = [
    "timestamp", "src_ip", "dst_port", "protocol",
    "username", "password", "login_success", "source_honeypot", "label"
]
SESSION_FIELDS = [
    "timestamp", "src_ip", "dst_port", "protocol",
    "duration", "login_attempts", "login_success", "source_honeypot", "label"
]
INPUT_FIELDS = [
    "timestamp", "src_ip", "dst_port", "protocol", "command",
    "has_wget", "has_curl", "has_reverse_shell", "source_honeypot", "label"
]


# ── Cowrie JSON 파서 ──────────────────────────────────────────────────────────

def parse_cowrie():
    """
    Cowrie JSON lines 파싱.
    eventid 기반:
      cowrie.login.success / cowrie.login.failed  → auth rows
      cowrie.session.connect / cowrie.session.closed → session rows
      cowrie.command.input / cowrie.session.file_download → input rows
    """
    auth_rows, session_rows, input_rows = [], [], []
    sessions = {}  # sessionid → {start, src_ip, port, attempts, successes}

    log_files = sorted(glob.glob(str(LOG_BASE / "cowrie" / "cowrie.json*")))
    if not log_files:
        print("[cowrie] 로그 파일 없음, 건너뜀")
        return auth_rows, session_rows, input_rows

    for logfile in log_files:
        print(f"[cowrie] 파싱: {logfile}")
        with open(logfile, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue

                eid = e.get("eventid", "")
                ts = e.get("timestamp", "")
                sid = e.get("session", "")
                src = e.get("src_ip", "")
                port = e.get("dst_port", 2222)

                if eid in ("cowrie.login.success", "cowrie.login.failed"):
                    success = 1 if eid == "cowrie.login.success" else 0
                    auth_rows.append({
                        "timestamp": ts, "src_ip": src, "dst_port": port,
                        "protocol": "SSH", "username": e.get("username", ""),
                        "password": e.get("password", ""),
                        "login_success": success,
                        "source_honeypot": "cowrie", "label": ""
                    })
                    sess = sessions.setdefault(sid, {
                        "start": ts, "src_ip": src, "port": port,
                        "attempts": 0, "successes": 0
                    })
                    sess["attempts"] += 1
                    sess["successes"] += success

                elif eid == "cowrie.session.connect":
                    sessions.setdefault(sid, {
                        "start": ts, "src_ip": src, "port": port,
                        "attempts": 0, "successes": 0
                    })

                elif eid == "cowrie.session.closed":
                    dur = e.get("duration", 0)
                    s = sessions.get(sid, {})
                    session_rows.append({
                        "timestamp": s.get("start", ts),
                        "src_ip": s.get("src_ip", src),
                        "dst_port": s.get("port", port),
                        "protocol": "SSH",
                        "duration": round(float(dur), 3),
                        "login_attempts": s.get("attempts", 0),
                        "login_success": min(s.get("successes", 0), 1),
                        "source_honeypot": "cowrie", "label": ""
                    })

                elif eid in ("cowrie.command.input", "cowrie.session.file_download"):
                    cmd = e.get("input", e.get("url", ""))
                    input_rows.append({
                        "timestamp": ts, "src_ip": src, "dst_port": port,
                        "protocol": "SSH", "command": cmd,
                        "has_wget": int("wget" in cmd),
                        "has_curl": int("curl" in cmd),
                        "has_reverse_shell": int(any(x in cmd for x in [
                            "nc ", "/dev/tcp", "python3 -c", "python -c",
                            "bash -i", "perl -e", "ruby -r"
                        ])),
                        "source_honeypot": "cowrie", "label": ""
                    })

    print(f"[cowrie] auth={len(auth_rows)}, sessions={len(session_rows)}, input={len(input_rows)}")
    return auth_rows, session_rows, input_rows


# ── Heralding CSV 파서 ────────────────────────────────────────────────────────

def parse_heralding():
    """
    Heralding CSV 파일 파싱.
    auth.csv: timestamp,auth_id,session_id,source_ip,source_port,destination_port,protocol,username,password,status
    session.csv: timestamp,session_id,duration,source_ip,source_port,destination_port,protocol
    """
    auth_rows, session_rows = [], []

    auth_file = LOG_BASE / "heralding" / "auth.csv"
    if auth_file.exists():
        print(f"[heralding] 파싱: {auth_file}")
        with open(auth_file, encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    auth_rows.append({
                        "timestamp": row.get("timestamp", ""),
                        "src_ip": row.get("source_ip", ""),
                        "dst_port": row.get("destination_port", ""),
                        "protocol": row.get("protocol", "").upper(),
                        "username": row.get("username", ""),
                        "password": row.get("password", ""),
                        "login_success": 0,  # Heralding은 항상 인증 실패로 로깅
                        "source_honeypot": "heralding", "label": ""
                    })
                except Exception:
                    continue
    else:
        print(f"[heralding] auth.csv 없음: {auth_file}")

    session_file = LOG_BASE / "heralding" / "session.csv"
    if session_file.exists():
        print(f"[heralding] 파싱: {session_file}")
        with open(session_file, encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    session_rows.append({
                        "timestamp": row.get("timestamp", ""),
                        "src_ip": row.get("source_ip", ""),
                        "dst_port": row.get("destination_port", ""),
                        "protocol": row.get("protocol", "").upper(),
                        "duration": row.get("duration", 0),
                        "login_attempts": 1,
                        "login_success": 0,
                        "source_honeypot": "heralding", "label": ""
                    })
                except Exception:
                    continue
    else:
        print(f"[heralding] session.csv 없음: {session_file}")

    print(f"[heralding] auth={len(auth_rows)}, sessions={len(session_rows)}")
    return auth_rows, session_rows, []


# ── OpenCanary JSON 파서 ──────────────────────────────────────────────────────

def parse_opencanary():
    """
    OpenCanary JSON logs.
    logtype 코드:
      1001 = PORTSCAN
      2000 = FTP LOGIN
      6001 = RDP
      5001 = VNC
      3001 = HTTP
    """
    LOGTYPE_MAP = {
        1001: "PORTSCAN",
        2000: "FTP",
        6001: "RDP",
        5001: "VNC",
        3001: "HTTP",
        4001: "TELNET",
        9001: "SNMP",
    }

    session_rows = []
    log_files = sorted(glob.glob(str(LOG_BASE / "opencanary" / "*.log*")))
    if not log_files:
        print("[opencanary] 로그 파일 없음, 건너뜀")
        return [], session_rows, []

    for logfile in log_files:
        print(f"[opencanary] 파싱: {logfile}")
        with open(logfile, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue

                logtype = e.get("logtype", 0)
                protocol = LOGTYPE_MAP.get(logtype, f"UNKNOWN_{logtype}")
                session_rows.append({
                    "timestamp": e.get("utc_time", ""),
                    "src_ip": e.get("src_host", ""),
                    "dst_port": e.get("dst_port", 0),
                    "protocol": protocol,
                    "duration": 0,
                    "login_attempts": 0,
                    "login_success": 0,
                    "source_honeypot": "opencanary", "label": ""
                })

    print(f"[opencanary] sessions={len(session_rows)}")
    return [], session_rows, []


# ── SNARE JSON 파서 ───────────────────────────────────────────────────────────

def parse_snare():
    """
    SNARE 로그 파싱: JSON lines (*.json*) + 텍스트 로그 (snare.log)
    SNARE는 /opt/snare/snare.log 에 텍스트 형식으로 기록함
    """
    import re
    input_rows = []

    def add_row(ts, src_ip, path):
        full_cmd = path
        input_rows.append({
            "timestamp": ts,
            "src_ip": src_ip,
            "dst_port": 8080,
            "protocol": "HTTP",
            "command": path,
            "has_wget": int("wget" in full_cmd),
            "has_curl": int("curl" in full_cmd),
            "has_reverse_shell": int(any(x in full_cmd for x in [
                "nc ", "/dev/tcp", "python", "bash -i"
            ])),
            "source_honeypot": "snare", "label": ""
        })

    # JSON 형식 파일 파싱
    json_files = sorted(glob.glob(str(LOG_BASE / "snare" / "*.json*")))
    for logfile in json_files:
        print(f"[snare] 파싱(JSON): {logfile}")
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
                ts = e.get("timestamp", e.get("time", ""))
                src = e.get("peer", e.get("remote_ip", e.get("src_ip", "")))
                add_row(ts, src, path)

    # 텍스트 로그 파싱 (snare.log)
    # 형식 예: 2026-04-09 12:00:00,123 - INFO - 172.30.0.20 - GET /path HTTP/1.1
    text_log = LOG_BASE / "snare" / "snare.log"
    if text_log.exists():
        print(f"[snare] 파싱(text): {text_log}")
        pattern = re.compile(
            r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'
            r'.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            r'.*?(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)'
        )
        with open(text_log, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = pattern.search(line)
                if m:
                    ts, src_ip, method, path = m.group(1), m.group(2), m.group(3), m.group(4)
                    add_row(ts, src_ip, f"{method} {path}")

    if not json_files and not text_log.exists():
        print("[snare] 로그 파일 없음, 건너뜀")

    print(f"[snare] input={len(input_rows)}")
    return [], [], input_rows


# ── Dionaea SQLite 파서 ───────────────────────────────────────────────────────

def parse_dionaea():
    """
    Dionaea SQLite DB (logsql.sqlite) 파싱.
    WAL 모드로 열어 실행 중인 Dionaea와 충돌 방지.
    """
    auth_rows, session_rows, input_rows = [], [], []
    db_path = LOG_BASE / "dionaea" / "logsql.sqlite"

    if not db_path.exists():
        print(f"[dionaea] DB 없음: {db_path}, 건너뜀")
        return auth_rows, session_rows, input_rows

    print(f"[dionaea] 파싱: {db_path}")
    try:
        conn = sqlite3.connect(str(db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        cur = conn.cursor()

        # 연결 + 로그인 정보
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
            ts = ""
            try:
                ts = datetime.fromtimestamp(float(row["connection_timestamp"])).isoformat()
            except (TypeError, ValueError, OSError):
                ts = str(row["connection_timestamp"])

            proto = (row["connection_protocol"] or "UNKNOWN").upper()
            src = row["remote_host"] or ""
            port = row["local_port"] or 0

            if row["login_username"]:
                auth_rows.append({
                    "timestamp": ts, "src_ip": src, "dst_port": port,
                    "protocol": proto,
                    "username": row["login_username"] or "",
                    "password": row["login_password"] or "",
                    "login_success": 0,
                    "source_honeypot": "dionaea", "label": ""
                })

            session_rows.append({
                "timestamp": ts, "src_ip": src, "dst_port": port,
                "protocol": proto, "duration": 0,
                "login_attempts": 1 if row["login_username"] else 0,
                "login_success": 0,
                "source_honeypot": "dionaea", "label": ""
            })

        # 다운로드된 파일 (malware) → input rows
        try:
            cur.execute("SELECT * FROM downloads")
            for row in cur.fetchall():
                input_rows.append({
                    "timestamp": str(row["download_md5_hash"] or ""),
                    "src_ip": "", "dst_port": 0,
                    "protocol": "SMB",
                    "command": str(dict(row)),
                    "has_wget": 0, "has_curl": 0, "has_reverse_shell": 0,
                    "source_honeypot": "dionaea", "label": ""
                })
        except sqlite3.OperationalError:
            pass  # downloads 테이블 없음

        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"[dionaea] DB 오류: {e}")

    print(f"[dionaea] auth={len(auth_rows)}, sessions={len(session_rows)}, input={len(input_rows)}")
    return auth_rows, session_rows, input_rows


# ── Mailoney JSON 파서 ────────────────────────────────────────────────────────

def parse_mailoney():
    """Mailoney JSON lines: SMTP 스팸/피싱 로그"""
    auth_rows = []
    log_files = sorted(glob.glob(str(LOG_BASE / "mailoney" / "*.json*")))
    if not log_files:
        print("[mailoney] 로그 파일 없음, 건너뜀")
        return auth_rows, [], []

    for logfile in log_files:
        print(f"[mailoney] 파싱: {logfile}")
        with open(logfile, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue

                auth_rows.append({
                    "timestamp": e.get("timestamp", e.get("time", "")),
                    "src_ip": e.get("src_ip", e.get("remote_ip", e.get("ip", ""))),
                    "dst_port": 25,
                    "protocol": "SMTP",
                    "username": e.get("username", e.get("user", "")),
                    "password": e.get("password", e.get("pass", "")),
                    "login_success": 0,
                    "source_honeypot": "mailoney", "label": ""
                })

    print(f"[mailoney] auth={len(auth_rows)}")
    return auth_rows, [], []


# ── Conpot JSON 파서 ──────────────────────────────────────────────────────────

def parse_conpot():
    """Conpot JSON lines: ICS/SCADA 연결 로그"""
    session_rows = []
    log_files = sorted(glob.glob(str(LOG_BASE / "conpot" / "*.json*")))
    if not log_files:
        print("[conpot] 로그 파일 없음, 건너뜀")
        return [], session_rows, []

    for logfile in log_files:
        print(f"[conpot] 파싱: {logfile}")
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
                local = e.get("local", {})
                session_rows.append({
                    "timestamp": e.get("timestamp", ""),
                    "src_ip": remote.get("ip", e.get("remote_ip", "")),
                    "dst_port": local.get("port", e.get("local_port", 0)),
                    "protocol": e.get("data_type", e.get("type", "ICS")).upper(),
                    "duration": e.get("session_length", e.get("duration", 0)),
                    "login_attempts": 0,
                    "login_success": 0,
                    "source_honeypot": "conpot", "label": ""
                })

    print(f"[conpot] sessions={len(session_rows)}")
    return [], session_rows, []


# ── CSV 쓰기 ──────────────────────────────────────────────────────────────────

def write_csv(rows, fields, path):
    """결측 키를 빈 문자열로 채우고 CSV로 저장"""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            # 누락된 필드를 빈 문자열로 채움
            writer.writerow({field: row.get(field, "") for field in fields})
    print(f"[output] {len(rows)}행 → {path}")


# ── 메인 ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print(" 허니팟 로그 파서 시작")
    print(f" LOG_BASE: {LOG_BASE}")
    print("=" * 50)

    all_auth, all_sessions, all_inputs = [], [], []

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
            a, s, i = parser()
            all_auth.extend(a)
            all_sessions.extend(s)
            all_inputs.extend(i)
        except Exception as ex:
            print(f"[!] {parser.__name__} 파서 오류: {ex}")

    print("")
    print("=" * 50)
    print(" 결과 저장 중...")
    write_csv(all_auth,     AUTH_FIELDS,    OUT_BASE / "auth.csv")
    write_csv(all_sessions, SESSION_FIELDS, OUT_BASE / "sessions.csv")
    write_csv(all_inputs,   INPUT_FIELDS,   OUT_BASE / "input.csv")

    print("")
    print(" 완료! 다음 단계:")
    print("   python3 /scripts/label_data.py")
    print("=" * 50)
