#!/usr/bin/env python3
"""
Simple SMTP honeypot — 포트 25
ML 데이터 수집용: SMTP 연결, AUTH 시도, 메일 내용을 JSON으로 로깅
"""

import asyncio
import json
import datetime
import os

LOG_FILE = os.environ.get("LOG_FILE", "/var/log/mailoney/mailoney.json")


def log_event(src_ip, src_port, event_type, data=None):
    entry = {
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": 25,
        "protocol": "SMTP",
        "event": event_type,
    }
    if data:
        entry.update(data)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[SMTP] {src_ip}:{src_port} {event_type}", flush=True)


async def handle_smtp(reader, writer):
    peer = writer.get_extra_info("peername") or ("unknown", 0)
    src_ip, src_port = peer[0], peer[1]

    log_event(src_ip, src_port, "connect")

    username = ""
    password = ""
    mail_from = ""
    rcpt_to = []

    try:
        # 배너 전송
        writer.write(b"220 mail.example.com ESMTP Postfix\r\n")
        await writer.drain()

        while True:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=30.0)
            except asyncio.TimeoutError:
                break
            if not line:
                break

            cmd = line.decode("utf-8", errors="replace").strip()
            cmd_upper = cmd.upper()

            if cmd_upper.startswith("EHLO") or cmd_upper.startswith("HELO"):
                writer.write(
                    b"250-mail.example.com\r\n"
                    b"250-SIZE 10240000\r\n"
                    b"250-AUTH LOGIN PLAIN\r\n"
                    b"250 STARTTLS\r\n"
                )

            elif cmd_upper.startswith("AUTH LOGIN"):
                writer.write(b"334 VXNlcm5hbWU6\r\n")  # Base64("Username:")
                await writer.drain()
                user_line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                import base64
                try:
                    username = base64.b64decode(user_line.strip()).decode("utf-8", errors="replace")
                except Exception:
                    username = user_line.decode("utf-8", errors="replace").strip()

                writer.write(b"334 UGFzc3dvcmQ6\r\n")  # Base64("Password:")
                await writer.drain()
                pass_line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                try:
                    password = base64.b64decode(pass_line.strip()).decode("utf-8", errors="replace")
                except Exception:
                    password = pass_line.decode("utf-8", errors="replace").strip()

                log_event(src_ip, src_port, "auth_attempt", {
                    "username": username, "password": password
                })
                writer.write(b"535 5.7.8 Authentication credentials invalid\r\n")

            elif cmd_upper.startswith("AUTH PLAIN"):
                import base64
                parts = cmd.split(" ", 2)
                if len(parts) == 3:
                    try:
                        decoded = base64.b64decode(parts[2]).decode("utf-8", errors="replace")
                        creds = decoded.split("\x00")
                        username = creds[1] if len(creds) > 1 else ""
                        password = creds[2] if len(creds) > 2 else ""
                    except Exception:
                        pass
                else:
                    writer.write(b"334 \r\n")
                    await writer.drain()
                    cred_line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                    try:
                        decoded = base64.b64decode(cred_line.strip()).decode("utf-8", errors="replace")
                        creds = decoded.split("\x00")
                        username = creds[1] if len(creds) > 1 else ""
                        password = creds[2] if len(creds) > 2 else ""
                    except Exception:
                        pass

                log_event(src_ip, src_port, "auth_attempt", {
                    "username": username, "password": password
                })
                writer.write(b"535 5.7.8 Authentication credentials invalid\r\n")

            elif cmd_upper.startswith("MAIL FROM"):
                mail_from = cmd
                writer.write(b"250 2.1.0 Ok\r\n")

            elif cmd_upper.startswith("RCPT TO"):
                rcpt_to.append(cmd)
                writer.write(b"550 5.1.1 User unknown\r\n")

            elif cmd_upper.startswith("DATA"):
                writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                await writer.drain()
                body_lines = []
                while True:
                    dline = await asyncio.wait_for(reader.readline(), timeout=30.0)
                    if dline.strip() == b".":
                        break
                    body_lines.append(dline.decode("utf-8", errors="replace").strip())
                log_event(src_ip, src_port, "mail_data", {
                    "mail_from": mail_from,
                    "rcpt_to": rcpt_to,
                    "body_lines": len(body_lines),
                })
                writer.write(b"550 5.7.1 Relay access denied\r\n")

            elif cmd_upper.startswith("QUIT"):
                writer.write(b"221 2.0.0 Bye\r\n")
                await writer.drain()
                break

            else:
                writer.write(b"502 5.5.2 Error: command not recognized\r\n")

            await writer.drain()

    except (asyncio.TimeoutError, ConnectionResetError, OSError):
        pass
    finally:
        log_event(src_ip, src_port, "disconnect")
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main():
    server = await asyncio.start_server(handle_smtp, "0.0.0.0", 25)
    print("SMTP Honeypot started on 0.0.0.0:25", flush=True)
    print(f"Log file: {LOG_FILE}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
