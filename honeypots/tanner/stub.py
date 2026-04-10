#!/usr/bin/env python3
"""
tanner_stub.py — SNARE가 필요로 하는 최소 Tanner API 스텁
SNARE는 공격 이벤트를 tanner로 POST하고 응답을 받아 로깅한다.
"""
import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

class TannerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"version": "0.6.0"}).encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            data = json.loads(body)
            logging.info("SNARE event: path=%s data=%s", self.path, json.dumps(data)[:200])
        except Exception:
            pass
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        # SNARE expects a detection type response
        resp = {"response": {"message": {"detection": {"type": 0}}}}
        self.wfile.write(json.dumps(resp).encode())

    def log_message(self, fmt, *args):
        pass  # suppress default access log

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8090), TannerHandler)
    logging.info("Tanner stub listening on port 8090")
    server.serve_forever()
