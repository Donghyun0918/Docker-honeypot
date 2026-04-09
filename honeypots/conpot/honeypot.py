#!/usr/bin/env python3
"""
Simple ICS/SCADA honeypot — Modbus TCP (502), S7comm (102), SNMP UDP (161)
ML 데이터 수집용: 연결 시도를 JSON으로 로깅
"""

import asyncio
import json
import socket
import datetime
import os

LOG_FILE = os.environ.get("LOG_FILE", "/var/log/conpot/conpot.json")


def log_event(src_ip, src_port, dst_port, protocol, data_len=0):
    entry = {
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "remote": {"ip": src_ip, "port": src_port},
        "local": {"port": dst_port},
        "data_type": protocol,
        "session_length": 0,
        "request_bytes": data_len,
    }
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[{protocol}] {src_ip}:{src_port} -> :{dst_port}", flush=True)


def make_tcp_handler(protocol, dst_port):
    async def handler(reader, writer):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        src_ip, src_port = peer[0], peer[1]
        data_len = 0
        try:
            data = await asyncio.wait_for(reader.read(512), timeout=5.0)
            data_len = len(data)
            if protocol == "MODBUS" and len(data) >= 8:
                tid = data[0:2]
                mbap = tid + b"\x00\x00\x00\x03"
                pdu = bytes([data[7] | 0x80, 0x02])
                writer.write(mbap + pdu)
                await writer.drain()
        except (asyncio.TimeoutError, ConnectionResetError, OSError):
            pass
        finally:
            log_event(src_ip, src_port, dst_port, protocol, data_len)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    return handler


class SnmpProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data, addr):
        src_ip, src_port = addr
        log_event(src_ip, src_port, 161, "SNMP", len(data))


async def main():
    modbus = await asyncio.start_server(
        make_tcp_handler("MODBUS", 502), "0.0.0.0", 502
    )
    s7 = await asyncio.start_server(
        make_tcp_handler("S7COMM", 102), "0.0.0.0", 102
    )

    loop = asyncio.get_event_loop()
    snmp_transport, _ = await loop.create_datagram_endpoint(
        SnmpProtocol,
        local_addr=("0.0.0.0", 161),
        family=socket.AF_INET,
    )

    print("ICS/SCADA Honeypot started:", flush=True)
    print("  Modbus TCP  : 0.0.0.0:502", flush=True)
    print("  S7comm TCP  : 0.0.0.0:102", flush=True)
    print("  SNMP UDP    : 0.0.0.0:161", flush=True)
    print(f"  Log file    : {LOG_FILE}", flush=True)

    try:
        async with modbus, s7:
            await asyncio.gather(
                modbus.serve_forever(),
                s7.serve_forever(),
            )
    finally:
        snmp_transport.close()


if __name__ == "__main__":
    asyncio.run(main())
