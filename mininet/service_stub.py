#!/usr/bin/env python3
"""Minimal HTTP service used only for local Mininet service/failover tests."""

import argparse
import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = "SecureIoTService/1.0"

    def do_GET(self):
        body = {
            "service": self.server.service_name,
            "host": self.server.server_address[0],
            "path": self.path,
            "status": "healthy",
        }
        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(length)
        body = {
            "service": self.server.service_name,
            "status": "received",
            "bytes": len(data),
            "path": self.path,
        }
        if self.path == "/api/iot/telemetry":
            try:
                telemetry = json.loads(data.decode("utf-8"))
                record = {
                    "received_at": datetime.now(timezone.utc).isoformat(),
                    "source_ip": self.client_address[0],
                    "payload": telemetry,
                }
                log_path = os.environ.get("IOT_TELEMETRY_LOG", "/tmp/secureiot_iot_telemetry.jsonl")
                with open(log_path, "a", encoding="utf-8") as log_file:
                    log_file.write(json.dumps(record, separators=(",", ":")) + "\n")
                device_id = telemetry.get("device_id", "unknown") if isinstance(telemetry, dict) else "unknown"
                print(f"IOT_TELEMETRY_RECEIVED device={device_id} source={self.client_address[0]} bytes={len(data)} log={log_path}", flush=True)
                body["telemetry_recorded"] = True
            except (UnicodeDecodeError, json.JSONDecodeError, OSError) as exc:
                body["telemetry_recorded"] = False
                body["error"] = str(exc)
        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        print(f"[{self.server.service_name}] {fmt % args}", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--name", required=True)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.service_name = args.name
    print(f"SERVICE_READY {args.name} {args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
