#!/usr/bin/env python3
"""Small lab-only HTTP backend used by the Mininet demo mode.

This is deliberately a demo service, not the project's authenticated Web/API.
It accepts telemetry POSTs from the IoT simulator and returns JSON so that
traffic crosses the VLAN gateway and is visible to flow/packet collectors.
"""

import argparse
import json
import logging
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = "SecureIoTDemoStub/1.0"

    def _send_json(self, status, payload):
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/health", "/", "/healthz"):
            self._send_json(200, {
                "status": "healthy",
                "service": self.server.service_name,
                "timestamp": time.time(),
            })
            return
        self._send_json(200, {
            "status": "ok",
            "service": self.server.service_name,
            "path": self.path,
        })

    def do_POST(self):
        length_header = self.headers.get("Content-Length", "0")
        try:
            length = int(length_header)
        except ValueError:
            self._send_json(400, {"status": "error", "message": "invalid content length"})
            return
        if length < 0 or length > 65536:
            self._send_json(413, {"status": "error", "message": "payload too large"})
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"status": "error", "message": "invalid JSON"})
            return
        if not isinstance(payload, dict):
            self._send_json(400, {"status": "error", "message": "JSON object required"})
            return
        if self.path != "/api/iot/telemetry":
            self._send_json(404, {"status": "error", "message": "not found"})
            return
        if not payload.get("device_id") or not payload.get("device_role"):
            self._send_json(400, {"status": "error", "message": "device_id and device_role are required"})
            return
        telemetry = payload.get("telemetry")
        if not isinstance(telemetry, dict):
            self._send_json(400, {"status": "error", "message": "telemetry object is required"})
            return
        logging.info("telemetry service=%s device=%s role=%s fields=%s", self.server.service_name,
                     payload.get("device_id"), payload.get("device_role"), sorted(telemetry))
        self._send_json(200, {
            "status": "accepted",
            "service": self.server.service_name,
            "device_id": payload.get("device_id"),
            "received_at": time.time(),
        })

    def log_message(self, fmt, *args):
        logging.info("%s - %s", self.client_address[0], fmt % args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--name", default="secureiot-demo-service")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    server.service_name = args.name
    logging.info("starting %s on %s:%s", args.name, args.host, args.port)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
