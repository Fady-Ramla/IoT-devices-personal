#!/usr/bin/env python3
"""Local JSON receiver for testing Ryu outbound flow delivery without an AI model."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/predict":
            self.send_json(404, {"received": False, "error": "unknown path"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeError):
            self.send_json(400, {"received": False, "error": "invalid JSON"})
            return
        if not isinstance(payload, dict) or not isinstance(payload.get("features"), dict) or not isinstance(payload.get("context"), dict):
            self.send_json(400, {"received": False, "error": "expected features and context objects"})
            return
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True), flush=True)
        self.send_json(202, {"received": True})

    def send_json(self, status, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("mock receiver: " + (fmt % args), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="listen address (default: localhost only)")
    parser.add_argument("--port", type=int, default=5001)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Receiver)
    print("Mock AI receiver listening at http://%s:%d/predict" % (args.host, args.port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping mock AI receiver", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
