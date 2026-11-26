#!/usr/bin/env python3
import http.server
import os
import ssl
import json
from urllib.parse import urlsplit

SERVER_IP = os.getenv("HTTPS_SERVER_IP", "10.10.20.3")
PORT = int(os.getenv("HTTPS_SERVER_PORT", "443"))
CERT_FILE = os.getenv("HTTPS_CERT_FILE", "/tmp/https_server/cert.pem")
KEY_FILE = os.getenv("HTTPS_KEY_FILE", "/tmp/https_server/key.pem")


class HTTPSHandler(http.server.BaseHTTPRequestHandler):
    server_version = "SecureIoTHTTPS/1.0"
    sys_version = ""

    def _send_response(self, status, content_type, body, include_body=True):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()

        if include_body:
            self.wfile.write(body)

        self.close_connection = True

    def _handle_request(self, include_body=True):
        route = urlsplit(self.path).path

        if route == "/":
            body = b"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureIoT HTTPS Service</title>
</head>
<body>
<h1>SecureIoT HTTPS Service</h1>
<p>The HTTPS backend is running.</p>
</body>
</html>
"""
            self._send_response(
                200, "text/html; charset=utf-8", body, include_body
            )

        elif route == "/health":
            body = json.dumps({
                "service": os.getenv(
                    "HTTPS_SERVICE_NAME", "secureiot-https"
                ),
                "status": "healthy",
                "backend": SERVER_IP,
            }).encode("utf-8")

            self._send_response(
                200, "application/json", body, include_body
            )

        else:
            body = b'{"status":"not_found"}'
            self._send_response(
                404, "application/json", body, include_body
            )

    def do_GET(self):
        self._handle_request(include_body=True)

    def do_HEAD(self):
        self._handle_request(include_body=False)

    def do_POST(self):
        body = b'{"status":"method_not_allowed"}'
        self.send_response(405)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, fmt, *args):
        print("[https] " + fmt % args, flush=True)


def main():
    if not os.path.isfile(CERT_FILE):
        raise FileNotFoundError("HTTPS certificate not found: " + CERT_FILE)

    if not os.path.isfile(KEY_FILE):
        raise FileNotFoundError("HTTPS private key not found: " + KEY_FILE)

    server = http.server.ThreadingHTTPServer(
        (SERVER_IP, PORT), HTTPSHandler
    )
    server.daemon_threads = True

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    server.socket = context.wrap_socket(
        server.socket, server_side=True
    )

    print(
        f"SecureIoT HTTPS server listening on {SERVER_IP}:{PORT}",
        flush=True,
    )

    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
