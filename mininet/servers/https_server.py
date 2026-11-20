#!/usr/bin/env python3
import http.server
import os
import ssl

SERVER_IP = os.getenv("HTTPS_SERVER_IP", "10.10.20.3")
PORT = int(os.getenv("HTTPS_SERVER_PORT", "443"))
CERT_FILE = os.getenv("HTTPS_CERT_FILE", "/tmp/https_server/cert.pem")
KEY_FILE = os.getenv("HTTPS_KEY_FILE", "/tmp/https_server/key.pem")
WEB_ROOT = os.getenv("HTTPS_WEB_ROOT", "/tmp/secureiot-https-web")
BACKEND_NAME = os.getenv("HTTPS_BACKEND_NAME", SERVER_IP)


class HTTPSHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_ROOT, **kwargs)

    def do_GET(self):
        print(f"HTTPS request: {self.path} backend={BACKEND_NAME}", flush=True)
        return super().do_GET()

    def list_directory(self, path):
        self.send_error(403, "Directory listing disabled")
        return None

    def log_message(self, fmt, *args):
        print("[https] " + fmt % args, flush=True)


def main():
    os.makedirs(WEB_ROOT, exist_ok=True)
    server = http.server.ThreadingHTTPServer((SERVER_IP, PORT), HTTPSHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(
        f"HTTPS server listening on {SERVER_IP}:{PORT} "
        f"backend={BACKEND_NAME} web_root={WEB_ROOT}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
