#!/usr/bin/env python3

import http.server
import ssl
import os

SERVER_IP = os.getenv("HTTPS_SERVER_IP", "10.10.20.3")
PORT = 443

CERT_FILE = os.getenv("HTTPS_CERT_FILE", "/tmp/https_server/cert.pem")
KEY_FILE = os.getenv("HTTPS_KEY_FILE", "/tmp/https_server/key.pem")


class HTTPSHandler(http.server.SimpleHTTPRequestHandler):

    def do_GET(self):
        print(f"HTTPS request: {self.path}")
        return super().do_GET()


def main():

    server = http.server.HTTPServer(
        (SERVER_IP, PORT),
        HTTPSHandler
    )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    context.load_cert_chain(
        certfile=CERT_FILE,
        keyfile=KEY_FILE
    )

    server.socket = context.wrap_socket(
        server.socket,
        server_side=True
    )

    print(f"HTTPS server listening on {SERVER_IP}:{PORT}")

    server.serve_forever()


if __name__ == "__main__":
    main()

