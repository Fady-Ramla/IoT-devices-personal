#!/usr/bin/env python3
"""Small TCP load balancer for the Mininet demonstration.

It performs TCP health checks and forwards each connection to the first healthy
backend. The same implementation works for plain HTTP/API and TLS passthrough;
TLS termination is intentionally not performed here.
"""

import argparse
import select
import socket
import threading
import time


class TcpLoadBalancer:
    def __init__(self, listen_host, listen_port, backends, health_timeout=1.0):
        self.listen_host = listen_host
        self.listen_port = int(listen_port)
        self.backends = list(backends)
        self.health_timeout = float(health_timeout)
        self._lock = threading.Lock()
        self._next = 0

    def healthy(self, backend):
        host, port = backend
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.health_timeout)
        try:
            sock.connect((host, port))
            return True
        except OSError:
            return False
        finally:
            sock.close()

    def choose_backend(self):
        with self._lock:
            if not self.backends:
                return None
            ordered = self.backends[self._next:] + self.backends[:self._next]
            self._next = (self._next + 1) % len(self.backends)
        for backend in ordered:
            if self.healthy(backend):
                return backend
        return None

    @staticmethod
    def relay(left, right):
        sockets = [left, right]
        try:
            while sockets:
                readable, _, exceptional = select.select(sockets, [], sockets, 30)
                if exceptional:
                    break
                if not readable:
                    break
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    destination = right if source is left else left
                    destination.sendall(data)
        except OSError:
            pass
        finally:
            for sock in (left, right):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()

    def handle(self, client, address):
        backend = self.choose_backend()
        if backend is None:
            client.close()
            print(f"NO_HEALTHY_BACKEND listen={self.listen_port} client={address}", flush=True)
            return
        try:
            upstream = socket.create_connection(backend, timeout=self.health_timeout)
        except OSError:
            client.close()
            print(f"BACKEND_CONNECT_FAILED backend={backend}", flush=True)
            return
        print(f"FORWARD listen={self.listen_port} backend={backend} client={address}", flush=True)
        self.relay(client, upstream)

    def serve_forever(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.listen_host, self.listen_port))
        server.listen(128)
        print(
            f"LOAD_BALANCER_READY listen={self.listen_host}:{self.listen_port} "
            f"backends={self.backends}",
            flush=True,
        )
        try:
            while True:
                client, address = server.accept()
                threading.Thread(
                    target=self.handle,
                    args=(client, address),
                    daemon=True,
                ).start()
        finally:
            server.close()


def parse_backends(value):
    result = []
    for item in value.split(","):
        host, port = item.rsplit(":", 1)
        result.append((host, int(port)))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--backends", required=True)
    args = parser.parse_args()
    TcpLoadBalancer(
        args.listen_host,
        args.listen_port,
        parse_backends(args.backends),
    ).serve_forever()


if __name__ == "__main__":
    main()
