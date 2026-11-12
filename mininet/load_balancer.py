#!/usr/bin/env python3
"""Small TCP load balancer with live counters."""
import argparse
import json
import os
import select
import socket
import tempfile
import threading
import time

DEFAULT_STATS = "/var/tmp/secureiot-lb-stats.json"

class TcpLoadBalancer:
    def __init__(self, listen_host, listen_port, backends, health_timeout=1.0):
        self.listen_host = listen_host
        self.listen_port = int(listen_port)
        self.backends = list(backends)
        self.health_timeout = float(health_timeout)
        self.stats_file = os.environ.get("SECUREIOT_LB_STATS_FILE", DEFAULT_STATS)
        self.lock = threading.Lock()
        self.next_backend = 0
        self.stats = {
            "requests_total": 0, "requests_active": 0,
            "bytes_in": 0, "bytes_out": 0,
            "backend_failovers": 0,
            "healthy_backends": [],
            "health_checks_performed": False,
            "last_health_check": None,
            "last_backend": None,
            "backend_requests": {
                f"{host}:{port}": 0 for host, port in self.backends
            },
            "listen_host": self.listen_host,
            "listen_port": self.listen_port,
            "backends": [f"{h}:{p}" for h, p in self.backends],
            "updated_at": time.time(),
        }
        self.write_stats()

    def write_stats(self):
        directory = os.path.dirname(self.stats_file) or "."
        os.makedirs(directory, exist_ok=True)
        with self.lock:
            data = dict(self.stats)
            data["backends"] = list(self.stats["backends"])
            data["updated_at"] = time.time()
        fd, tmp = tempfile.mkstemp(prefix=".lb-stats.", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, separators=(",", ":"))
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.stats_file)
            # The stats contain counters and health state, not credentials.
            # Mininet may launch the LB as root while the dashboard is run by
            # the normal user, so keep the atomically replaced file readable.
            os.chmod(self.stats_file, 0o644)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def update(self, **delta):
        with self.lock:
            for key, value in delta.items():
                self.stats[key] += value
        self.write_stats()

    def record_backend(self, backend):
        """Record the backend selected for one accepted client connection."""
        backend_id = f"{backend[0]}:{backend[1]}"
        with self.lock:
            self.stats["last_backend"] = backend_id
            self.stats["backend_requests"].setdefault(backend_id, 0)
            self.stats["backend_requests"][backend_id] += 1
        self.write_stats()

    def healthy(self, backend):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.health_timeout)
        try:
            sock.connect(backend)
            return True
        except OSError:
            return False
        finally:
            sock.close()

    def choose_backend(self):
        with self.lock:
            if not self.backends:
                return None
            ordered = self.backends[self.next_backend:] + self.backends[:self.next_backend]
            self.next_backend = (self.next_backend + 1) % len(self.backends)
        healthy = [backend for backend in ordered if self.healthy(backend)]
        with self.lock:
            self.stats["healthy_backends"] = [f"{host}:{port}" for host, port in healthy]
            self.stats["health_checks_performed"] = True
            self.stats["last_health_check"] = time.time()
        self.write_stats()
        for backend in ordered:
            if backend in healthy:
                return backend
        return None

    def relay(self, client, upstream):
        sockets = [client, upstream]
        try:
            while sockets:
                readable, _, exceptional = select.select(sockets, [], sockets, 30)
                if exceptional or not readable:
                    return
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    destination = upstream if source is client else client
                    destination.sendall(data)
                    self.update(**({"bytes_in": len(data)} if source is client
                                    else {"bytes_out": len(data)}))
        except OSError:
            return
        finally:
            for sock in (client, upstream):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()

    def handle(self, client, address):
        self.update(requests_total=1, requests_active=1)
        backend = self.choose_backend()
        if backend is None:
            client.close()
            self.update(requests_active=-1, backend_failovers=1)
            print(f"NO_HEALTHY_BACKEND client={address}", flush=True)
            return
        self.record_backend(backend)
        try:
            upstream = socket.create_connection(backend, timeout=self.health_timeout)
        except OSError:
            client.close()
            self.update(requests_active=-1, backend_failovers=1)
            print(f"BACKEND_CONNECT_FAILED backend={backend}", flush=True)
            return
        print(f"FORWARD listen={self.listen_port} backend={backend} client={address}", flush=True)
        try:
            self.relay(client, upstream)
        finally:
            self.update(requests_active=-1)

    def serve_forever(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.listen_host, self.listen_port))
        server.listen(128)
        print(f"LOAD_BALANCER_READY listen={self.listen_host}:{self.listen_port} stats_file={self.stats_file}", flush=True)
        try:
            while True:
                client, address = server.accept()
                threading.Thread(target=self.handle, args=(client, address), daemon=True).start()
        finally:
            server.close()

def parse_backends(value):
    return [(host, int(port)) for host, port in (item.rsplit(":", 1) for item in value.split(","))]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--backends", required=True)
    args = parser.parse_args()
    TcpLoadBalancer(args.listen_host, args.listen_port, parse_backends(args.backends)).serve_forever()

if __name__ == "__main__":
    main()
