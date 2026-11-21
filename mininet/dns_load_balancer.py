#!/usr/bin/env python3
"""Small UDP DNS primary-backup load balancer with live counters."""
import argparse
import json
import os
import socket
import tempfile
import threading
import time

DEFAULT_STATS = "/var/tmp/secureiot-lb-dns-stats.json"


def probe_query(name="https.lab"):
    transaction_id = os.urandom(2)
    labels = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    return transaction_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x01\x00\x01"


class DnsLoadBalancer:
    def __init__(self, listen_host, listen_port, backends, health_timeout=1.0,
                 forward_timeout=3.0):
        self.listen_host = listen_host
        self.listen_port = int(listen_port)
        self.backends = list(backends)
        self.health_timeout = float(health_timeout)
        self.forward_timeout = float(forward_timeout)
        self.stats_file = os.environ.get("SECUREIOT_LB_STATS_FILE", DEFAULT_STATS)
        self.lock = threading.Lock()
        self.stats = {
            "requests_total": 0,
            "requests_active": 0,
            "backend_failovers": 0,
            "failure_events_total": 0,
            "recovery_events": 0,
            "active_failures": 0,
            "failed_backends": [],
            "healthy_backends": [],
            "health_checks_performed": False,
            "last_health_check": None,
            "last_backend": None,
            "listen_host": self.listen_host,
            "listen_port": self.listen_port,
            "backends": [f"{h}:{p}" for h, p in self.backends],
            "backend_requests": {f"{h}:{p}": 0 for h, p in self.backends},
            "updated_at": time.time(),
        }
        self._health_snapshot = None
        self.write_stats()

    def write_stats(self):
        directory = os.path.dirname(self.stats_file) or "."
        os.makedirs(directory, exist_ok=True)
        with self.lock:
            payload = dict(self.stats)
            payload["backends"] = list(self.stats["backends"])
            payload["backend_requests"] = dict(self.stats["backend_requests"])
            payload["updated_at"] = time.time()
        fd, tmp = tempfile.mkstemp(prefix=".dns-lb-stats.", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.stats_file)
            os.chmod(self.stats_file, 0o644)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def set_stats(self, **values):
        with self.lock:
            self.stats.update(values)
        self.write_stats()

    def health_check(self, backend):
        query = probe_query()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.health_timeout)
        try:
            sock.sendto(query, backend)
            response, _ = sock.recvfrom(4096)
            return len(response) >= 12 and response[:2] == query[:2]
        except OSError:
            return False
        finally:
            sock.close()

    def record_health_state(self, healthy):
        """Record backend transitions separately from per-request failovers."""
        healthy_ids = {f"{host}:{port}" for host, port in healthy}
        all_ids = {f"{host}:{port}" for host, port in self.backends}
        with self.lock:
            previous = self._health_snapshot
            if previous is None:
                # Count failures observed on the first check; they are not
                # healthy merely because they predate this process.
                self.stats["failure_events_total"] += len(all_ids - healthy_ids)
            else:
                self.stats["failure_events_total"] += len(previous - healthy_ids)
                self.stats["recovery_events"] += len(healthy_ids - previous)
            self._health_snapshot = set(healthy_ids)
            failed = sorted(all_ids - healthy_ids)
            self.stats["active_failures"] = len(failed)
            self.stats["failed_backends"] = failed
        self.write_stats()

    def choose_backend(self):
        healthy = [backend for backend in self.backends if self.health_check(backend)]
        self.record_health_state(healthy)
        self.set_stats(
            healthy_backends=[f"{host}:{port}" for host, port in healthy],
            health_checks_performed=True,
            last_health_check=time.time(),
        )
        if not healthy:
            return None, False
        primary = self.backends[0]
        for backend in self.backends:
            if backend in healthy:
                return backend, backend != primary
        return None, False

    def forward(self, backend, packet):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.forward_timeout)
        try:
            sock.sendto(packet, backend)
            response, _ = sock.recvfrom(65535)
            if response:
                return response
        except OSError:
            return None
        finally:
            sock.close()
        return None

    def handle(self, server, packet, client):
        with self.lock:
            self.stats["requests_total"] += 1
            self.stats["requests_active"] += 1
        self.write_stats()
        try:
            backend, is_failover = self.choose_backend()
            if backend is None:
                print(f"DNS_NO_HEALTHY_BACKEND client={client}", flush=True)
                return
            response = self.forward(backend, packet)
            if response is None and len(self.backends) > 1:
                backup = next((item for item in self.backends if item != backend), None)
                if backup is not None and self.health_check(backup):
                    backend = backup
                    response = self.forward(backend, packet)
                    is_failover = True
            if response is None:
                print(f"DNS_FORWARD_FAILED backend={backend}", flush=True)
                return
            backend_id = f"{backend[0]}:{backend[1]}"
            with self.lock:
                self.stats["last_backend"] = backend_id
                self.stats["backend_requests"][backend_id] = self.stats["backend_requests"].get(backend_id, 0) + 1
                if is_failover:
                    self.stats["backend_failovers"] += 1
            self.write_stats()
            server.sendto(response, client)
            print(f"DNS_FORWARD frontend={self.listen_port} backend={backend} client={client}", flush=True)
        finally:
            with self.lock:
                self.stats["requests_active"] -= 1
            self.write_stats()

    def serve_forever(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.listen_host, self.listen_port))
        print(
            f"DNS_LOAD_BALANCER_READY listen={self.listen_host}:{self.listen_port} "
            f"stats_file={self.stats_file}", flush=True
        )
        try:
            while True:
                packet, client = server.recvfrom(65535)
                threading.Thread(target=self.handle, args=(server, packet, client), daemon=True).start()
        finally:
            server.close()


def parse_backends(value):
    return [(host, int(port)) for host, port in (item.rsplit(":", 1) for item in value.split(","))]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=53)
    parser.add_argument("--backends", required=True)
    parser.add_argument("--health-timeout", type=float, default=1.0)
    parser.add_argument("--forward-timeout", type=float, default=3.0)
    args = parser.parse_args()
    DnsLoadBalancer(
        args.listen_host,
        args.listen_port,
        parse_backends(args.backends),
        health_timeout=args.health_timeout,
        forward_timeout=args.forward_timeout,
    ).serve_forever()


if __name__ == "__main__":
    main()
