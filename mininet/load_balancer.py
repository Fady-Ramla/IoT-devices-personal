#!/usr/bin/env python3
"""Small dependency-free TCP load balancer for the SecureIoT Mininet PoC.

Port 5000 and 443 are proxied independently. Backends are health-checked with
TCP connect; dead backends are removed and restored automatically.
"""
import os
import socket
import threading
import time

CHECK_INTERVAL = float(os.getenv("LB_CHECK_INTERVAL", "2"))
LISTEN = {5000: [("10.10.20.2", 5000), ("10.10.20.8", 5000)],
          443: [("10.10.20.3", 443), ("10.10.20.8", 443)]}

class Pool:
    def __init__(self, backends):
        self.backends = backends
        self.healthy = set()
        self.index = 0
        self.lock = threading.Lock()

    def check(self):
        healthy = set()
        for backend in self.backends:
            try:
                with socket.create_connection(backend, timeout=0.7):
                    healthy.add(backend)
            except OSError:
                pass
        with self.lock:
            changed = healthy != self.healthy
            self.healthy = healthy
        if changed:
            print("[lb] health update:", sorted(healthy), flush=True)

    def next(self):
        with self.lock:
            choices = sorted(self.healthy)
            if not choices:
                return None
            backend = choices[self.index % len(choices)]
            self.index += 1
            return backend


def pump(source, target):
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            target.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (source, target):
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass


def serve(port, pool):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(128)
    print("[lb] listening on", port, flush=True)
    while True:
        client, address = listener.accept()
        backend = pool.next()
        if backend is None:
            client.close()
            print("[lb] no healthy backend for", port, address, flush=True)
            continue
        threading.Thread(target=proxy, args=(client, backend, port), daemon=True).start()


def proxy(client, backend, port):
    try:
        upstream = socket.create_connection(backend, timeout=2)
        upstream.settimeout(None)
        client.settimeout(None)
        a = threading.Thread(target=pump, args=(client, upstream), daemon=True)
        b = threading.Thread(target=pump, args=(upstream, client), daemon=True)
        a.start(); b.start(); a.join(); b.join()
    except OSError as exc:
        print("[lb] backend error", port, backend, exc, flush=True)
    finally:
        for sock in (client, locals().get("upstream")):
            if sock:
                try: sock.close()
                except OSError: pass


def main():
    pools = {port: Pool(backends) for port, backends in LISTEN.items()}
    for pool in pools.values():
        pool.check()
    def health_loop():
        while True:
            for pool in pools.values(): pool.check()
            time.sleep(CHECK_INTERVAL)
    threading.Thread(target=health_loop, daemon=True).start()
    for port, pool in pools.items():
        threading.Thread(target=serve, args=(port, pool), daemon=True).start()
    while True: time.sleep(3600)

if __name__ == "__main__":
    main()

