#!/usr/bin/env python3
"""SecureIoT TCP/UDP service proxy with Security-driven backend exclusion.

Frontends: HTTP/API 5000, HTTPS 443, SSH 22, DNS UDP+TCP 53.
Ryu atomically publishes blocked backend IPs in SECUREIOT_LB_STATE_FILE.
The same program can run as the gateway fallback using LB_LISTEN_IP=10.10.20.100
and LB_HEARTBEAT_ENABLED=0.
"""
import json
import os
import socket
import threading
import time

CHECK_INTERVAL = max(0.5, float(os.getenv("LB_CHECK_INTERVAL", "2")))
STATE_POLL_INTERVAL = max(0.1, float(os.getenv("LB_STATE_POLL_INTERVAL", "0.5")))
STATE_FILE = os.getenv("SECUREIOT_LB_STATE_FILE", "/tmp/secureiot_lb_state.json")
HEARTBEAT_FILE = os.getenv("SECUREIOT_LB_HEARTBEAT_FILE", "/tmp/secureiot_lb_heartbeat.json")
LISTEN_IP = os.getenv("LB_LISTEN_IP", "0.0.0.0")
HEARTBEAT_ENABLED = os.getenv("LB_HEARTBEAT_ENABLED", "1") == "1"

DEFAULT_HTTP = "10.10.20.2:5000,10.10.20.8:5000"
DEFAULT_HTTPS = "10.10.20.3:443,10.10.20.19:443"
DEFAULT_SSH = "10.10.20.4:22,10.10.20.20:22"
DEFAULT_DNS = "10.10.30.2:53,10.10.30.17:53"

DNS_HEALTH_QUERY = (
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x07example\x03com\x00\x00\x01\x00\x01"
)


def parse_backends(value):
    """Parse comma-separated IPv4 host:port backend entries."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("backend list must be a non-empty string")

    result = []
    for item in value.split(","):
        item = item.strip()
        if not item or item.count(":") != 1:
            raise ValueError("backend must use host:port format")
        host, port_text = item.rsplit(":", 1)
        if not host.strip():
            raise ValueError("backend host is empty")
        try:
            port = int(port_text)
        except (TypeError, ValueError):
            raise ValueError("backend port must be an integer")
        if not 1 <= port <= 65535:
            raise ValueError("backend port is outside the valid range")
        result.append((host.strip(), port))
    if not result:
        raise ValueError("backend list is empty")
    return result


def dns_bind_address(cli_address=None):
    """Return the internal DNS frontend address on h38."""
    if cli_address:
        return cli_address
    return os.getenv("LB_DNS_BIND_ADDRESS", "10.10.20.100")


# All four declared service pairs from vlan_config_38host.py.
TCP_LISTEN = {
    5000: [("10.10.20.2", 5000), ("10.10.20.8", 5000)],
    443:  [("10.10.20.3", 443), ("10.10.20.19", 443)],
    22:   [("10.10.20.4", 22), ("10.10.20.20", 22)],
    53:   [("10.10.30.2", 53), ("10.10.30.17", 53)],
}
UDP_LISTEN = {
    53: [("10.10.30.2", 53), ("10.10.30.17", 53)],
}

BLOCKED_IPS = set()
BLOCKED_LOCK = threading.RLock()
READY_ENDPOINTS = set()
READY_LOCK = threading.RLock()
EXPECTED_ENDPOINTS = ({("tcp", port) for port in TCP_LISTEN}
                      | {("udp", port) for port in UDP_LISTEN})


def _atomic_json(path, payload):
    temporary = path + ".tmp.%d" % os.getpid()
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def load_blocked_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        values = payload.get("blocked_backends", [])
        if not isinstance(values, list):
            raise ValueError("blocked_backends must be a list")
        return {str(value) for value in values}
    except FileNotFoundError:
        return set()
    except (OSError, ValueError, TypeError, AttributeError):
        # A malformed existing state file must not silently re-enable servers.
        return {backend[0] for pool in list(TCP_LISTEN.values()) + list(UDP_LISTEN.values())
                for backend in pool}


def state_loop():
    global BLOCKED_IPS
    last_signature = None
    while True:
        try:
            stat = os.stat(STATE_FILE)
            signature = (stat.st_mtime_ns, stat.st_size)
        except OSError:
            signature = None
        if signature is not None and signature != last_signature:
            last_signature = signature
            refreshed = load_blocked_state()
            with BLOCKED_LOCK:
                changed = refreshed != BLOCKED_IPS
                BLOCKED_IPS = refreshed
            if changed:
                print("[lb] Security blocked backends:", sorted(refreshed), flush=True)
        time.sleep(STATE_POLL_INTERVAL)


def blocked_snapshot():
    with BLOCKED_LOCK:
        return set(BLOCKED_IPS)


def _dns_probe(sock):
    # A tiny A query for example.com. A response proves the UDP DNS backend works.
    query = DNS_HEALTH_QUERY
    sock.send(query)
    response = sock.recv(4096)
    return len(response) >= 12 and response[:2] == query[:2]



class Pool:
    def __init__(self, backends, protocol="tcp",
                 failure_threshold=None, recovery_threshold=None):
        self.backends = tuple(backends)
        self.protocol = protocol
        self.failure_threshold = max(
            1, int(failure_threshold or os.getenv("LB_FAILURE_THRESHOLD", "2"))
        )
        self.recovery_threshold = max(
            1, int(recovery_threshold or os.getenv("LB_RECOVERY_THRESHOLD", "1"))
        )
        self.healthy = set()
        self.index = 0
        self.lock = threading.RLock()
        self._failures = {backend: 0 for backend in self.backends}
        self._successes = {backend: 0 for backend in self.backends}

    def candidates(self):
        blocked = blocked_snapshot()
        with self.lock:
            return [
                backend for backend in self.backends
                if backend in self.healthy and backend[0] not in blocked
            ]

    def mark_failed(self, backend):
        with self.lock:
            self.healthy.discard(backend)
            self._failures[backend] = self.failure_threshold
            self._successes[backend] = 0

    def check(self):
        blocked = blocked_snapshot()
        for backend in self.backends:
            if backend[0] in blocked:
                with self.lock:
                    self.healthy.discard(backend)
                    self._successes[backend] = 0
                continue

            ok = False
            try:
                if self.protocol == "udp":
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                        probe.settimeout(0.7)
                        probe.connect(backend)
                        ok = _dns_probe(probe)
                else:
                    with socket.create_connection(backend, timeout=0.7):
                        ok = True
            except OSError:
                ok = False

            with self.lock:
                if ok:
                    self._failures[backend] = 0
                    self._successes[backend] = self._successes.get(backend, 0) + 1
                    if self._successes[backend] >= self.recovery_threshold:
                        self.healthy.add(backend)
                else:
                    self._successes[backend] = 0
                    self._failures[backend] = self._failures.get(backend, 0) + 1
                    if self._failures[backend] >= self.failure_threshold:
                        self.healthy.discard(backend)

        with self.lock:
            current = set(self.healthy)
        print("[lb] %s health update: %s" %
              (self.protocol, sorted(current)), flush=True)

    def next(self):
        choices = self.candidates()
        if not choices:
            return None
        with self.lock:
            selected = choices[self.index % len(choices)]
            self.index += 1
            return selected


class DNSPool(Pool):
    def __init__(self, backends, failure_threshold=1, recovery_threshold=1):
        super().__init__(
            backends,
            protocol="udp",
            failure_threshold=failure_threshold,
            recovery_threshold=recovery_threshold,
        )


def pump(source, target):
    """Copy one direction and propagate EOF only to the target write side."""
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            target.sendall(data)
    except OSError:
        pass
    finally:
        # Do not shutdown source.SHUT_WR here.
        # The opposite pump still needs to write responses through source.
        try:
            target.shutdown(socket.SHUT_WR)
        except OSError:
            pass



def proxy(client, pool, port):
    """Proxy one TCP client, trying healthy backends in configured order."""
    upstream = None
    selected = None

    for backend in pool.candidates():
        try:
            upstream = socket.create_connection(backend, timeout=2)
            selected = backend
            break
        except OSError as exc:
            print("[lb] TCP connect failed port=%s backend=%s error=%s" %
                  (port, backend, exc), flush=True)
            pool.mark_failed(backend)

    if upstream is None:
        try:
            client.close()
        except OSError:
            pass
        return

    try:
        upstream.settimeout(None)
        client.settimeout(None)
        left = threading.Thread(target=pump, args=(client, upstream), daemon=True)
        right = threading.Thread(target=pump, args=(upstream, client), daemon=True)
        left.start()
        right.start()
        left.join()
        right.join()
    except OSError as exc:
        print("[lb] TCP proxy error port=%s backend=%s error=%s" %
              (port, selected, exc), flush=True)
    finally:
        for sock in (client, upstream):
            try:
                sock.close()
            except OSError:
                pass


def proxy_tcp(client, backend, port):
    """Compatibility wrapper for callers that already selected a backend."""
    class _SelectedPool:
        def candidates(self):
            return [backend]
        def mark_failed(self, _backend):
            return None

    proxy(client, _SelectedPool(), port)



def serve_tcp(port, pool, bind_ip=None):
    address = bind_ip or (dns_bind_address() if port == 53 else LISTEN_IP)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, port))
    listener.listen(128)
    print("[lb] TCP listening on %s:%d" % (address, port), flush=True)
    with READY_LOCK:
        READY_ENDPOINTS.add(("tcp", port))
    try:
        while True:
            client, peer = listener.accept()
            threading.Thread(
                target=proxy, args=(client, pool, port), daemon=True
            ).start()
    finally:
        with READY_LOCK:
            READY_ENDPOINTS.discard(("tcp", port))
        listener.close()


def forward_dns(query, client_address, client_socket, pool, timeout=1.0):
    """Forward a DNS query; reject mismatched transaction IDs and try backup."""
    if not isinstance(query, bytes) or len(query) < 12:
        return False

    for backend in pool.candidates():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
                upstream.settimeout(timeout)
                upstream.sendto(query, backend)
                response, _ = upstream.recvfrom(65535)

            valid = (
                len(response) >= 12
                and response[:2] == query[:2]
                and bool(response[2] & 0x80)
            )
            if not valid:
                print("[lb] rejected invalid DNS response from %s" %
                      (backend,), flush=True)
                pool.mark_failed(backend)
                continue

            client_socket.sendto(response, client_address)
            return True
        except OSError as exc:
            print("[lb] DNS backend failed %s: %s" %
                  (backend, exc), flush=True)
            pool.mark_failed(backend)

    return False


def serve_udp(port, pool, bind_ip=None):
    address = bind_ip or (dns_bind_address() if port == 53 else LISTEN_IP)
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, port))
    print("[lb] UDP listening on %s:%d" % (address, port), flush=True)
    with READY_LOCK:
        READY_ENDPOINTS.add(("udp", port))
    try:
        while True:
            data, peer = listener.recvfrom(65535)
            if port == 53:
                threading.Thread(
                    target=forward_dns,
                    args=(data, peer, listener, pool),
                    daemon=True,
                ).start()
                continue

            backend = pool.next()
            if backend is None:
                continue
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
                    upstream.settimeout(2.0)
                    upstream.sendto(data, backend)
                    response, _ = upstream.recvfrom(65535)
                listener.sendto(response, peer)
            except OSError as exc:
                print("[lb] UDP backend error port=%d backend=%s error=%s" %
                      (port, backend, exc), flush=True)
                pool.mark_failed(backend)
    finally:
        with READY_LOCK:
            READY_ENDPOINTS.discard(("udp", port))
        listener.close()


def heartbeat_loop():
    """Publish liveness only while every required frontend socket is bound."""
    while True:
        with READY_LOCK:
            ready = EXPECTED_ENDPOINTS.issubset(READY_ENDPOINTS)
        if ready:
            try:
                _atomic_json(HEARTBEAT_FILE, {"pid": os.getpid(), "timestamp": time.time()})
            except OSError as exc:
                print("[lb] heartbeat write failed: %s" % exc, flush=True)
        time.sleep(1.0)


def main():
    global BLOCKED_IPS
    BLOCKED_IPS = load_blocked_state()
    threading.Thread(target=state_loop, daemon=True).start()
    if HEARTBEAT_ENABLED:
        threading.Thread(target=heartbeat_loop, daemon=True).start()

    tcp_pools = {port: Pool(backends, "tcp") for port, backends in TCP_LISTEN.items()}
    udp_pools = {port: Pool(backends, "udp") for port, backends in UDP_LISTEN.items()}
    for pool in list(tcp_pools.values()) + list(udp_pools.values()):
        pool.check()

    def health_loop():
        while True:
            for pool in list(tcp_pools.values()) + list(udp_pools.values()):
                pool.check()
            time.sleep(CHECK_INTERVAL)

    threading.Thread(target=health_loop, daemon=True).start()
    for port, pool in tcp_pools.items():
        threading.Thread(target=serve_tcp, args=(port, pool), daemon=True).start()
    for port, pool in udp_pools.items():
        threading.Thread(target=serve_udp, args=(port, pool), daemon=True).start()
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
