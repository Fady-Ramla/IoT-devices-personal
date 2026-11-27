"""Loopback-only fault-injection tests for the SecureIoT TCP backend pool."""
import importlib.util
import pathlib
import socket
import threading
import unittest

MODULE_PATH = next(
    (
        parent / "mininet" / "load_balancer.py"
        for parent in pathlib.Path(__file__).resolve().parents
        if (parent / "mininet" / "load_balancer.py").is_file()
    ),
    None,
)

if MODULE_PATH is None:
    raise FileNotFoundError("Could not locate mininet/load_balancer.py")
spec = importlib.util.spec_from_file_location("secureiot_load_balancer", MODULE_PATH)
lb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lb)


class TcpSink:
    """Tiny TCP listener used only on 127.0.0.1 by tests."""
    def __init__(self):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.address = self.listener.getsockname()
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while not self.stopped.is_set():
            try:
                conn, _ = self.listener.accept()
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    def close(self):
        self.stopped.set()
        self.listener.close()
        self.thread.join(timeout=1)


class TcpResponder:
    """Local listener that replies with a marker identifying the backend."""
    def __init__(self, marker):
        self.marker = marker
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.address = self.listener.getsockname()
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while not self.stopped.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                try:
                    data = conn.recv(4096)
                    # TCP health probes close without sending payload.
                    if data:
                        conn.sendall(self.marker)
                        conn.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

    def close(self):
        self.stopped.set()
        self.listener.close()
        self.thread.join(timeout=1)


class LoadBalancerFailoverTests(unittest.TestCase):
    def test_primary_preferred_backup_selected_when_primary_drops_and_recovers(self):
        primary = TcpSink()
        backup = TcpSink()
        try:
            pool = lb.Pool([primary.address, backup.address],
                           failure_threshold=1, recovery_threshold=1)
            pool.check()
            self.assertEqual(pool.candidates(), [primary.address, backup.address])

            primary.close()
            pool.check()
            self.assertEqual(pool.candidates(), [backup.address])
            self.assertEqual(pool.candidates()[0], backup.address)

            # Recreate a listener at the same primary port and verify failback.
            primary = TcpSinkAt(primary.address)
            pool.check()
            self.assertEqual(pool.candidates(), [primary.address, backup.address])
        finally:
            primary.close()
            backup.close()


    def test_proxy_delivers_request_to_backup_after_primary_failure(self):
        primary = TcpSink()
        backup = TcpResponder(b"backup-response")
        try:
            pool = lb.Pool([primary.address, backup.address],
                           failure_threshold=1, recovery_threshold=1)
            pool.check()
            primary.close()
            pool.check()

            client, proxy_side = socket.socketpair()
            worker = threading.Thread(target=lb.proxy,
                                      args=(proxy_side, pool, 5000), daemon=True)
            worker.start()
            client.settimeout(2)
            client.sendall(b"test-request")
            client.shutdown(socket.SHUT_WR)
            response = b""
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                response += chunk
            client.close()
            self.assertEqual(response, b"backup-response")
        finally:
            primary.close()
            backup.close()

    def test_http_and_https_defaults_point_to_declared_backup_hosts(self):
        self.assertEqual(lb.parse_backends(lb.DEFAULT_HTTP),
                         [("10.10.20.2", 5000), ("10.10.20.8", 5000)])
        self.assertEqual(lb.parse_backends(lb.DEFAULT_HTTPS),
                         [("10.10.20.3", 443), ("10.10.20.19", 443)])

    def test_invalid_backend_list_is_rejected(self):
        with self.assertRaises(ValueError):
            lb.parse_backends("10.10.20.2")


class TcpSinkAt(TcpSink):
    def __init__(self, address):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(address)
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.address = self.listener.getsockname()
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()


if __name__ == "__main__":
    unittest.main(verbosity=2)
