import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "mininet"))

from dns_load_balancer import DnsLoadBalancer  # noqa: E402


class FakeSocket:
    def __init__(self, response):
        self.response = response
        self.timeouts = []
        self.sent = []

    def settimeout(self, value):
        self.timeouts.append(value)

    def sendto(self, packet, backend):
        self.sent.append((packet, backend))

    def recvfrom(self, _size):
        return self.response, ("10.10.30.17", 53)

    def close(self):
        pass


class DnsLoadBalancerTimeoutTests(unittest.TestCase):
    def make_lb(self):
        return DnsLoadBalancer(
            "127.0.0.1",
            53,
            [("10.0.0.2", 53), ("10.0.0.17", 53)],
            health_timeout=1.0,
            forward_timeout=3.0,
        )

    def test_health_check_and_forward_use_separate_timeouts(self):
        lb = self.make_lb()
        query = b"\x12\x34" + b"x" * 20
        health_socket = FakeSocket(query)
        forward_socket = FakeSocket(b"response")

        with patch("dns_load_balancer.probe_query", return_value=query), \
                patch("dns_load_balancer.socket.socket",
                      side_effect=[health_socket, forward_socket]):
            self.assertTrue(lb.health_check(lb.backends[0]))
            self.assertEqual(lb.forward(lb.backends[0], query), b"response")

        self.assertEqual(health_socket.timeouts, [1.0])
        self.assertEqual(forward_socket.timeouts, [3.0])

    def test_forward_timeout_can_be_configured_independently(self):
        lb = DnsLoadBalancer(
            "127.0.0.1",
            53,
            [("10.0.0.2", 53)],
            health_timeout=0.5,
            forward_timeout=4.0,
        )
        self.assertEqual(lb.health_timeout, 0.5)
        self.assertEqual(lb.forward_timeout, 4.0)


if __name__ == "__main__":
    unittest.main()
