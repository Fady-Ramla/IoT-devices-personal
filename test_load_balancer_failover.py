import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "mininet"))

from load_balancer import TcpLoadBalancer  # noqa: E402


class FakeClient:
    def close(self):
        pass


class LoadBalancerFailoverTests(unittest.TestCase):
    def make_lb(self, stats_file):
        lb = TcpLoadBalancer(
            "127.0.0.1",
            0,
            [("10.0.0.2", 5000), ("10.0.0.8", 5000)],
        )
        lb.stats_file = stats_file
        return lb

    def read_stats(self, path):
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def test_primary_unhealthy_backup_request_counts_as_failover(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            stats_file = str(Path(temp_dir) / "lb-stats.json")
            lb = self.make_lb(stats_file)
            primary, backup = lb.backends
            lb.healthy = lambda backend: backend == backup
            lb.relay = lambda client, upstream: None

            with patch("load_balancer.socket.create_connection", return_value=object()):
                lb.handle(FakeClient(), ("10.0.0.21", 12345))

            stats = self.read_stats(stats_file)
            self.assertEqual(stats["healthy_backends"], ["10.0.0.8:5000"])
            self.assertEqual(stats["last_backend"], "10.0.0.8:5000")
            self.assertEqual(stats["backend_failovers"], 1)
            self.assertEqual(stats["backend_requests"]["10.0.0.8:5000"], 1)
            self.assertEqual(stats["requests_active"], 0)

    def test_normal_round_robin_to_backup_is_not_a_failover(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            stats_file = str(Path(temp_dir) / "lb-stats.json")
            lb = self.make_lb(stats_file)
            lb.healthy = lambda backend: True

            first_backend, first_failed_over = lb.choose_backend()
            second_backend, second_failed_over = lb.choose_backend()

            self.assertEqual(first_backend, lb.backends[0])
            self.assertFalse(first_failed_over)
            self.assertEqual(second_backend, lb.backends[1])
            self.assertFalse(second_failed_over)
            self.assertEqual(self.read_stats(stats_file)["backend_failovers"], 0)


if __name__ == "__main__":
    unittest.main()
