"""Tests for Ryu's idle-safe load-balancer heartbeat health detection."""
import ast
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "topology_monitor.py"
TREE = ast.parse(SOURCE.read_text(encoding="utf-8"))
TOPOLOGY = next(node for node in TREE.body
                if isinstance(node, ast.ClassDef)
                and node.name == "TopologyMonitor")
METHOD = next(node for node in TOPOLOGY.body
              if isinstance(node, ast.FunctionDef)
              and node.name == "_lb_health_is_healthy")
NAMESPACE = {"Path": Path, "json": json, "time": __import__("time"),
             "LB_HEALTH_TIMEOUT": 5}
exec(compile(ast.fix_missing_locations(ast.Module(
    body=[METHOD], type_ignores=[])), str(SOURCE), "exec"), NAMESPACE)


class HealthHarness:
    _lb_health_is_healthy = NAMESPACE["_lb_health_is_healthy"]


class LoadBalancerHealthTests(unittest.TestCase):
    def test_recent_heartbeat_is_healthy(self):
        with tempfile.TemporaryDirectory() as directory:
            stats = Path(directory) / "lb.json"
            stats.write_text(json.dumps({"heartbeat_at": 98.0}), encoding="utf-8")
            self.assertTrue(HealthHarness()._lb_health_is_healthy(stats, now=100.0))

    def test_stale_heartbeat_is_unhealthy(self):
        with tempfile.TemporaryDirectory() as directory:
            stats = Path(directory) / "lb.json"
            stats.write_text(json.dumps({"heartbeat_at": 94.0}), encoding="utf-8")
            self.assertFalse(HealthHarness()._lb_health_is_healthy(stats, now=100.0))

    def test_future_or_malformed_heartbeat_is_unhealthy(self):
        with tempfile.TemporaryDirectory() as directory:
            stats = Path(directory) / "lb.json"
            stats.write_text(json.dumps({"heartbeat_at": 101.0}), encoding="utf-8")
            self.assertFalse(HealthHarness()._lb_health_is_healthy(stats, now=100.0))
            stats.write_text("{not-json", encoding="utf-8")
            self.assertFalse(HealthHarness()._lb_health_is_healthy(stats, now=100.0))

    def test_missing_stats_file_is_unhealthy(self):
        with tempfile.TemporaryDirectory() as directory:
            stats = Path(directory) / "missing.json"
            self.assertFalse(HealthHarness()._lb_health_is_healthy(stats, now=100.0))


if __name__ == "__main__":
    unittest.main()
