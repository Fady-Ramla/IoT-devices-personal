"""Behavior-focused checks for whole-host blocking and link recovery."""
import ast
import logging
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "topology_monitor.py"
TREE = ast.parse(SOURCE.read_text(encoding="utf-8"))
TOPOLOGY = next(node for node in TREE.body
                if isinstance(node, ast.ClassDef)
                and node.name == "TopologyMonitor")


def extract_method(name, globals_=None):
    node = next(item for item in TOPOLOGY.body
                if isinstance(item, ast.FunctionDef) and item.name == name)
    namespace = {"DEVICE_BLOCK_PRIORITY": 50000}
    namespace.update(globals_ or {})
    exec(compile(ast.fix_missing_locations(ast.Module(
        body=[node], type_ignores=[])), str(SOURCE), "exec"), namespace)
    return namespace[name]


class BlockParser:
    @staticmethod
    def OFPMatch(**fields):
        return fields


class BlockHarness:
    install_device_block = extract_method("_install_device_block_rule")

    def __init__(self):
        self.installed = []

    @staticmethod
    def normalize_device_mac(mac):
        return str(mac).strip().lower()

    def _add_flow(self, datapath, priority, match, actions, track_key=None):
        self.installed.append((priority, match, list(actions), track_key))


class RerouteHarness:
    _path_uses_failed_link = staticmethod(extract_method("_path_uses_failed_link"))
    reroute_active_flows = extract_method("reroute_active_flows")

    def __init__(self):
        self.logger = logging.getLogger("test.host.block.reroute")
        self.active_flows = {
            "blocked-source": {
                "src_mac": "host-a", "dst_mac": "host-c",
                "src_ip": "10.10.10.1", "dst_ip": "10.10.10.3",
                "path": [1, 2, 3], "vlan_id": 10,
            },
            "affected": {
                "src_mac": "host-b", "dst_mac": "host-c",
                "src_ip": "10.10.10.2", "dst_ip": "10.10.10.3",
                "path": [1, 2, 3], "vlan_id": 10,
            },
            "unaffected": {
                "src_mac": "host-d", "dst_mac": "host-e",
                "src_ip": "10.10.10.4", "dst_ip": "10.10.10.5",
                "path": [1, 4, 3], "vlan_id": 10,
            },
        }
        self.host_location = {
            "host-a": (1, 0),
            "host-b": (1, 1), "host-c": (3, 1),
            "host-d": (1, 2), "host-e": (3, 2),
        }
        self.blocked_devices = {
            "host-a": {"mac": "host-a", "ip": "10.10.10.1",
                       "enforcement_status": "executed"}
        }
        self.operational_graph = object()
        self.path_engine = SimpleNamespace(
            network_state={},
            get_backup_path=lambda **kwargs: {"success": True, "path": [1, 5, 3]},
        )
        self.install_calls = []

    def is_device_blocked(self, mac):
        return mac in self.blocked_devices

    def _install_path(self, path, src_mac, dst_mac, vlan_id, dst_location=None):
        self.install_calls.append((list(path), src_mac, dst_mac, vlan_id))
        return True

    def _record_path_history(self, *args):
        pass


class HostBlockAndRerouteTests(unittest.TestCase):
    def test_host_block_matches_source_mac_only_and_drops_all_destinations(self):
        harness = BlockHarness()
        datapath = SimpleNamespace(ofproto_parser=BlockParser())
        harness.install_device_block(datapath, "AA:BB:CC:DD:EE:01")

        self.assertEqual(len(harness.installed), 1)
        priority, match, actions, track_key = harness.installed[0]
        self.assertEqual(match, {"eth_src": "aa:bb:cc:dd:ee:01"})
        self.assertEqual(priority, 50000)
        self.assertEqual(actions, [])
        self.assertIsNone(track_key)

    def test_failed_link_reroutes_only_impacted_flow_and_keeps_host_a_blocked(self):
        harness = RerouteHarness()
        unaffected_path = list(harness.active_flows["unaffected"]["path"])
        blocked_path = list(harness.active_flows["blocked-source"]["path"])

        result = harness.reroute_active_flows(failed_links={(1, 2)})

        self.assertEqual(result, {"success": True, "rerouted": 1, "failed": 0})
        self.assertEqual(harness.active_flows["blocked-source"]["path"], blocked_path)
        self.assertEqual(harness.active_flows["affected"]["path"], [1, 5, 3])
        self.assertEqual(harness.active_flows["unaffected"]["path"], unaffected_path)
        self.assertEqual(len(harness.install_calls), 1)
        self.assertIn("host-a", harness.blocked_devices)
        self.assertEqual(harness.blocked_devices["host-a"]["enforcement_status"], "executed")


if __name__ == "__main__":
    unittest.main()
