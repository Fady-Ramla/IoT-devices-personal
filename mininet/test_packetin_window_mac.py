#!/usr/bin/env python3
"""Focused regression test for MAC preservation in PacketIn flow windows.

The test extracts the two production methods from traffic_monitor_merged.py,
so it can run without importing/installing the Ryu framework.
"""
import ast
import copy
import ipaddress
import unittest
from pathlib import Path
from types import SimpleNamespace


SOURCE = Path(__file__).resolve().parents[1] / "traffic_monitor_merged.py"


def load_harness():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    target_class = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "TrafficMonitorMerged"
    )
    wanted = {"_update_packet_flow_window", "_write_packet_flow_window"}
    methods = [
        copy.deepcopy(node) for node in target_class.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    assert {method.name for method in methods} == wanted
    harness_class = ast.ClassDef(
        name="Harness", bases=[], keywords=[], body=methods, decorator_list=[]
    )
    module = ast.fix_missing_locations(ast.Module(body=[harness_class], type_ignores=[]))
    namespace = {
        "ipaddress": ipaddress,
        "PACKET_FLOW_WINDOW": 10.0,
        "MAX_MAC_OBSERVATIONS_PER_FLOW": 32,
        "MAX_MAC_OBSERVATION_FLOWS": 1024,
    }
    exec(compile(module, str(SOURCE), "exec"), namespace)
    Harness = namespace["Harness"]

    def capture(self, row, run):
        self.written_row = row
        self.written_run = run
        return True

    Harness._write_flow_feature = capture
    Harness._write_flow_feature_locked = capture
    return Harness


class PacketInWindowMacTest(unittest.TestCase):
    def setUp(self):
        Harness = load_harness()
        self.subject = Harness()
        self.run = {"run_id": "test-run", "generation": 1, "state": "active"}
        self.subject.dataset_run = self.run
        self.subject.packet_flow_windows = {}
        self.subject.packet_flow_mac_observations = {}
        self.subject._get_topology_monitor = lambda: SimpleNamespace(
            ip_to_mac={
                "10.10.10.5": "00:00:00:00:00:06",
                "10.10.20.2": "00:00:00:00:00:03",
            }
        )

    def add_packet(self, now, src_mac, dst_mac, dpid=4):
        self.subject._update_packet_flow_window(
            now, self.run, dpid, "10.10.10.5", "10.10.20.2",
            51514, 5000, 6, 100, 0x02, src_mac, dst_mac
        )

    def flush_row(self):
        key, state = next(iter(self.subject.packet_flow_windows.items()))
        self.assertTrue(self.subject._write_packet_flow_window(key, state))
        return self.subject.written_row

    def test_endpoint_macs_stay_stable_and_link_macs_are_observations(self):
        self.add_packet(100.0, "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02")
        self.add_packet(101.0, "AA:BB:CC:DD:EE:03", "AA:BB:CC:DD:EE:04", dpid=3)
        row = self.flush_row()
        self.assertEqual(len(row), 28)
        self.assertEqual(row[-3], "packetin_window")
        self.assertEqual(row[-2:], ["00:00:00:00:00:06", "00:00:00:00:00:03"])
        mac_key = ("test-run", 1, "10.10.10.5", "10.10.20.2", "tcp", "51514", "5000")
        tracker = self.subject.packet_flow_mac_observations[mac_key]
        self.assertEqual(len(tracker["items"]), 2)
        self.assertEqual(tracker["items"][0], {
            "switch_dpid": 4,
            "src_mac": "aa:bb:cc:dd:ee:01",
            "dst_mac": "aa:bb:cc:dd:ee:02",
        })
        self.assertFalse(tracker["truncated"])

    def test_packet_window_keeps_source_endpoint_mac_when_link_mac_changes(self):
        self.add_packet(100.0, "00:00:00:00:00:06", "02:10:00:00:00:01")
        self.add_packet(101.0, "02:20:00:00:00:01", "00:00:00:00:00:03", dpid=3)
        row = self.flush_row()
        self.assertEqual(row[-2:], ["00:00:00:00:00:06", "00:00:00:00:00:03"])

    def test_mac_observations_are_unique_and_capped(self):
        for dpid in range(1, 35):
            self.add_packet(
                100.0 + dpid,
                "02:10:00:00:%02x:%02x" % (dpid // 256, dpid % 256),
                "02:20:00:00:%02x:%02x" % (dpid // 256, dpid % 256),
                dpid=dpid,
            )
        # A repeated L2 observation is deduplicated.
        self.add_packet(200.0, "02:10:00:00:00:01", "02:20:00:00:00:01", dpid=1)
        mac_key = ("test-run", 1, "10.10.10.5", "10.10.20.2", "tcp", "51514", "5000")
        tracker = self.subject.packet_flow_mac_observations[mac_key]
        self.assertEqual(len(tracker["items"]), 32)
        self.assertTrue(tracker["truncated"])

    def test_endpoint_mac_is_not_guessed_without_topology_mapping(self):
        self.subject._get_topology_monitor = lambda: SimpleNamespace(ip_to_mac={})
        self.subject._update_packet_flow_window(
            100.0, self.run, 4, "10.10.10.5", "10.10.20.2",
            51514, 5000, 6, 100, 0x02,
            "00:00:00:00:00:06", "02:10:00:00:00:01"
        )
        row = self.flush_row()
        self.assertEqual(row[-2:], ["", ""])


if __name__ == "__main__":
    unittest.main(verbosity=2)
