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


SOURCE = Path(__file__).with_name("traffic_monitor_merged.py")


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
    namespace = {"ipaddress": ipaddress, "PACKET_FLOW_WINDOW": 10.0}
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

    def add_packet(self, now, src_mac, dst_mac):
        self.subject._update_packet_flow_window(
            now, self.run, 4, "10.10.10.5", "10.10.20.2",
            51514, 5000, 6, 100, 0x02, src_mac, dst_mac
        )

    def flush_row(self):
        key, state = next(iter(self.subject.packet_flow_windows.items()))
        self.assertTrue(self.subject._write_packet_flow_window(key, state))
        return self.subject.written_row

    def test_unique_macs_are_written_normalized(self):
        self.add_packet(100.0, "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02")
        row = self.flush_row()
        self.assertEqual(len(row), 28)
        self.assertEqual(row[-3], "packetin_window")
        self.assertEqual(row[-2:], ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"])

    def test_ambiguous_mac_for_same_ip_pair_is_left_blank(self):
        self.add_packet(100.0, "02:00:00:00:00:01", "02:00:00:00:00:02")
        self.add_packet(101.0, "02:00:00:00:00:99", "02:00:00:00:00:02")
        row = self.flush_row()
        self.assertEqual(row[-2:], ["", "02:00:00:00:00:02"])

    def test_legacy_call_without_mac_keeps_fields_blank(self):
        self.subject._update_packet_flow_window(
            100.0, self.run, 4, "10.10.10.5", "10.10.20.2",
            51514, 5000, 6, 100, 0x02
        )
        row = self.flush_row()
        self.assertEqual(row[-2:], ["", ""])


if __name__ == "__main__":
    unittest.main(verbosity=2)
