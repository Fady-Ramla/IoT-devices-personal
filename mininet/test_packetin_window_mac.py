#!/usr/bin/env python3
"""Focused regression test for link and endpoint MACs in PacketIn windows.

The test extracts production methods from traffic_monitor_merged.py so it can
run without importing/installing the Ryu framework.
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
    resolver = next(
        copy.deepcopy(node) for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "resolve_endpoint_mac"
    )
    harness_class = ast.ClassDef(
        name="Harness", bases=[], keywords=[], body=methods, decorator_list=[]
    )
    module = ast.fix_missing_locations(ast.Module(
        body=[resolver, harness_class], type_ignores=[]))
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
        self.subject.mac_to_ip = {}
        self.subject._get_topology_monitor = lambda: SimpleNamespace(
            ip_to_mac={
                "10.10.10.5": "00:00:00:00:00:06",
                "10.10.20.2": "00:00:00:00:00:03",
            },
            mac_to_ip={
                "00:00:00:00:00:06": "10.10.10.5",
                "00:00:00:00:00:03": "10.10.20.2",
            },
            host_location={
                "00:00:00:00:00:06": (4, 1),
                "00:00:00:00:00:03": (1, 2),
            },
            ip_vlan={"10.10.10.5": 10, "10.10.20.2": 20},
            mac_vlan={"00:00:00:00:00:06": 10, "00:00:00:00:00:03": 20},
            vlan_port_map={
                (4, 1): {"kind": "access"},
                (1, 2): {"kind": "access"},
            },
        )

    def add_packet(self, now, src_mac, dst_mac, dpid=4):
        self.subject._update_packet_flow_window(
            now, self.run, dpid, "10.10.10.5", "10.10.20.2",
            51514, 5000, 6, 100, 0x02, src_mac, dst_mac
        )

    def flush_row_for(self, dpid=None):
        key, state = next(
            (key, state) for key, state in self.subject.packet_flow_windows.items()
            if dpid is None or key[2] == dpid
        )
        self.assertTrue(self.subject._write_packet_flow_window(key, state))
        return self.subject.written_row

    def test_link_macs_are_per_switch_and_endpoint_macs_stay_stable(self):
        self.add_packet(100.0, "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", dpid=4)
        self.add_packet(101.0, "AA:BB:CC:DD:EE:03", "AA:BB:CC:DD:EE:04", dpid=3)
        row = self.flush_row_for(4)
        self.assertEqual(len(row), 30)
        self.assertEqual(row[-5], "packetin_window")
        self.assertEqual(row[-4:], [
            "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
            "00:00:00:00:00:06", "00:00:00:00:00:03",
        ])
        core_row = self.flush_row_for(3)
        self.assertEqual(core_row[-4:], [
            "aa:bb:cc:dd:ee:03", "aa:bb:cc:dd:ee:04",
            "00:00:00:00:00:06", "00:00:00:00:00:03",
        ])
        mac_key = ("test-run", 1, "10.10.10.5", "10.10.20.2", "tcp", "51514", "5000")
        tracker = self.subject.packet_flow_mac_observations[mac_key]
        self.assertEqual(len(tracker["items"]), 2)
        self.assertEqual(tracker["items"][0], {
            "switch_dpid": 4,
            "src_mac": "aa:bb:cc:dd:ee:01",
            "dst_mac": "aa:bb:cc:dd:ee:02",
        })
        self.assertFalse(tracker["truncated"])

    def test_packet_window_keeps_link_gateway_mac_separate_from_endpoint(self):
        self.add_packet(100.0, "00:00:00:00:00:06", "02:20:00:00:00:01", dpid=4)
        self.add_packet(101.0, "02:20:00:00:00:01", "00:00:00:00:00:03", dpid=3)
        ingress = self.flush_row_for(4)
        egress = self.flush_row_for(3)
        self.assertEqual(ingress[-4:], [
            "00:00:00:00:00:06", "02:20:00:00:00:01",
            "00:00:00:00:00:06", "00:00:00:00:00:03",
        ])
        self.assertEqual(egress[-4:], [
            "02:20:00:00:00:01", "00:00:00:00:00:03",
            "00:00:00:00:00:06", "00:00:00:00:00:03",
        ])

    def test_link_mac_is_blank_when_ambiguous_on_one_switch(self):
        self.add_packet(100.0, "00:00:00:00:00:06", "02:20:00:00:00:01", dpid=4)
        self.add_packet(101.0, "00:00:00:00:00:07", "02:20:00:00:00:02", dpid=4)
        row = self.flush_row_for(4)
        self.assertEqual(row[-4:-2], ["", ""])
        self.assertEqual(row[-2:], ["00:00:00:00:00:06", "00:00:00:00:00:03"])

    def test_mac_observations_are_unique_and_capped(self):
        for dpid in range(1, 35):
            self.add_packet(
                100.0 + dpid,
                "02:10:00:00:%02x:%02x" % (dpid // 256, dpid % 256),
                "02:20:00:00:%02x:%02x" % (dpid // 256, dpid % 256),
                dpid=dpid,
            )
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
        row = self.flush_row_for()
        self.assertEqual(row[-2:], ["", ""])
        self.assertEqual(row[-4:-2], ["00:00:00:00:00:06", "02:10:00:00:00:01"])

    def test_missing_destination_ip_map_uses_unique_known_access_endpoint(self):
        self.subject._get_topology_monitor = lambda: SimpleNamespace(
            ip_to_mac={"10.10.10.5": "00:00:00:00:00:06"},
            host_location={
                "00:00:00:00:00:06": (4, 1),
                "00:00:00:00:00:03": (1, 2),
            },
            mac_to_ip={"00:00:00:00:00:03": "10.10.20.2"},
            vlan_port_map={(4, 1): {"kind": "access"}, (1, 2): {"kind": "access"}},
        )
        self.subject._update_packet_flow_window(
            100.0, self.run, 4, "10.10.10.5", "10.10.20.2",
            51514, 5000, 6, 100, 0x02,
            "00:00:00:00:00:06", "02:10:00:00:00:01"
        )
        row = self.flush_row_for()
        self.assertEqual(row[-2:], ["00:00:00:00:00:06", "00:00:00:00:00:03"])

    def test_gateway_trunk_mac_is_not_selected_as_h2_endpoint(self):
        # h6 -> gateway -> h2. The IP map for h2 is stale and points to the
        # gateway VLAN MAC; host/port metadata identifies h2 on an access port.
        self.subject._get_topology_monitor = lambda: SimpleNamespace(
            ip_to_mac={
                "10.10.10.5": "00:00:00:00:00:06",
                "10.10.20.2": "02:20:00:00:00:01",
            },
            mac_to_ip={
                "00:00:00:00:00:06": "10.10.10.5",
                "00:00:00:00:00:03": "10.10.20.2",
                "02:20:00:00:00:01": "10.10.20.2",
            },
            host_location={
                "00:00:00:00:00:06": (4, 6),
                "00:00:00:00:00:03": (1, 2),
                "02:20:00:00:00:01": (3, 9),
            },
            ip_vlan={"10.10.10.5": 10, "10.10.20.2": 20},
            mac_vlan={
                "00:00:00:00:00:06": 10,
                "00:00:00:00:00:03": 20,
                "02:20:00:00:00:01": 20,
            },
            vlan_port_map={
                (4, 6): {"kind": "access"},
                (1, 2): {"kind": "access"},
                (3, 9): {"kind": "trunk"},
            },
        )
        self.add_packet(100.0, "00:00:00:00:00:06", "02:20:00:00:00:01", dpid=4)
        self.add_packet(101.0, "02:20:00:00:00:01", "00:00:00:00:00:03", dpid=3)
        self.add_packet(102.0, "02:20:00:00:00:01", "00:00:00:00:00:03", dpid=1)

        source_edge = self.flush_row_for(4)
        gateway = self.flush_row_for(3)
        target_edge = self.flush_row_for(1)
        self.assertEqual(source_edge[-4:], [
            "00:00:00:00:00:06", "02:20:00:00:00:01",
            "00:00:00:00:00:06", "00:00:00:00:00:03",
        ])
        self.assertEqual(gateway[-4:], [
            "02:20:00:00:00:01", "00:00:00:00:00:03",
            "00:00:00:00:00:06", "00:00:00:00:00:03",
        ])
        self.assertEqual(target_edge[-4:], [
            "02:20:00:00:00:01", "00:00:00:00:00:03",
            "00:00:00:00:00:06", "00:00:00:00:00:03",
        ])
        mac_key = ("test-run", 1, "10.10.10.5", "10.10.20.2", "tcp", "51514", "5000")
        observations = self.subject.packet_flow_mac_observations[mac_key]["items"]
        self.assertEqual([item["switch_dpid"] for item in observations], [4, 3, 1])

    def test_unknown_destination_location_does_not_fall_back_to_gateway(self):
        self.subject._get_topology_monitor = lambda: SimpleNamespace(
            ip_to_mac={
                "10.10.10.5": "00:00:00:00:00:06",
                "10.10.20.2": "02:20:00:00:00:01",
            },
            host_location={"00:00:00:00:00:06": (4, 6)},
            ip_vlan={"10.10.10.5": 10, "10.10.20.2": 20},
            mac_vlan={"00:00:00:00:00:06": 10},
            vlan_port_map={
                (4, 6): {"kind": "access"},
                (3, 9): {"kind": "trunk"},
            },
        )
        self.add_packet(100.0, "00:00:00:00:00:06", "02:20:00:00:00:01", dpid=4)
        row = self.flush_row_for(4)
        self.assertEqual(row[-2:], ["00:00:00:00:00:06", ""])

    def test_untrusted_inter_switch_mac_is_not_used_as_endpoint(self):
        self.subject._get_topology_monitor = lambda: SimpleNamespace(
            ip_to_mac={},
            host_location={"00:00:00:00:00:06": (4, 1)},
            mac_to_ip={
                "00:00:00:00:00:03": "10.10.20.2",
                "00:00:00:00:00:06": "10.10.10.5",
            },
            vlan_port_map={(4, 1): {"kind": "access"}},
        )
        self.subject.mac_to_ip = {
            "00:00:00:00:00:03": "10.10.20.2",
            "00:00:00:00:00:06": "10.10.10.5",
        }
        self.add_packet(100.0, "00:00:00:00:00:06", "02:10:00:00:00:01")
        row = self.flush_row_for()
        self.assertEqual(row[-2:], ["00:00:00:00:00:06", ""])

    def test_destination_mac_must_match_destination_ip_vlan(self):
        self.subject._get_topology_monitor = lambda: SimpleNamespace(
            ip_to_mac={
                "10.10.10.5": "00:00:00:00:00:06",
                "10.10.20.2": "02:10:00:00:00:01",
            },
            host_location={
                "00:00:00:00:00:06": (4, 1),
                "00:00:00:00:00:03": (1, 2),
                "02:10:00:00:00:01": (4, 3),
            },
            mac_to_ip={"00:00:00:00:00:03": "10.10.20.2"},
            ip_vlan={"10.10.10.5": 10, "10.10.20.2": 20},
            mac_vlan={
                "00:00:00:00:00:06": 10,
                "00:00:00:00:00:03": 20,
                "02:10:00:00:00:01": 10,
            },
            vlan_port_map={
                (4, 1): {"kind": "access"},
                (1, 2): {"kind": "access"},
                (4, 3): {"kind": "trunk"},
            },
        )
        self.add_packet(100.0, "00:00:00:00:00:06", "02:10:00:00:00:01")
        row = self.flush_row_for()
        self.assertEqual(row[-2:], ["00:00:00:00:00:06", "00:00:00:00:00:03"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
