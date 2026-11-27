import logging
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from topology_monitor import TopologyMonitor


class InfrastructureForwardingTests(unittest.TestCase):

    def setUp(self):
        self.monitor = TopologyMonitor.__new__(TopologyMonitor)
        self.monitor.logger = logging.getLogger(
            "test.infrastructure.forwarding"
        )

        self.monitor.vlan_map_ready = True
        self.monitor.vlan_port_map = {
            (1, 1): {
                "kind": "access",
                "role": "endpoint",
                "vlan_id": 20,
                "allowed_vlans": frozenset(),
            },
            (1, 2): {
                "kind": "access",
                "role": "infrastructure",
                "vlan_id": 20,
                "allowed_vlans": frozenset(),
            },
            (1, 3): {
                "kind": "access",
                "role": "infrastructure",
                "vlan_id": 20,
                "allowed_vlans": frozenset(),
            },
            (1, 4): {
                "kind": "trunk",
                "role": "gateway",
                "vlan_id": None,
                "allowed_vlans": frozenset({10, 20, 30, 40, 50}),
            },
            (1, 6): {
                "kind": "access",
                "role": "infrastructure",
                "vlan_id": 20,
                "allowed_vlans": frozenset(),
            },
        }

        self.monitor.port_desc = {
            (1, 2): "s1-eth2",
            (1, 3): "s1-eth3",
            (1, 4): "gw-eth0",
            (1, 6): "sec-mir-s1-ovs",
        }
        self.monitor.port_to_link = {}
        self.monitor.known_switch_ports = set()

        self.monitor.mac_vlan = {}
        self.monitor.host_location = {}
        self.monitor.ip_to_mac = {}
        self.monitor.mac_to_ip = {}
        self.monitor.ip_vlan = {}

        self.monitor._is_special_port = Mock(return_value=False)

    def test_infrastructure_access_is_forwarding_port_not_endpoint_port(self):
        self.assertTrue(
            self.monitor._is_forwarding_access_port(1, 2)
        )
        self.assertFalse(
            self.monitor.is_host_port(1, 2)
        )

    def test_infrastructure_mac_is_learned(self):
        mac = "00:00:00:00:00:27"

        learned = self.monitor._learn_host(
            1, 2, mac, vlan_id=20
        )

        self.assertTrue(learned)
        self.assertEqual(self.monitor.host_location[mac], (1, 2))
        self.assertEqual(self.monitor.mac_vlan[mac], 20)

    def test_infrastructure_arp_learns_ip_for_forwarding(self):
        arp_packet = SimpleNamespace(
            src_mac="00:00:00:00:00:27",
            src_ip="10.10.20.100",
        )

        learned = self.monitor._learn_from_arp(
            1, 2, arp_packet, 20
        )

        self.assertTrue(learned)
        self.assertEqual(
            self.monitor.ip_to_mac["10.10.20.100"],
            "00:00:00:00:00:27",
        )
        self.assertEqual(self.monitor.ip_vlan["10.10.20.100"], 20)

    def test_flooding_collection_includes_infrastructure_access_ports(self):
        ports = self.monitor._collect_host_ports(1, 1)

        self.assertEqual(ports, {2, 3})
        self.assertNotIn(4, ports)  # Gateway trunk is handled separately.
        self.assertNotIn(6, ports)  # Security mirror is never a host port.

    def test_infrastructure_learning_still_checks_vlan(self):
        learned = self.monitor._learn_host(
            1, 2, "00:00:00:00:00:28", vlan_id=10
        )

        self.assertFalse(learned)
        self.assertNotIn(
            "00:00:00:00:00:28",
            self.monitor.host_location,
        )

    def test_infrastructure_port_is_not_forwarding_port_when_inter_switch(self):
        self.monitor.known_switch_ports.add((1, 2))

        self.assertFalse(
            self.monitor._is_forwarding_access_port(1, 2)
        )


if __name__ == "__main__":
    unittest.main()
