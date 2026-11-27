import logging
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from topology_monitor import TopologyMonitor


def ethernet_frame(destination):
    dst = bytes.fromhex(destination.replace(":", ""))
    src = bytes.fromhex("020000000099")
    ethertype = bytes.fromhex("88b5")
    return dst + src + ethertype


class GatewayClffForwardingTests(unittest.TestCase):

    def setUp(self):
        self.monitor = TopologyMonitor.__new__(TopologyMonitor)

        self.monitor.logger = logging.getLogger(
            "test.gateway.clff.forwarding"
        )
        self.monitor.vlan_map_ready = True

        self.monitor.vlan_port_map = {
            (3, 1): {
                "kind": "trunk",
                "role": "gateway",
                "vlan_id": None,
                "allowed_vlans": frozenset({10, 20, 30, 40, 50}),
            },
            (3, 2): {
                "kind": "access",
                "role": "endpoint",
                "vlan_id": 20,
                "allowed_vlans": frozenset(),
            },
            (3, 3): {
                "kind": "access",
                "role": "endpoint",
                "vlan_id": 10,
                "allowed_vlans": frozenset(),
            },
            (3, 4): {
                "kind": "access",
                "role": "endpoint",
                "vlan_id": 20,
                "allowed_vlans": frozenset(),
            },
            (3, 7): {
                "kind": "trunk",
                "role": "security_mirror",
                "vlan_id": None,
                "allowed_vlans": frozenset({10, 20, 30, 40, 50}),
            },
        }

        self.monitor.clff_packet_state = {}
        self.monitor.port_to_link = {}

        # Isolate forwarding decision from live Ryu/OVS operations.
        self.monitor._cleanup_clff_packet_state = Mock()
        self.monitor._get_clff_packet_key = Mock(
            return_value=("test-packet",)
        )
        self.monitor._get_clff_root = Mock(return_value=3)
        self.monitor._collect_host_ports = Mock(return_value={3, 4})
        self.monitor._clff_usable = Mock(return_value=False)
        self.monitor._packet_out = Mock()

        self.datapath = SimpleNamespace(id=3)

    def flood(self, destination, vlan_id=20, in_port=2):
        msg = SimpleNamespace(data=ethernet_frame(destination))
        self.monitor._flood_ethernet(
            self.datapath, msg, in_port, vlan_id
        )

    def test_vlan20_broadcast_includes_gateway_trunk(self):
        self.flood("ff:ff:ff:ff:ff:ff", vlan_id=20)

        self.monitor._packet_out.assert_called_once()
        args = self.monitor._packet_out.call_args.args

        self.assertEqual(args[2], [1, 4])
        self.assertEqual(args[3], 20)

    def test_vlan10_broadcast_includes_gateway_trunk(self):
        self.monitor._collect_host_ports = Mock(return_value=set())

        self.flood(
            "ff:ff:ff:ff:ff:ff",
            vlan_id=10,
            in_port=3,
        )

        self.monitor._packet_out.assert_called_once()
        args = self.monitor._packet_out.call_args.args

        self.assertEqual(args[2], [1])
        self.assertEqual(args[3], 10)

    def test_unknown_unicast_is_not_sent_to_gateway(self):
        self.monitor._collect_host_ports = Mock(return_value={4})

        self.flood("00:00:00:00:00:99", vlan_id=20)

        self.monitor._packet_out.assert_called_once()
        args = self.monitor._packet_out.call_args.args

        self.assertEqual(args[2], [4])

    def test_disallowed_vlan_is_not_added_to_gateway(self):
        ports = self.monitor._get_gateway_trunk_ports(
            dpid=3,
            in_port=2,
            vlan_id=60,
        )

        self.assertEqual(ports, set())

    def test_gateway_ingress_is_not_reflooded_to_gateway(self):
        ports = self.monitor._get_gateway_trunk_ports(
            dpid=3,
            in_port=1,
            vlan_id=20,
        )

        self.assertEqual(ports, set())

    def test_gateway_port_is_selected_by_role_not_any_trunk(self):
        ports = self.monitor._get_gateway_trunk_ports(
            dpid=3,
            in_port=2,
            vlan_id=20,
        )

        self.assertEqual(ports, {1})
        self.assertNotIn(7, ports)

    def test_gateway_on_another_switch_is_not_selected(self):
        ports = self.monitor._get_gateway_trunk_ports(
            dpid=1,
            in_port=2,
            vlan_id=20,
        )

        self.assertEqual(ports, set())

    def test_unready_vlan_map_fails_closed(self):
        self.monitor.vlan_map_ready = False

        ports = self.monitor._get_gateway_trunk_ports(
            dpid=3,
            in_port=2,
            vlan_id=20,
        )

        self.assertEqual(ports, set())


if __name__ == "__main__":
    unittest.main()
