import logging
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from topology_monitor import TopologyMonitor

class SecurityMirrorPortTests(unittest.TestCase):

    def setUp(self):
        self.monitor = TopologyMonitor.__new__(TopologyMonitor)
        self.monitor.logger = logging.getLogger(
            "test.security.mirror.port"
        )
        self.monitor.port_desc = {}
        self.monitor.vlan_map_ready = True
        self.monitor.vlan_port_map = {
            (1, 1): {
                "kind": "access",
                "role": "endpoint",
                "vlan_id": 20,
                "allowed_vlans": frozenset(),
            },
            (3, 1): {
                "kind": "trunk",
                "role": "gateway",
                "vlan_id": None,
                "allowed_vlans": frozenset({10, 20, 30, 40, 50}),
            },
        }
        self.monitor.port_to_link = {}
        self.monitor.known_switch_ports = set()
        self.monitor.mac_vlan = {}
        self.monitor.host_location = {}
        self.monitor.ip_to_mac = {}
        self.monitor.mac_to_ip = {}
        self.monitor.ip_vlan = {}

        # Isolate the handler from live Ryu/OVS operations.
        self.monitor._is_special_port = Mock(return_value=False)
        self.monitor._decode_port_name = Mock(
            side_effect=lambda name: (
                name.decode("utf-8")
                if isinstance(name, bytes) else str(name)
            )
        )
        self.monitor._send_lldp = Mock()
        self.monitor._remove_lldp_for_port = Mock()
        self.monitor._update_topology_from_lldp = Mock()

        self.datapath = SimpleNamespace(
            id=1,
            ofproto=SimpleNamespace(
                OFPPR_DELETE=1,
                OFPPS_LINK_DOWN=1,
                OFPPC_PORT_DOWN=1,
            ),
        )

    def make_event(self, port_no, name, reason=0,
                   state=0, config=0):
        desc = SimpleNamespace(
            port_no=port_no,
            name=name,
            state=state,
            config=config,
        )
        msg = SimpleNamespace(
            datapath=self.datapath,
            desc=desc,
            reason=reason,
        )
        return SimpleNamespace(msg=msg)

    def test_mirror_port_add_is_recorded_but_not_probed(self):
        event = self.make_event(
            6, b"sec-mir-s1-ovs"
        )

        self.monitor.port_status_handler(event)

        self.assertEqual(
            self.monitor.port_desc[(1, 6)],
            "sec-mir-s1-ovs",
        )
        self.monitor._send_lldp.assert_not_called()
        self.monitor._remove_lldp_for_port.assert_not_called()
        self.monitor._update_topology_from_lldp.assert_not_called()

    def test_mirror_port_delete_is_removed_without_topology_update(self):
        self.monitor.port_desc[(1, 6)] = "sec-mir-s1-ovs"

        event = self.make_event(
            6,
            b"sec-mir-s1-ovs",
            reason=self.datapath.ofproto.OFPPR_DELETE,
        )

        self.monitor.port_status_handler(event)

        self.assertNotIn((1, 6), self.monitor.port_desc)
        self.monitor._send_lldp.assert_not_called()
        self.monitor._remove_lldp_for_port.assert_not_called()
        self.monitor._update_topology_from_lldp.assert_not_called()

    def test_access_endpoint_is_host_port(self):
        self.assertTrue(self.monitor.is_host_port(1, 1))

    def test_gateway_trunk_is_not_host_port(self):
        self.assertFalse(self.monitor.is_host_port(3, 1))

    def test_inter_switch_port_is_not_host_port(self):
        self.monitor.known_switch_ports.add((1, 4))
        self.assertFalse(self.monitor.is_host_port(1, 4))

    def test_security_mirror_port_is_not_host_port(self):
        self.monitor.port_desc[(1, 6)] = "sec-mir-s1-ovs"
        self.assertFalse(self.monitor.is_host_port(1, 6))

    def test_unknown_port_is_not_host_port(self):
        self.assertFalse(self.monitor.is_host_port(1, 99))

    def test_access_endpoint_is_learned(self):
        mac = "00:00:00:00:00:01"

        learned = self.monitor._learn_host(
            1, 1, mac, vlan_id=20
        )

        self.assertTrue(learned)
        self.assertEqual(self.monitor.host_location[mac], (1, 1))
        self.assertEqual(self.monitor.mac_vlan[mac], 20)

    def test_gateway_trunk_is_learned_for_forwarding(self):
        mac = "00:00:00:00:00:02"

        learned = self.monitor._learn_host(
            3, 1, mac, vlan_id=20
        )

        self.assertTrue(learned)
        self.assertEqual(self.monitor.host_location[mac], (3, 1))
        self.assertEqual(self.monitor.mac_vlan[mac], 20)
        self.assertNotIn(mac, self.monitor.mac_to_ip)

    def test_arp_from_access_endpoint_learns_ip(self):
        arp = SimpleNamespace(
            src_mac="00:00:00:00:00:11",
            src_ip="10.10.20.11",
        )

        learned = self.monitor._learn_from_arp(
            1, 1, arp, 20
        )

        self.assertTrue(learned)
        self.assertEqual(
            self.monitor.ip_to_mac["10.10.20.11"],
            "00:00:00:00:00:11",
        )
        self.assertEqual(self.monitor.ip_vlan["10.10.20.11"], 20)

    def test_arp_from_gateway_does_not_learn_endpoint_ip(self):
        arp = SimpleNamespace(
            src_mac="00:00:00:00:00:12",
            src_ip="10.10.20.1",
        )

        learned = self.monitor._learn_from_arp(
            3, 1, arp, 20
        )

        self.assertTrue(learned)
        self.assertEqual(
            self.monitor.host_location["00:00:00:00:00:12"],
            (3, 1),
        )
        self.assertNotIn("10.10.20.1", self.monitor.ip_to_mac)
        self.assertNotIn("10.10.20.1", self.monitor.ip_vlan)

    def test_unknown_port_is_not_learned(self):
        mac = "00:00:00:00:00:03"

        learned = self.monitor._learn_host(
            1, 99, mac, vlan_id=20
        )

        self.assertFalse(learned)
        self.assertNotIn(mac, self.monitor.host_location)
        self.assertNotIn(mac, self.monitor.mac_vlan)

    def test_access_endpoint_rejects_wrong_vlan(self):
        mac = "00:00:00:00:00:04"

        learned = self.monitor._learn_host(
            1, 1, mac, vlan_id=10
        )

        self.assertFalse(learned)
        self.assertNotIn(mac, self.monitor.host_location)

    def test_normal_port_add_keeps_existing_behavior(self):
        event = self.make_event(
            1, b"s1-eth1"
        )

        self.monitor.port_status_handler(event)

        self.assertEqual(
            self.monitor.port_desc[(1, 1)],
            "s1-eth1",
        )
        self.monitor._send_lldp.assert_called_once_with(
            self.datapath, 1
        )
        self.monitor._remove_lldp_for_port.assert_not_called()
        self.monitor._update_topology_from_lldp.assert_not_called()

if __name__ == "__main__":
    unittest.main()
