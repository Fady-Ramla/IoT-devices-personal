#!/usr/bin/env python3
"""Static/unit checks for the six-switch Core + gateway-trunk proposal."""

from collections import Counter, defaultdict
from pathlib import Path
import sys
import unittest


MININET_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(MININET_DIR))

from vlan_config_38host import HOSTS, INTER_SWITCH_LINKS, SWITCH_NAMES, VLAN_IDS  # noqa: E402
from configure_gateway import (  # noqa: E402
    FORWARD_RULES,
    GATEWAY_PARENT_INTERFACE,
    GATEWAY_VLAN_MACS,
    GATEWAY_VLAN_INTERFACES,
    configure_gateway,
)


class FakeGateway:
    """Capture commands without executing anything in a network namespace."""

    def __init__(self):
        self.commands = []

    def cmd(self, command):
        self.commands.append(command)
        return "__SECUREIOT_GATEWAY_RC__0\n"


class CoreSwitchTrunkTests(unittest.TestCase):
    def test_switch_inventory_and_link_diversity(self):
        self.assertEqual(set(SWITCH_NAMES), {"s1", "s2", "s3", "s4", "s5", "s6"})
        self.assertEqual(len(SWITCH_NAMES), 6)
        self.assertNotIn("s7", SWITCH_NAMES)
        self.assertEqual(len(INTER_SWITCH_LINKS), 12)
        self.assertTrue(all(a in SWITCH_NAMES and b in SWITCH_NAMES
                            for a, b in INTER_SWITCH_LINKS))
        self.assertTrue(all(a != b for a, b in INTER_SWITCH_LINKS))
        self.assertEqual(len(set(tuple(sorted(link)) for link in INTER_SWITCH_LINKS)), 12)

        degree = Counter(node for link in INTER_SWITCH_LINKS for node in link)
        for switch in SWITCH_NAMES:
            self.assertGreaterEqual(degree[switch], 3, "%s has too few paths" % switch)

        core_links = {tuple(sorted(link)) for link in INTER_SWITCH_LINKS
                      if "s3" in link}
        self.assertEqual(core_links, {
            ("s1", "s3"), ("s2", "s3"), ("s3", "s4"),
            ("s3", "s5"), ("s3", "s6"),
        })

        mesh_links = {tuple(sorted(link)) for link in INTER_SWITCH_LINKS
                      if "s3" not in link}
        self.assertEqual(mesh_links, {
            ("s1", "s2"), ("s1", "s5"), ("s2", "s4"),
            ("s2", "s5"), ("s4", "s5"), ("s4", "s6"),
            ("s5", "s6"),
        })

        # A single switch-link failure must not partition the switch graph.
        for failed_edge in INTER_SWITCH_LINKS:
            adjacency = {switch: set() for switch in SWITCH_NAMES}
            for left, right in INTER_SWITCH_LINKS:
                if {left, right} == set(failed_edge):
                    continue
                adjacency[left].add(right)
                adjacency[right].add(left)
            reached = set()
            pending = [SWITCH_NAMES[0]]
            while pending:
                current = pending.pop()
                if current in reached:
                    continue
                reached.add(current)
                pending.extend(adjacency[current] - reached)
            self.assertEqual(reached, set(SWITCH_NAMES),
                             "network partitions when %s-%s fails" % failed_edge)

    def test_hosts_servers_and_vlan_distribution(self):
        self.assertEqual(len(HOSTS), 38)
        self.assertEqual(38 + len(INTER_SWITCH_LINKS) * 2 + 1, 63)
        self.assertNotIn("s3", {spec["switch"] for spec in HOSTS.values()})
        counts = Counter(spec["switch"] for spec in HOSTS.values())
        self.assertEqual(counts, Counter({"s1": 2, "s2": 3, "s4": 12,
                                          "s5": 11, "s6": 10}))
        self.assertEqual(HOSTS["h1"]["switch"], "s1")
        self.assertEqual(HOSTS["h2"]["switch"], "s1")
        for host_id in ("h3", "h4", "h38"):
            self.assertEqual(HOSTS[host_id]["switch"], "s2")
        for host_id in ("h17", "h18", "h19", "h20"):
            self.assertEqual(HOSTS[host_id]["switch"], "s5")
        for host_number in range(5, 17):
            self.assertEqual(HOSTS["h%d" % host_number]["switch"], "s4")

        vlans_by_switch = defaultdict(set)
        for spec in HOSTS.values():
            vlans_by_switch[spec["switch"]].add(spec["vlan"])
        self.assertEqual(vlans_by_switch["s1"], {20, 30})
        self.assertEqual(vlans_by_switch["s2"], {20})
        self.assertEqual(vlans_by_switch["s4"], {10})
        self.assertEqual(vlans_by_switch["s5"], {20, 30, 50})
        self.assertEqual(vlans_by_switch["s6"], {40, 50})
        self.assertEqual(set().union(*vlans_by_switch.values()), set(VLAN_IDS))
        self.assertEqual(set(VLAN_IDS), {10, 20, 30, 40, 50})

    def test_gateway_is_one_parent_trunk_with_five_vlan_subinterfaces(self):
        self.assertEqual(GATEWAY_PARENT_INTERFACE, "gw-eth0")
        self.assertEqual(set(GATEWAY_VLAN_INTERFACES), set(VLAN_IDS))
        self.assertEqual(set(GATEWAY_VLAN_MACS), set(VLAN_IDS))
        self.assertEqual(len(set(GATEWAY_VLAN_MACS.values())), len(VLAN_IDS))
        self.assertEqual(
            GATEWAY_VLAN_INTERFACES,
            {
                10: ("gw-eth0.10", "10.10.10.1/24"),
                20: ("gw-eth0.20", "10.10.20.1/24"),
                30: ("gw-eth0.30", "10.10.30.1/24"),
                40: ("gw-eth0.40", "10.10.40.1/24"),
                50: ("gw-eth0.50", "10.10.50.1/24"),
            },
        )
        self.assertTrue(all("gw-eth0." in rule for rule in FORWARD_RULES[1:]))
        fake = FakeGateway()
        configure_gateway(fake)
        for vlan_id, (interface, address) in GATEWAY_VLAN_INTERFACES.items():
            self.assertTrue(any(
                "ip link add link gw-eth0 name %s type vlan id %d"
                % (interface, vlan_id) in command for command in fake.commands
            ))
            self.assertTrue(any(
                "ip link set dev %s address %s"
                % (interface, GATEWAY_VLAN_MACS[vlan_id]) in command
                for command in fake.commands
            ))
            self.assertTrue(any(
                "ip addr replace %s dev %s" % (address, interface) in command
                for command in fake.commands
            ))
        self.assertTrue(any("iptables -P FORWARD DROP" in command
                            for command in fake.commands))


if __name__ == "__main__":
    unittest.main()
