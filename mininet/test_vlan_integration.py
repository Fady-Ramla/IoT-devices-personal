#!/usr/bin/env python3
"""Pure-Python VLAN topology/policy smoke tests (no Ryu or Mininet runtime)."""
import ast
import ipaddress
import json
import os
import re
import tempfile
import uuid
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent

# The inventory is deliberately importable without Mininet.
import sys
sys.path.insert(0, str(ROOT / "mininet"))
import vlan_config_38host as config

assert len(config.HOSTS) == 38
assert len({row["ip"] for row in config.HOSTS.values()}) == 38
assert len(config.INTER_SWITCH_LINKS) == 12
assert dict(Counter(row["vlan"] for row in config.HOSTS.values())) == {
    10: 12, 20: 7, 30: 2, 40: 2, 50: 15,
}
assert set(config.VLAN_GATEWAYS) == {10, 20, 30, 40, 50}

# Extract only the three pure topology-map publisher functions. This avoids
# importing Mininet on the sandbox while still exercising the exact code.
launcher = ROOT / "mininet" / "Real_network_topology.py"
tree = ast.parse(launcher.read_text(encoding="utf-8"))
function_names = {
    "_switch_port_for_node", "_switch_interface_for_node_interface",
    "_switch_dpid", "_write_vlan_port_map",
}
functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
             and node.name in function_names]
assert {node.name for node in functions} == function_names

with tempfile.TemporaryDirectory() as tmp:
    map_path = Path(tmp) / "vlan_port_map.json"
    globals_for_publisher = {
        "HOSTS": config.HOSTS,
        "NETWORKS": config.NETWORKS,
        "INTER_SWITCH_LINKS": config.INTER_SWITCH_LINKS,
        "VLAN_PORT_MAP_FILE": str(map_path),
        "os": os,
        "json": json,
        "uuid": uuid,
        "info": lambda *args, **kwargs: None,
    }
    module = ast.Module(body=functions, type_ignores=[])
    exec(compile(module, str(launcher), "exec"), globals_for_publisher)

    class Interface:
        def __init__(self, node, name):
            self.node = node
            self.name = name

    class Node:
        def __init__(self, name, dpid=None):
            self.name = name
            self.dpid = dpid
            self.ports = {}
            self.links = {}

        def connectionsTo(self, node):
            return self.links.get(node.name, [])

        def connect(self, other, left_name, right_name):
            left = Interface(self, left_name)
            right = Interface(other, right_name)
            self.ports[left] = len(self.ports) + 1
            other.ports[right] = len(other.ports) + 1
            self.links.setdefault(other.name, []).append((left, right))
            other.links.setdefault(self.name, []).append((left, right))

    nodes = {f"s{i}": Node(f"s{i}", f"{i:016x}") for i in range(1, 7)}
    nodes["gw"] = Node("gw")
    for host_name, spec in config.HOSTS.items():
        nodes[host_name] = Node(host_name)
        nodes[spec["switch"]].connect(nodes[host_name],
                                      f"{spec['switch']}-eth{len(nodes[spec['switch']].ports)}",
                                      f"{host_name}-eth0")
    nodes["s3"].connect(nodes["gw"], "s3-gw0", "gw-eth0")
    for left_name, right_name in config.INTER_SWITCH_LINKS:
        left, right = nodes[left_name], nodes[right_name]
        left.connect(right, f"{left_name}-trunk{len(left.ports)}",
                     f"{right_name}-trunk{len(right.ports)}")

    class FakeNetwork:
        def get(self, name):
            return nodes[name]

    globals_for_publisher["_write_vlan_port_map"](FakeNetwork())
    payload = json.loads(map_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 2
    assert payload["host_count"] == 38
    assert re.fullmatch(r"[0-9a-f]{32}", payload["topology_id"])
    assert len(payload["ports"]) == 63
    assert Counter(row["kind"] for row in payload["ports"]) == {
        "access": 38, "trunk": 25,
    }
    assert Counter(row["role"] for row in payload["ports"] if row["kind"] == "access") == {
        "endpoint": 38,
    }
    assert Counter(row.get("role") for row in payload["ports"]) == {
        "endpoint": 62, "gateway": 1,
    }
    gateway_rows = [row for row in payload["ports"] if row.get("role") == "gateway"]
    assert gateway_rows[0]["switch"] == "s3"
    assert set(gateway_rows[0]["allowed_vlans"]) == {10, 20, 30, 40, 50}

# Exercise the actual VLAN policy methods without importing Ryu.
topology = ROOT / "topology_monitor.py"
tree = ast.parse(topology.read_text(encoding="utf-8"))
monitor_class = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                     and node.name == "TopologyMonitor")
policy_methods = {"_observed_vlan_id", "_resolve_ingress_vlan",
                  "_source_ip_allowed", "_port_allows_vlan",
                  "_send_packet_out_bytes"}
methods = [node for node in monitor_class.body if isinstance(node, ast.FunctionDef)
           and node.name in policy_methods]
assert {node.name for node in methods} == policy_methods

class VlanProtocol:
    pass
class IPv4Protocol:
    pass
class IPv6Protocol:
    pass
class ArpProtocol:
    pass

fake_vlan = SimpleNamespace(vlan=VlanProtocol)
fake_ipv4 = SimpleNamespace(ipv4=IPv4Protocol)
fake_ipv6 = SimpleNamespace(ipv6=IPv6Protocol)
fake_arp = SimpleNamespace(arp=ArpProtocol)

policy_globals = {
    "ALLOWED_VLANS": frozenset({10, 20, 30, 40, 50}),
    "OFPVID_PRESENT": 0x1000,
    "vlan": fake_vlan,
    "ipv4": fake_ipv4,
    "ipv6": fake_ipv6,
    "arp": fake_arp,
    "ipaddress": ipaddress,
}
Policy = type("Policy", (), {})
exec(compile(ast.Module(body=methods, type_ignores=[]), str(topology), "exec"),
     policy_globals)
for method in methods:
    setattr(Policy, method.name, policy_globals[method.name])

class FakePacket:
    def __init__(self, protocols=()):
        self.protocols = dict(protocols)
    def get_protocol(self, key):
        return self.protocols.get(key)

policy = Policy()
policy.vlan_map_ready = True
policy.vlan_port_map = {
    (1, 1): {"kind": "access", "role": "endpoint", "vlan_id": 10,
             "allowed_vlans": frozenset()},
    (1, 2): {"kind": "access", "role": "gateway", "vlan_id": 20,
             "allowed_vlans": frozenset()},
    (1, 3): {"kind": "trunk", "vlan_id": None,
             "allowed_vlans": frozenset({10, 20, 30, 40, 50})},
}
policy.vlan_networks = {
    10: ipaddress.ip_network("10.10.10.0/24"),
    20: ipaddress.ip_network("10.10.20.0/24"),
    30: ipaddress.ip_network("10.10.30.0/24"),
    40: ipaddress.ip_network("10.10.40.0/24"),
    50: ipaddress.ip_network("10.10.50.0/24"),
}

class FakeDatapath:
    id = 1

assert policy._resolve_ingress_vlan(FakeDatapath(), 1,
                                    SimpleNamespace(match={}), FakePacket()) == 10
assert policy._resolve_ingress_vlan(FakeDatapath(), 99,
                                    SimpleNamespace(match={}), FakePacket()) is None
assert policy._resolve_ingress_vlan(FakeDatapath(), 3,
                                    SimpleNamespace(match={}), FakePacket()) is None
assert policy._resolve_ingress_vlan(
    FakeDatapath(), 3,
    SimpleNamespace(match={"vlan_vid": 0x1000 | 30}), FakePacket()) == 30
assert policy._resolve_ingress_vlan(
    FakeDatapath(), 3,
    SimpleNamespace(match={"vlan_vid": 0x1000 | 999}), FakePacket()) is None
assert policy._source_ip_allowed(
    10, FakePacket([(IPv4Protocol, SimpleNamespace(src="10.10.10.15"))]),
    FakeDatapath(), 1)
assert not policy._source_ip_allowed(
    10, FakePacket([(IPv4Protocol, SimpleNamespace(src="10.10.20.15"))]),
    FakeDatapath(), 1)
assert policy._source_ip_allowed(
    20, FakePacket([(IPv4Protocol, SimpleNamespace(src="10.10.10.15"))]),
    FakeDatapath(), 2)  # routed source enters only via the marked gateway port
assert not policy._source_ip_allowed(
    10, FakePacket([(IPv6Protocol, SimpleNamespace(src="2001:db8::1"))]),
    FakeDatapath(), 1)
assert policy._port_allows_vlan(1, 1, 10)
assert not policy._port_allows_vlan(1, 1, 20)
assert policy._port_allows_vlan(1, 3, 50)

class FakeParser:
    @staticmethod
    def OFPActionOutput(port):
        return ("output", port)
    @staticmethod
    def OFPActionPushVlan(ethertype):
        return ("push_vlan", ethertype)
    @staticmethod
    def OFPActionSetField(**kwargs):
        return ("set_field", kwargs)
    @staticmethod
    def OFPActionPopVlan():
        return ("pop_vlan",)
    @staticmethod
    def OFPPacketOut(**kwargs):
        return SimpleNamespace(**kwargs)

class FakeOfproto:
    OFP_NO_BUFFER = 0xFFFFFFFF

class FakeOutDatapath:
    id = 1
    ofproto_parser = FakeParser()
    ofproto = FakeOfproto()
    def __init__(self):
        self.messages = []
    def send_msg(self, message):
        self.messages.append(message)

out_dp = FakeOutDatapath()
policy._send_packet_out_bytes(out_dp, 0xFFFFFFFD, 1, b"arp-reply", 10, False)
assert len(out_dp.messages) == 1
assert out_dp.messages[0].actions == [("output", 1)]
policy._send_packet_out_bytes(out_dp, 0xFFFFFFFD, [3], b"arp-request", 10, False)
assert out_dp.messages[1].actions == [
    ("push_vlan", 0x8100),
    ("set_field", {"vlan_vid": 0x1000 | 10}),
    ("output", 3),
]
policy._send_packet_out_bytes(out_dp, 0xFFFFFFFD, 1, b"wrong-vlan", 20, False)
assert len(out_dp.messages) == 2

print("VLAN integration smoke tests: PASS (publisher + fail-closed policy)")
