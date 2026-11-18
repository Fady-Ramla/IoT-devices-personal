#!/usr/bin/env python3
"""Regression test for IPv4 TCP/UDP fields used in OpenFlow matches."""
import ast
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "topology_monitor.py"


def load_match_helper():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))
    imports_udp = any(
        isinstance(node, ast.ImportFrom)
        and node.module == "ryu.lib.packet"
        and any(alias.name == "udp" for alias in node.names)
        for node in tree.body
    )
    assert imports_udp, "topology_monitor must import ryu.lib.packet.udp"

    class_node = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "TopologyMonitor"
    )
    helper = next(
        node for node in class_node.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_ipv4_flow_match_fields"
    )
    helper.decorator_list = []

    protocol_types = {
        "ipv4": object(),
        "tcp": object(),
        "udp": object(),
    }
    namespace = {
        name: SimpleNamespace(**{name: marker})
        for name, marker in protocol_types.items()
    }
    module = ast.fix_missing_locations(ast.Module(body=[helper], type_ignores=[]))
    exec(compile(module, str(SOURCE), "exec"), namespace)
    return namespace[helper.name], protocol_types


class Packet:
    def __init__(self, protocol_types, ip, tcp=None, udp=None):
        self.values = {
            protocol_types["ipv4"]: ip,
            protocol_types["tcp"]: tcp,
            protocol_types["udp"]: udp,
        }

    def get_protocol(self, protocol_type):
        return self.values.get(protocol_type)


def main():
    helper, types = load_match_helper()

    udp_fields = helper(Packet(
        types,
        SimpleNamespace(proto=17, src="10.0.0.1", dst="10.0.0.2"),
        udp=SimpleNamespace(src_port=53000, dst_port=53),
    ))
    assert udp_fields["udp_src"] == 53000
    assert udp_fields["udp_dst"] == 53
    assert udp_fields["ip_proto"] == 17

    tcp_fields = helper(Packet(
        types,
        SimpleNamespace(proto=6, src="10.0.0.3", dst="10.0.0.4"),
        tcp=SimpleNamespace(src_port=41000, dst_port=5000),
    ))
    assert tcp_fields["tcp_src"] == 41000
    assert tcp_fields["tcp_dst"] == 5000
    assert "udp_src" not in tcp_fields

    print("PASS: UDP and TCP IPv4 flow-match fields are extracted")


if __name__ == "__main__":
    main()
