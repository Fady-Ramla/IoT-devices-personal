#!/usr/bin/env python3
"""SecureIoT Phase 3 PoC: Linux L3 gateway on s1.

This is intentionally a separate, auditable helper. It does not claim to be
Ryu-native routing; Ryu continues to control L2 discovery/forwarding while the
s1 Linux namespace provides VLAN interfaces, IPv4 routing, and the initial
policy firewall.
"""

from vlan_config import VLAN_GATEWAYS, VLAN_IDS

GATEWAY_PORTS = {
    10: "s1-vlan10",
    20: "s1-vlan20",
    30: "s1-vlan30",
    40: "s1-vlan40",
}


def _run(s1, command):
    result = s1.cmd(command)
    if result.strip():
        print("[gateway]", result.strip())


def configure_gateway(s1):
    """Create tagged internal OVS ports, enable IPv4 routing and policy."""
    for vlan in VLAN_IDS:
        port = GATEWAY_PORTS[vlan]
        _run(s1, "ovs-vsctl --may-exist add-port s1 %s tag=%d -- set Interface %s type=internal" % (port, vlan, port))
        _run(s1, "ip link set %s up" % port)
        _run(s1, "ip addr replace %s/24 dev %s" % (VLAN_GATEWAYS[vlan], port))

    _run(s1, "sysctl -w net.ipv4.ip_forward=1 >/dev/null")
    _run(s1, "iptables -N SECUREIOT_FORWARD 2>/dev/null || true")
    _run(s1, "iptables -F SECUREIOT_FORWARD")
    _run(s1, "iptables -C FORWARD -j SECUREIOT_FORWARD 2>/dev/null || iptables -I FORWARD 1 -j SECUREIOT_FORWARD")

    # Stateful return traffic first.
    _run(s1, "iptables -A SECUREIOT_FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

    # VLAN 10 clients -> VLAN 20 services: API and HTTPS only.
    _run(s1, "iptables -A SECUREIOT_FORWARD -s 10.10.10.0/24 -d 10.10.20.0/24 -p tcp -m multiport --dports 5000,443 -j ACCEPT")
    # VLAN 10 clients -> VLAN 30 DNS only.
    _run(s1, "iptables -A SECUREIOT_FORWARD -s 10.10.10.0/24 -d 10.10.30.0/24 -p udp --dport 53 -j ACCEPT")
    _run(s1, "iptables -A SECUREIOT_FORWARD -s 10.10.10.0/24 -d 10.10.30.0/24 -p tcp --dport 53 -j ACCEPT")
    # VLAN 20 services -> VLAN 30 DNS only.
    _run(s1, "iptables -A SECUREIOT_FORWARD -s 10.10.20.0/24 -d 10.10.30.0/24 -p udp --dport 53 -j ACCEPT")
    _run(s1, "iptables -A SECUREIOT_FORWARD -s 10.10.20.0/24 -d 10.10.30.0/24 -p tcp --dport 53 -j ACCEPT")
    # Management SSH to services; no broad management access.
    _run(s1, "iptables -A SECUREIOT_FORWARD -s 10.10.40.0/24 -d 10.10.20.0/24 -p tcp --dport 22 -j ACCEPT")
    # Default deny for routed traffic.
    _run(s1, "iptables -A SECUREIOT_FORWARD -j DROP")

    print("[gateway] VLAN gateways configured:", ", ".join("VLAN %d=%s" % (v, VLAN_GATEWAYS[v]) for v in VLAN_IDS))
    print("[gateway] Inter-VLAN policy: default deny; explicit service ports only")
