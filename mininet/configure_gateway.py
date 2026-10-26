#!/usr/bin/env python3
"""Configure the separate Linux gateway host used by the 38-host topology.

Expected Mininet node: ``gw`` with five interfaces:
  gw-eth0: IoT       10.10.10.1/24 (VLAN 10)
  gw-eth1: Services  10.10.20.1/24 (VLAN 20)
  gw-eth2: DNS       10.10.30.1/24 (VLAN 30)
  gw-eth3: IT        10.10.40.1/24 (VLAN 40)
  gw-eth4: Employees 10.10.50.1/24 (VLAN 50)

This is not the alternative OVS-internal-port gateway attached to s1.
"""

import re


GATEWAY_INTERFACES = {
    "gw-eth0": "10.10.10.1/24",
    "gw-eth1": "10.10.20.1/24",
    "gw-eth2": "10.10.30.1/24",
    "gw-eth3": "10.10.40.1/24",
    "gw-eth4": "10.10.50.1/24",
}

FORWARD_RULES = (
    # Permit return traffic for connections admitted below.
    "iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    # IoT to approved application services and DNS.
    "iptables -A FORWARD -i gw-eth0 -o gw-eth1 -p tcp -m multiport --dports 5000,443 -j ACCEPT",
    "iptables -A FORWARD -i gw-eth0 -o gw-eth2 -p udp --dport 53 -j ACCEPT",
    "iptables -A FORWARD -i gw-eth0 -o gw-eth2 -p tcp --dport 53 -j ACCEPT",
    # Employees to application frontends and DNS.
    "iptables -A FORWARD -i gw-eth4 -o gw-eth1 -p tcp -m multiport --dports 5000,443 -j ACCEPT",
    "iptables -A FORWARD -i gw-eth4 -o gw-eth2 -p udp --dport 53 -j ACCEPT",
    "iptables -A FORWARD -i gw-eth4 -o gw-eth2 -p tcp --dport 53 -j ACCEPT",
    # IT admins to approved service and management ports.
    "iptables -A FORWARD -i gw-eth3 -o gw-eth1 -p tcp -m multiport --dports 22,443,5000 -j ACCEPT",
    "iptables -A FORWARD -i gw-eth3 -o gw-eth0 -p tcp --dport 5000 -j ACCEPT",
    # Services-to-IoT and all other unlisted forwarding are denied by policy.
)

_RC_MARKER = "__SECUREIOT_GATEWAY_RC__"


def _run(gateway, command):
    """Run one command in the Mininet gateway namespace and fail on errors."""
    wrapped = (
        command
        + "; __secureiot_rc=$?; printf '\\n"
        + _RC_MARKER
        + "%s\\n' \"$__secureiot_rc\""
    )
    output = gateway.cmd(wrapped)
    match = re.search(re.escape(_RC_MARKER) + r"(\d+)\s*$", output)
    if not match:
        raise RuntimeError("could not determine gateway command status: " + command)
    rc = int(match.group(1))
    detail = output[:match.start()].strip()
    if detail:
        print("[gateway]", detail)
    if rc != 0:
        raise RuntimeError("gateway command failed (rc=%d): %s" % (rc, command))
    return detail


def configure_gateway(gateway):
    """Set up gw-eth0..4 and the 38-host allowlist firewall policy."""
    for interface, address in GATEWAY_INTERFACES.items():
        _run(gateway, "ip link set dev %s up" % interface)
        _run(gateway, "ip addr flush dev %s" % interface)
        _run(gateway, "ip addr replace %s dev %s" % (address, interface))

    _run(gateway, "sysctl -w net.ipv4.ip_forward=1")

    # The gateway is an isolated Mininet host namespace. Reset its forwarding
    # and NAT rules so repeated lab starts are deterministic and idempotent.
    _run(gateway, "iptables -F")
    _run(gateway, "iptables -t nat -F")
    _run(gateway, "iptables -P FORWARD DROP")
    for rule in FORWARD_RULES:
        _run(gateway, rule)

    print("[gateway] 38-host five-zone gateway configured")
