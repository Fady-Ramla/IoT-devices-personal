#!/usr/bin/env python3
"""Configure the Linux gateway over one 802.1Q trunk to Core s3.

Expected Mininet node: ``gw`` with one parent interface, ``gw-eth0``.
Five VLAN subinterfaces retain the existing gateway addresses:
  gw-eth0.10: 10.10.10.1/24 (IoT / VLAN 10)
  gw-eth0.20: 10.10.20.1/24 (Services / VLAN 20)
  gw-eth0.30: 10.10.30.1/24 (DNS / VLAN 30)
  gw-eth0.40: 10.10.40.1/24 (IT / VLAN 40)
  gw-eth0.50: 10.10.50.1/24 (Employees / VLAN 50)
"""

import re
import subprocess


GATEWAY_PARENT_INTERFACE = "gw-eth0"
GATEWAY_VLAN_INTERFACES = {
    10: ("gw-eth0.10", "10.10.10.1/24"),
    20: ("gw-eth0.20", "10.10.20.1/24"),
    30: ("gw-eth0.30", "10.10.30.1/24"),
    40: ("gw-eth0.40", "10.10.40.1/24"),
    50: ("gw-eth0.50", "10.10.50.1/24"),
}
GATEWAY_VLAN_MACS = {
    10: "02:10:00:00:00:01",
    20: "02:20:00:00:00:01",
    30: "02:30:00:00:00:01",
    40: "02:40:00:00:00:01",
    50: "02:50:00:00:00:01",
}

FORWARD_RULES = (
    # Permit return traffic for connections admitted below.
    "iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    # Allow all five VLANs to access the Internet through WAN.
    "iptables -A FORWARD -i gw-eth0.10 -o wan-gw -j ACCEPT",
    "iptables -A FORWARD -i gw-eth0.20 -o wan-gw -j ACCEPT",
    "iptables -A FORWARD -i gw-eth0.30 -o wan-gw -j ACCEPT",
    "iptables -A FORWARD -i gw-eth0.40 -o wan-gw -j ACCEPT",
    "iptables -A FORWARD -i gw-eth0.50 -o wan-gw -j ACCEPT",
    # IoT to approved application services and DNS.
    "iptables -A FORWARD -i gw-eth0.10 -o gw-eth0.20 -p tcp -m multiport --dports 5000,443 -j ACCEPT",
    "iptables -A FORWARD -i gw-eth0.10 -o gw-eth0.30 -p udp --dport 53 -j ACCEPT",
    "iptables -A FORWARD -i gw-eth0.10 -o gw-eth0.30 -p tcp --dport 53 -j ACCEPT",
    # Employees to application frontends and DNS.
    "iptables -A FORWARD -i gw-eth0.50 -o gw-eth0.20 -p tcp -m multiport --dports 5000,443 -j ACCEPT",
    "iptables -A FORWARD -i gw-eth0.50 -o gw-eth0.30 -p udp --dport 53 -j ACCEPT",
    "iptables -A FORWARD -i gw-eth0.50 -o gw-eth0.30 -p tcp --dport 53 -j ACCEPT",
    # IT admins to approved service and management ports.
    "iptables -A FORWARD -i gw-eth0.40 -o gw-eth0.20 -p tcp -m multiport --dports 22,443,5000 -j ACCEPT",
    "iptables -A FORWARD -i gw-eth0.40 -o gw-eth0.10 -p tcp --dport 5000 -j ACCEPT",
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



def _host_run(command):
    """Run a command on the Ubuntu host without using a shell."""
    result = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(
            "host command failed (rc=%d): %s\\n%s"
            % (result.returncode, " ".join(command), result.stderr.strip())
        )
    return result.stdout.strip()


def _ensure_host_iptables_rule(table, chain, rule):
    """Add a host firewall rule only when absent, preserving Tailscale chains."""
    check = subprocess.run(
        ["iptables", "-t", table, "-C", chain] + rule,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if check.returncode != 0:
        # Put host WAN forwarding rules before any Tailscale jump in FORWARD.
        action = ["-I", chain, "1"] if table == "filter" and chain == "FORWARD" else ["-A", chain]
        _host_run(["iptables", "-t", table] + action + rule)


def configure_wan(gateway):
    """Create the host-to-gateway WAN veth and configure host routing/NAT."""
    if subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip() != "0":
        raise RuntimeError("WAN setup must run as root (start Mininet with sudo).")

    gateway_pid = getattr(gateway, "pid", None)
    if not gateway_pid:
        raise RuntimeError("Mininet gateway namespace PID is not available.")

    # Do not delete an existing interface: it may belong to another active lab.
    exists = subprocess.run(
        ["ip", "link", "show", "wan-host"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if exists.returncode == 0:
        raise RuntimeError(
            "wan-host already exists. Check for another active topology before continuing."
        )

    _host_run(["ip", "link", "add", "wan-host", "type", "veth",
               "peer", "name", "wan-gw"])
    _host_run(["ip", "addr", "replace", "172.31.255.1/30", "dev", "wan-host"])
    _host_run(["ip", "link", "set", "wan-host", "up"])
    _host_run(["ip", "link", "set", "wan-gw", "netns", str(gateway_pid)])

    _run(gateway, "ip addr replace 172.31.255.2/30 dev wan-gw")
    _run(gateway, "ip link set dev wan-gw up")
    _run(gateway, "ip route replace default via 172.31.255.1 dev wan-gw")

    _host_run([
        "ip", "route", "replace", "10.10.0.0/16",
        "via", "172.31.255.2", "dev", "wan-host"
    ])

    # Enable IPv4 forwarding on the Ubuntu host.
    _host_run(["sysctl", "-w", "net.ipv4.ip_forward=1"])

    # Preserve Tailscale chains and all unrelated host firewall rules.
    _ensure_host_iptables_rule(
        "filter", "FORWARD",
        ["-d", "10.10.0.0/16", "-i", "enp0s3", "-o", "wan-host",
         "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]
    )
    _ensure_host_iptables_rule(
        "filter", "FORWARD",
        ["-s", "10.10.0.0/16", "-i", "wan-host", "-o", "enp0s3", "-j", "ACCEPT"]
    )
    _ensure_host_iptables_rule(
        "nat", "POSTROUTING",
        ["-s", "10.10.0.0/16", "-o", "enp0s3", "-j", "MASQUERADE"]
    )

    print("[gateway] WAN veth, host route, forwarding and NAT configured")

def configure_gateway(gateway):
    """Create five VLAN interfaces on gw-eth0 and install the allowlist firewall."""
    _run(gateway, "ip link set dev %s up" % GATEWAY_PARENT_INTERFACE)

    for vlan_id, (interface, address) in GATEWAY_VLAN_INTERFACES.items():
        # Delete a stale subinterface first so repeated setup stays deterministic.
        _run(gateway, "ip link del dev %s 2>/dev/null || true" % interface)
        _run(
            gateway,
            "ip link add link %s name %s type vlan id %d"
            % (GATEWAY_PARENT_INTERFACE, interface, vlan_id),
        )
        # Linux VLAN subinterfaces inherit the parent MAC by default. Give
        # each VLAN a distinct local MAC because the controller validates
        # learned MAC identities against a single VLAN at a time.
        _run(
            gateway,
            "ip link set dev %s address %s"
            % (interface, GATEWAY_VLAN_MACS[vlan_id]),
        )
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

    print("[gateway] 38-host five-zone gateway configured over one VLAN trunk")
