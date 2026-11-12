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

import os
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
    # Services may reach the host WAN for the server-side ngrok POST. IoT
    # devices remain isolated from the WAN and can only be polled on :8081.
    "iptables -A FORWARD -i gw-eth0.20 -o wan-gw -j ACCEPT",
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
    # Server-side IoT polling: only the sensor HTTP port is allowed from
    # Services to IoT. Devices still cannot initiate telemetry pushes.
    "iptables -A FORWARD -i gw-eth0.20 -o gw-eth0.10 -p tcp --dport 8081 -j ACCEPT",
    # All other Services-to-IoT and unlisted forwarding remain denied.
)

_RC_MARKER = "__SECUREIOT_GATEWAY_RC__"
# Linux interface names are limited to 15 characters.
WAN_HOST_INTERFACE = "sio-wan-host"
WAN_GATEWAY_INTERFACE = "sio-wan-gw"


def _host_run(command):
    """Run a host-namespace command and raise with useful diagnostics."""
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True)
    if result.returncode:
        raise RuntimeError("host command failed (rc=%d): %s\n%s" %
                           (result.returncode, " ".join(command), result.stderr.strip()))
    return result.stdout.strip()


def _wan_interface():
    configured = os.getenv("SECUREIOT_WAN_INTERFACE", "").strip()
    if configured:
        return configured
    route = _host_run(["ip", "route", "get", "8.8.8.8"])
    fields = route.split()
    if "dev" not in fields:
        raise RuntimeError("could not determine host WAN interface from: " + route)
    return fields[fields.index("dev") + 1]


def _host_iptables(table, operation, chain, rule):
    """Install a host iptables rule once, preserving unrelated rules."""
    check = subprocess.run(["iptables", "-t", table, "-C", chain] + rule,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if check.returncode:
        _host_run(["iptables", "-t", table] + operation + [chain] + rule)


def configure_wan(gateway):
    """Attach a host-backed WAN veth, route the lab, and enable NAT."""
    if os.geteuid() != 0:
        raise RuntimeError("WAN setup requires root; start Mininet with sudo")
    gateway_pid = getattr(gateway, "pid", None)
    if not gateway_pid:
        raise RuntimeError("gateway namespace PID is unavailable")
    if subprocess.run(["ip", "link", "show", WAN_HOST_INTERFACE],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        raise RuntimeError("%s already exists; clean up the previous topology" % WAN_HOST_INTERFACE)
    wan = _wan_interface()
    _host_run(["ip", "link", "add", WAN_HOST_INTERFACE, "type", "veth",
               "peer", "name", WAN_GATEWAY_INTERFACE])
    _host_run(["ip", "addr", "replace", "172.31.255.1/30", "dev", WAN_HOST_INTERFACE])
    _host_run(["ip", "link", "set", WAN_HOST_INTERFACE, "up"])
    _host_run(["ip", "link", "set", WAN_GATEWAY_INTERFACE, "netns", str(gateway_pid)])
    _run(gateway, "ip addr replace 172.31.255.2/30 dev %s" % WAN_GATEWAY_INTERFACE)
    _run(gateway, "ip link set dev %s up" % WAN_GATEWAY_INTERFACE)
    _run(gateway, "ip route replace default via 172.31.255.1 dev %s" % WAN_GATEWAY_INTERFACE)
    _host_run(["ip", "route", "replace", "10.10.0.0/16", "via", "172.31.255.2",
               "dev", WAN_HOST_INTERFACE])
    _host_run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    _host_iptables("filter", ["-I"], "FORWARD",
                   ["-d", "10.10.0.0/16", "-i", wan, "-o", WAN_HOST_INTERFACE,
                    "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
    _host_iptables("filter", ["-I"], "FORWARD",
                   ["-s", "10.10.0.0/16", "-i", WAN_HOST_INTERFACE, "-o", wan, "-j", "ACCEPT"])
    _host_iptables("nat", ["-A"], "POSTROUTING",
                   ["-s", "10.10.0.0/16", "-o", wan, "-j", "MASQUERADE"])
    print("[gateway] WAN/NAT configured via %s (Services VLAN egress only)" % wan)


def cleanup_wan():
    """Remove only the lab WAN veth and route; leave host firewall policy intact."""
    subprocess.run(["ip", "route", "del", "10.10.0.0/16", "dev", WAN_HOST_INTERFACE],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "del", WAN_HOST_INTERFACE],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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
