"""Proposed VLAN/host map for SecureIoT's 38-host topology.

Derived from the supplied 38-host topology inventory and its declared service
backend IPs. The switch placement for the larger host groups is a proposed
placement because no canonical 38-host vlan_config/design file was found.
Review it before replacing the active config.
"""

VLAN_CLIENTS = 10
VLAN_SERVICES = 20
VLAN_DNS = 30
VLAN_MANAGEMENT = 40
VLAN_EMPLOYEES = 50

VLAN_IDS = (
    VLAN_CLIENTS,
    VLAN_SERVICES,
    VLAN_DNS,
    VLAN_MANAGEMENT,
    VLAN_EMPLOYEES,
)

NETWORKS = {
    VLAN_CLIENTS: "10.10.10.0/24",
    VLAN_SERVICES: "10.10.20.0/24",
    VLAN_DNS: "10.10.30.0/24",
    VLAN_MANAGEMENT: "10.10.40.0/24",
    VLAN_EMPLOYEES: "10.10.50.0/24",
}
VLAN_NETWORKS = NETWORKS

VLAN_GATEWAYS = {
    VLAN_CLIENTS: "10.10.10.1",
    VLAN_SERVICES: "10.10.20.1",
    VLAN_DNS: "10.10.30.1",
    VLAN_MANAGEMENT: "10.10.40.1",
    VLAN_EMPLOYEES: "10.10.50.1",
}

# Proposed 12 switch links: seven retained mesh links plus five Core uplinks.
INTER_SWITCH_LINKS = (
    ("s1", "s2"),
    ("s1", "s5"),
    ("s2", "s4"),
    ("s2", "s5"),
    ("s4", "s5"),
    ("s4", "s6"),
    ("s5", "s6"),
    ("s1", "s3"),
    ("s2", "s3"),
    ("s4", "s3"),
    ("s5", "s3"),
    ("s6", "s3"),
)

SWITCH_NAMES = ("s1", "s2", "s3", "s4", "s5", "s6")

HOSTS = {}


def _add(host_id, switch, vlan, ip, role):
    if host_id in HOSTS:
        raise ValueError("duplicate host ID: " + host_id)
    HOSTS[host_id] = {
        "switch": switch,
        "vlan": vlan,
        "ip": ip + "/24",
        "role": role,
    }


# Primary infrastructure. h1 is DNS; h2/h3/h4 are application/HTTPS/SSH.
_add("h1", "s1", VLAN_DNS, "10.10.30.2", "dns_primary")
_add("h2", "s1", VLAN_SERVICES, "10.10.20.2", "web_api_primary")
_add("h3", "s2", VLAN_SERVICES, "10.10.20.3", "https_primary")
_add("h4", "s2", VLAN_SERVICES, "10.10.20.4", "ssh_primary")

# IoT clients h5-h16 attach to s4; former IoT s3 is now the Core switch.
for host_number in range(5, 17):
    _add(
        "h%d" % host_number,
        "s4",
        VLAN_CLIENTS,
        "10.10.10.%d" % host_number,
        "iot",
    )

# Backup services h17-h20. h18 uses .8 because the supplied load-balancer
# command explicitly lists 10.10.20.8 as its second backend.
_add("h17", "s5", VLAN_DNS, "10.10.30.17", "dns_backup")
_add("h18", "s5", VLAN_SERVICES, "10.10.20.8", "web_api_backup")
_add("h19", "s5", VLAN_SERVICES, "10.10.20.19", "https_backup")
_add("h20", "s5", VLAN_SERVICES, "10.10.20.20", "ssh_backup")

# Employee clients h21-h35; split across s5/s6.
for host_number in range(21, 36):
    switch = "s5" if host_number <= 27 else "s6"
    _add(
        "h%d" % host_number,
        switch,
        VLAN_EMPLOYEES,
        "10.10.50.%d" % host_number,
        "employee",
    )

_add("h36", "s6", VLAN_MANAGEMENT, "10.10.40.36", "it_admin")
_add("h37", "s6", VLAN_MANAGEMENT, "10.10.40.37", "it_admin")
# The service VIP/front-end host uses .100; the supplied topology calls this h38.
_add("h38", "s2", VLAN_SERVICES, "10.10.20.100", "load_balancer")


def host_cidr(host_id):
    """Return the configured IPv4 CIDR for a Mininet host ID."""
    return HOSTS[host_id]["ip"]


def gateway_for(host_id):
    """Return the zone gateway address for a Mininet host ID."""
    return VLAN_GATEWAYS[HOSTS[host_id]["vlan"]]


# Fail early on accidental edits that would invalidate this proposed map.
assert len(HOSTS) == 38, "expected exactly 38 hosts"
assert set(HOSTS) == {"h%d" % n for n in range(1, 39)}
assert len({spec["ip"] for spec in HOSTS.values()}) == 38, "host IPs must be unique"
assert len(INTER_SWITCH_LINKS) == 12, "expected exactly 12 inter-switch links"
assert {spec["vlan"] for spec in HOSTS.values()} <= set(VLAN_IDS)
