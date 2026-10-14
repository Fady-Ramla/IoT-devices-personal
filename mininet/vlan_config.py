"""Central VLAN configuration for SecureIoT Phase 2.

Phase 2 enables L2 VLAN segmentation. Inter-VLAN L3 routing remains disabled
until the Ryu gateway implementation is added and tested separately.
"""

VLAN_CLIENTS = 10
VLAN_SERVICES = 20
VLAN_DNS = 30
VLAN_MANAGEMENT = 40

VLAN_IDS = (VLAN_CLIENTS, VLAN_SERVICES, VLAN_DNS, VLAN_MANAGEMENT)

VLAN_NETWORKS = {
    VLAN_CLIENTS: "10.10.10.0/24",
    VLAN_SERVICES: "10.10.20.0/24",
    VLAN_DNS: "10.10.30.0/24",
    VLAN_MANAGEMENT: "10.10.40.0/24",
}

VLAN_GATEWAYS = {
    VLAN_CLIENTS: "10.10.10.1",
    VLAN_SERVICES: "10.10.20.1",
    VLAN_DNS: "10.10.30.1",
    VLAN_MANAGEMENT: "10.10.40.1",
}

HOSTS = {
    "h1": (VLAN_DNS, "10.10.30.2/24", VLAN_GATEWAYS[VLAN_DNS]),
    "h2": (VLAN_SERVICES, "10.10.20.2/24", VLAN_GATEWAYS[VLAN_SERVICES]),
    "h3": (VLAN_SERVICES, "10.10.20.3/24", VLAN_GATEWAYS[VLAN_SERVICES]),
    "h4": (VLAN_SERVICES, "10.10.20.4/24", VLAN_GATEWAYS[VLAN_SERVICES]),
    "h5": (VLAN_CLIENTS, "10.10.10.5/24", VLAN_GATEWAYS[VLAN_CLIENTS]),
    "h6": (VLAN_CLIENTS, "10.10.10.6/24", VLAN_GATEWAYS[VLAN_CLIENTS]),
    "h7": (VLAN_CLIENTS, "10.10.10.7/24", VLAN_GATEWAYS[VLAN_CLIENTS]),
    "h8": (VLAN_SERVICES, "10.10.20.8/24", VLAN_GATEWAYS[VLAN_SERVICES]),
    "h9": (VLAN_MANAGEMENT, "10.10.40.9/24", VLAN_GATEWAYS[VLAN_MANAGEMENT]),
    "h10": (VLAN_DNS, "10.10.30.10/24", VLAN_GATEWAYS[VLAN_DNS]),
    "h11": (VLAN_SERVICES, "10.10.20.100/24", VLAN_GATEWAYS[VLAN_SERVICES]),
}

HOST_SWITCH = {
    "h1": "s1", "h2": "s1", "h3": "s2", "h4": "s2",
    "h5": "s3", "h6": "s3", "h7": "s4", "h8": "s4",
    "h9": "s5", "h10": "s6", "h11": "s6",
}

# Every inter-switch link is a trunk in this phase.
TRUNK_PORTS = {
    "s1": ("s1-eth3", "s1-eth4", "s1-eth5"),
    "s2": ("s2-eth3", "s2-eth4", "s2-eth5", "s2-eth6"),
    "s3": ("s3-eth3", "s3-eth4", "s3-eth5", "s3-eth6"),
    "s4": ("s4-eth3", "s4-eth4", "s4-eth5", "s4-eth6"),
    "s5": ("s5-eth2", "s5-eth3", "s5-eth4", "s5-eth5", "s5-eth6"),
    "s6": ("s6-eth2", "s6-eth3"),
}

ACCESS_PORTS = {
    "s1": {"s1-eth1": VLAN_DNS, "s1-eth2": VLAN_SERVICES},
    "s2": {"s2-eth1": VLAN_SERVICES, "s2-eth2": VLAN_SERVICES},
    "s3": {"s3-eth1": VLAN_CLIENTS, "s3-eth2": VLAN_CLIENTS},
    "s4": {"s4-eth1": VLAN_CLIENTS, "s4-eth2": VLAN_SERVICES},
    "s5": {"s5-eth1": VLAN_MANAGEMENT},
    "s6": {"s6-eth1": VLAN_DNS, "s6-eth4": VLAN_SERVICES},
}


def configure_ovs_vlans(net):
    """Configure host access ports and inter-switch trunks after net.start()."""
    allowed = ",".join(str(vlan) for vlan in VLAN_IDS)
    for switch_name, ports in TRUNK_PORTS.items():
        switch = net.get(switch_name)
        for port in ports:
            switch.cmd("ovs-vsctl set Port %s trunks=%s" % (port, allowed))
            switch.cmd("ovs-vsctl clear Port %s tag" % port)
    for switch_name, ports in ACCESS_PORTS.items():
        switch = net.get(switch_name)
        for port, vlan in ports.items():
            switch.cmd("ovs-vsctl set Port %s tag=%d" % (port, vlan))
            switch.cmd("ovs-vsctl clear Port %s trunks" % port)


