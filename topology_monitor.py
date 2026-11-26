# ================================================================
# TrustFlow - Topology Monitor  
#
# Responsibilities:
#   - Discover OpenFlow switches
#   - Discover physical inter-switch links using LLDP
#   - Detect link / switch failure fast (PortStatus + LLDP timeout)
#   - Maintain Physical graph and Operational graph (NetworkX)
#   - Learn directly connected hosts, handle ARP
#   - Known unicast: PathEngine decision on the OPERATIONAL graph
#   - Broadcast / unknown unicast: CLFF (no OFPP_FLOOD, no STP)
#   - Flush stale forwarding rules after a link is lost
#   - Notify other components with EventTopologyChanged
#
# Architecture:
#   TopologyMonitor OWNS ALL FORWARDING.
#   TrafficMonitorMerged MUST NOT send forwarding PacketOuts.
#
#   Physical graph     = what physically exists (LLDP reality)
#   Operational graph  = what routing/CLFF may currently use
#                        (physical minus isolated links)
# ================================================================

import ipaddress
import json
import os
from pathlib import Path
import time
import re

import networkx as nx

from path_engine import PathEngine

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import event as controller_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    DEAD_DISPATCHER,
    set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub


# Ryu monitors the same heartbeat file published by h38's Load Balancer.
LB_HEARTBEAT_FILE = os.getenv(
    "SECUREIOT_LB_HEARTBEAT_FILE",
    "/tmp/secureiot_lb_heartbeat.json",
)
LB_HEARTBEAT_MAX_AGE = max(
    2.0, float(os.getenv("SECUREIOT_LB_HEARTBEAT_MAX_AGE", "4.0"))
)
LB_HEARTBEAT_FAILURE_THRESHOLD = max(
    1, int(os.getenv("SECUREIOT_LB_FAILURE_THRESHOLD", "3"))
)
LB_HEARTBEAT_RECOVERY_THRESHOLD = max(
    1, int(os.getenv("SECUREIOT_LB_RECOVERY_THRESHOLD", "3"))
)
LB_HEARTBEAT_MONITOR_INTERVAL = max(
    0.5, float(os.getenv("SECUREIOT_LB_MONITOR_INTERVAL", "1.0"))
)
LB_HEARTBEAT_STARTUP_GRACE = max(
    0.0, float(os.getenv("SECUREIOT_LB_STARTUP_GRACE", "20.0"))
)


def load_balancer_heartbeat_is_healthy(
    heartbeat_file=None, now=None, max_age=None
):
    """Accept only a fresh heartbeat written by a live load_balancer.py."""
    heartbeat_file = heartbeat_file or LB_HEARTBEAT_FILE
    max_age = LB_HEARTBEAT_MAX_AGE if max_age is None else float(max_age)

    try:
        with open(heartbeat_file, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        pid = int(payload["pid"])
        timestamp = float(payload["timestamp"])
    except (OSError, ValueError, TypeError, KeyError):
        return False

    current_time = time.time() if now is None else float(now)
    age = current_time - timestamp

    if pid <= 1 or age < -1.0 or age > max_age:
        return False

    try:
        commandline = Path("/proc/%d/cmdline" % pid).read_bytes()
    except OSError:
        return False

    return b"load_balancer.py" in commandline

from ryu.lib.packet import (
    packet,
    ethernet,
    arp,
    ipv4,
    ipv6,
    vlan,
    tcp,
    udp,
)

try:
    from ryu.lib.packet import lldp
except ImportError:
    lldp = None

try:
    from clff_engine import CLFFEngine
except ImportError:
    CLFFEngine = None


# ================================================================
# Constants
# ================================================================

LLDP_INTERVAL = 3
LLDP_STALE_TIMEOUT = 9          # 3 x interval (PortStatus is the fast path)

LLDP_MAC = "01:80:c2:00:00:0e"

EXPECTED_SWITCHES = int(os.getenv("EXPECTED_SWITCHES", "6"))
EXPECTED_PHYSICAL_LINKS = int(os.getenv("EXPECTED_PHYSICAL_LINKS", "12"))
EXPECTED_SWITCH_NAMES = {"s1", "s2", "s3", "s4", "s5", "s6"}
EXPECTED_VLAN_NETWORKS = {
    10: "10.10.10.0/24",
    20: "10.10.20.0/24",
    30: "10.10.30.0/24",
    40: "10.10.40.0/24",
    50: "10.10.50.0/24",
}
EXPECTED_ENDPOINTS_BY_VLAN = {10: 12, 20: 7, 30: 2, 40: 2, 50: 15}
ALLOWED_VLANS = frozenset(
    int(value) for value in os.getenv("SECUREIOT_ALLOWED_VLANS", "10,20,30,40,50").split(",")
)
if ALLOWED_VLANS != frozenset(EXPECTED_VLAN_NETWORKS):
    raise RuntimeError("TrustFlow 38-host controller requires VLANs 10,20,30,40,50")
VLAN_PORT_MAP_FILE = Path(os.getenv(
    "SECUREIOT_VLAN_PORT_MAP",
    str(Path(__file__).resolve().parent / "New_Datasets" / "config" / "vlan_port_map.json"),
))
OFPVID_PRESENT = 0x1000
OFPVID_NONE = 0x0000
VLAN_PORT_MAP_POLL_INTERVAL = 1

NORMAL_PRIORITY = 10
REROUTE_PRIORITY = 100
DEVICE_BLOCK_PRIORITY = 50000
SERVICE_BLOCK_PRIORITY = 50010
ENDPOINT_BLOCK_PRIORITY = 50020
# Emergency service forwarding must win over the generic LB endpoint drop,
# while remaining below device/service policy priorities.
EMERGENCY_FAILOVER_PRIORITY = 50030

HOST_FLOW_IDLE_TIMEOUT = 30
HOST_FLOW_HARD_TIMEOUT = 0

ETH_TYPE_LLDP = 0x88CC
ETH_TYPE_ARP = 0x0806

CLFF_PACKET_STATE_TIMEOUT = 5
PORT_STATS_INTERVAL = 5
LINK_CAPACITY_BPS = 10_000_000
CONGESTION_REEVAL_INTERVAL = 5
CONGESTION_REROUTE_COOLDOWN = 15

# The controller must understand service targets without importing Mininet.
# Keep a safe fallback for deployments that start Ryu from a reduced checkout.
try:
    from vlan_config_38host import HOSTS, SERVICE_PAIRS, LOAD_BALANCER, host_ip
except ImportError:
    try:
        # Ryu is normally started from the repository root, while the active
        # 38-host configuration lives under mininet/.
        from mininet.vlan_config_38host import (
            HOSTS, SERVICE_PAIRS, LOAD_BALANCER, host_ip
        )
    except ImportError:
        HOSTS = {}
        SERVICE_PAIRS = {
            "dns": {"primary": "h1", "backup": "h17", "port": 53, "vlan": 30},
            "http_api": {"primary": "h2", "backup": "h18", "port": 5000, "vlan": 20},
            "https": {"primary": "h3", "backup": "h19", "port": 443, "vlan": 20},
            "ssh": {"primary": "h4", "backup": "h20", "port": 22, "vlan": 20},
        }
        LOAD_BALANCER = {"host": "h38", "frontends": (53, 5000, 443, 22)}
        def host_ip(host):
            return {"h1": "10.10.30.2", "h2": "10.10.20.2",
                    "h3": "10.10.20.3", "h4": "10.10.20.4",
                    "h17": "10.10.30.17", "h18": "10.10.20.8",
                    "h19": "10.10.20.19", "h20": "10.10.20.20",
                    "h38": "10.10.20.100"}.get(host)


# ================================================================
# Custom Ryu Events
# ================================================================

class EventRerouteHost(controller_event.EventBase):
    """Request host rerouting (sent by TrafficMonitorMerged)."""

    def __init__(self, host_ip, request_id=None):
        super(EventRerouteHost, self).__init__()
        self.host_ip = host_ip
        self.request_id = request_id


class EventTopologyChanged(controller_event.EventBase):
    """
    Sent when the PHYSICAL topology really changed (after baseline).
    Consumed by ResilienceEngine; path selection is delegated to PathEngine.

    added / removed: sets of (dpid_a, dpid_b) sorted tuples.
    """

    def __init__(
        self,
        old_signature,
        new_signature,
        added=None,
        removed=None,
        topology_ready=None
    ):
        super(EventTopologyChanged, self).__init__()
        self.old_signature = old_signature
        self.new_signature = new_signature
        self.added = set(added or set())
        self.removed = set(removed or set())

        # Aliases for compatibility with resilience/path components.
        self.previous_signature = old_signature
        self.current_signature = new_signature
        self.recovered_links = self.added
        self.failed_links = self.removed
        self.topology_ready = topology_ready


# ================================================================
# Topology Monitor
# ================================================================

class TopologyMonitor(app_manager.RyuApp):

    # Client-facing service VIP inventory.
    # DNS is published on VLAN30 and DNATed by the gateway to h38.
    VIP_SERVICES = {
        ("10.10.20.100", 20, 6, 5000),
        ("10.10.20.100", 20, 6, 443),
        ("10.10.20.100", 20, 6, 22),
        ("10.10.30.100", 30, 6, 53),
        ("10.10.30.100", 30, 17, 53),
    }

    # Actual packets observed by OVS after gateway DNAT/SNAT.
    # DNS requests reach the h38 frontend on VLAN20 as 10.10.20.100.
    VIP_DISPATCH_SERVICES = {
        ("10.10.20.100", 20, 6, 5000),
        ("10.10.20.100", 20, 6, 443),
        ("10.10.20.100", 20, 6, 22),
        ("10.10.20.100", 20, 6, 53),
        ("10.10.20.100", 20, 17, 53),
    }

    VIP_TAKEOVER_PRIORITY = 49990
    VIP_FLOW_IDLE_TIMEOUT = 60
    VIP_FLOW_HARD_TIMEOUT = 300

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {}

    _EVENTS = [EventTopologyChanged]

    def __init__(self, *args, **kwargs):
        super(TopologyMonitor, self).__init__(*args, **kwargs)

        self.datapaths = {}

        # Physical topology (reality).
        self.graph = nx.Graph()

        # Operational topology (what routing may use).
        self.operational_graph = nx.Graph()
        self.path_engine = PathEngine(self.operational_graph)

        # Links temporarily removed from routing (sorted tuples).
        self.isolated_links = set()

        # Physical links, sorted tuples.
        self.edges = set()

        # (dpid, port) -> (remote_dpid, remote_port)
        self.port_to_link = {}

        # (dpid, remote_dpid) -> (local_port, remote_port)
        self.link_to_port = {}

        # Every port that was EVER seen carrying LLDP. Never removed,
        # so a dead inter-switch port is never mistaken for a host port.
        self.known_switch_ports = set()

        # Raw LLDP observations.
        self.lldp_links = {}

        # (dpid, port_no) -> name / hardware address from PortDesc.
        self.port_desc = {}
        self.port_hw_addr = {}

        # Keep the exact endpoints while a link is administratively isolated.
        # LLDP mappings disappear after OFPPortMod disables the ports.
        # edge -> ((dpid_a, port_a), (dpid_b, port_b))
        self.isolated_link_ports = {}

        # PortStats samples used by traffic-aware path selection.
        self.port_stats_previous = {}

        # Topology state.
        self.topology_signature = None
        self.topology_change_count = 0
        self.topology_ready = False
        self.full_topology_discovered = False   # baseline reached once

        # Hosts.
        self.host_location = {}
        self.ip_to_mac = {}
        self.mac_to_ip = {}
        self.mac_vlan = {}
        self.ip_vlan = {}

        # Fail-closed VLAN membership learned from Mininet's atomic port map.
        self.vlan_port_map = {}
        self.vlan_networks = {}
        self.vlan_map_ready = False
        self.vlan_map_topology_id = None

        # Explicit Security blocks keyed by normalized source MAC.
        # IP is retained only for audit; enforcement matches eth_src.
        self.blocked_devices = {}
        # Service blocks match the primary backend destination.  This is
        # deliberately separate from device blocks so LB health checks fail
        # closed and the existing load balancer selects its backup backend.
        self.blocked_services = {}
        # LB blocks match both directions for the VIP; the normal device
        # source-MAC block remains intact for backwards compatibility.
        self.blocked_endpoints = {}
        # Service-scoped LB failovers are independent from a full VIP block.
        self.blocked_lb_services = {}
        # Temporary Ryu-as-LB rules are tracked by public service name so a
        # single service can be restored without deleting other failovers.
        self.emergency_failover_flows = []

        # Confirmed OpenFlow batches: FlowMod XIDs are tracked until
        # their BarrierReply, OpenFlow error, timeout, or disconnect.
        self._security_pending_lock = hub.Semaphore(1)
        self._security_xid_transactions = {}
        self._security_openflow_timeout = max(
            0.01,
            float(os.getenv("SECURITY_OPENFLOW_TIMEOUT", "2.0"))
        )

        # VIP takeover can be requested independently by Security or by
        # Load Balancer process-health monitoring.
        self.vip_takeover_active = False
        self.vip_takeover_reasons = set()
        self.vip_takeover_dispatch = {}
        self.vip_takeover_flows = {}

        self.lb_health_takeover_active = False
        self.lb_heartbeat_seen = False
        self.lb_heartbeat_failures = 0
        self.lb_heartbeat_recoveries = 0
        self.lb_monitor_started_at = time.time()

        # Active host-to-host flows (for rerouting).
        self.active_flows = {}
        self.congestion_last_reroute = {}

        # Forwarding rules we installed, so they can be flushed:
        #   (dpid, priority, key) -> match
        self.installed_flows = {}

        # CLFF.
        if CLFFEngine is not None:
            self.clff = CLFFEngine(logger=self.logger)
        else:
            self.clff = None

        self._clff_valid = False
        self.clff_packet_state = {}

        self.lldp_thread = hub.spawn(self._lldp_loop)
        self.port_stats_thread = hub.spawn(self._port_stats_loop)
        # Gateway internal OVS ports are created by Mininet after the
        # switches connect. Re-request PortDesc so they become known host
        # ports instead of remaining invisible to reactive forwarding.
        self.port_desc_thread = hub.spawn(self._port_desc_loop)
        self.congestion_thread = hub.spawn(
            self._congestion_reoptimization_loop
        )
        self.vlan_map_thread = hub.spawn(self._vlan_port_map_loop)
        self.lb_health_thread = hub.spawn(self._lb_heartbeat_loop)

        self.logger.info("TopologyMonitor initialized")
        self.logger.info("Forwarding owner: TopologyMonitor")
        self.logger.info("CLFF: %s",
                         "available" if self.clff else "NOT available")

    def _lb_heartbeat_loop(self):
        """Move VIP traffic to Ryu on LB failure and restore it after recovery."""
        self.logger.info(
            "Load Balancer heartbeat monitor started: file=%s interval=%.1fs",
            LB_HEARTBEAT_FILE,
            LB_HEARTBEAT_MONITOR_INTERVAL,
        )

        while True:
            try:
                healthy = load_balancer_heartbeat_is_healthy()

                if healthy:
                    self.lb_heartbeat_seen = True
                    self.lb_heartbeat_failures = 0
                    self.lb_heartbeat_recoveries += 1

                    if (
                        self.lb_health_takeover_active
                        and self.lb_heartbeat_recoveries
                        >= LB_HEARTBEAT_RECOVERY_THRESHOLD
                    ):
                        result = self.deactivate_vip_takeover(
                            reason="lb_health"
                        )
                        if result.get("success"):
                            self.lb_health_takeover_active = False
                            self.logger.info(
                                "Load Balancer heartbeat recovered; "
                                "Ryu emergency VIP takeover released: %s",
                                result.get("status"),
                            )
                            self.lb_heartbeat_recoveries = 0
                        else:
                            self.logger.error(
                                "Load Balancer recovery detected, but "
                                "VIP failback failed; keeping Ryu takeover: %s",
                                result,
                            )
                            # Retry cleanup on the next monitor cycle.
                            self.lb_heartbeat_recoveries = (
                                LB_HEARTBEAT_RECOVERY_THRESHOLD
                            )
                    elif not self.lb_health_takeover_active:
                        self.lb_heartbeat_recoveries = 0

                else:
                    self.lb_heartbeat_recoveries = 0
                    self.lb_heartbeat_failures += 1

                    startup_grace_elapsed = (
                        self.lb_heartbeat_seen
                        or time.time() - self.lb_monitor_started_at
                        >= LB_HEARTBEAT_STARTUP_GRACE
                    )

                    if (
                        startup_grace_elapsed
                        and not self.lb_health_takeover_active
                        and self.lb_heartbeat_failures
                        >= LB_HEARTBEAT_FAILURE_THRESHOLD
                    ):
                        if (
                            self.vlan_map_ready
                            and self.full_topology_discovered
                        ):
                            result = self.activate_vip_takeover(
                                reason="lb_health"
                            )
                            if result.get("success"):
                                self.lb_health_takeover_active = True
                                self.logger.error(
                                    "Load Balancer heartbeat lost; "
                                    "Ryu emergency VIP takeover active: %s",
                                    result,
                                )
                            elif self.lb_heartbeat_failures % 5 == 0:
                                self.logger.warning(
                                    "Load Balancer is unhealthy; "
                                    "Ryu takeover is waiting for readiness: %s",
                                    result,
                                )
                        elif self.lb_heartbeat_failures % 5 == 0:
                            self.logger.warning(
                                "Load Balancer heartbeat is missing; "
                                "waiting for complete topology before takeover"
                            )

            except Exception:
                self.logger.exception(
                    "Load Balancer heartbeat monitor encountered an error"
                )

            hub.sleep(LB_HEARTBEAT_MONITOR_INTERVAL)

    def _vlan_port_map_loop(self):
        last_signature = None
        while True:
            try:
                stat = VLAN_PORT_MAP_FILE.stat()
                signature = (stat.st_mtime_ns, stat.st_size)
                if signature != last_signature:
                    payload = json.loads(VLAN_PORT_MAP_FILE.read_text(encoding="utf-8"))
                    if payload.get("schema_version") != 2:
                        raise ValueError("unsupported VLAN map schema")
                    if int(payload.get("expected_switches", -1)) != EXPECTED_SWITCHES:
                        raise ValueError("switch-count mismatch in VLAN map")
                    if int(payload.get("expected_inter_switch_links", -1)) != EXPECTED_PHYSICAL_LINKS:
                        raise ValueError("link-count mismatch in VLAN map")
                    if set(int(value) for value in payload.get("allowed_vlans", [])) != set(ALLOWED_VLANS):
                        raise ValueError("allowed VLAN list mismatch")
                    if int(payload.get("host_count", -1)) != 38:
                        raise ValueError("expected 38-host topology map")
                    topology_id = str(payload.get("topology_id", ""))
                    if not re.fullmatch(r"[0-9a-f]{32}", topology_id):
                        raise ValueError("invalid topology ID")

                    networks = {
                        int(vlan_id): ipaddress.ip_network(cidr, strict=True)
                        for vlan_id, cidr in payload.get("networks", {}).items()
                    }
                    expected_networks = {
                        vlan_id: ipaddress.ip_network(cidr, strict=True)
                        for vlan_id, cidr in EXPECTED_VLAN_NETWORKS.items()
                    }
                    if networks != expected_networks:
                        raise ValueError("network/VLAN definitions mismatch")

                    port_map = {}
                    access_count = trunk_count = endpoint_count = gateway_count = 0
                    inter_switch_trunk_count = gateway_trunk_count = 0
                    gateway_trunk_switches = set()
                    endpoint_vlan_counts = {vlan_id: 0 for vlan_id in ALLOWED_VLANS}
                    gateway_vlan_counts = {vlan_id: 0 for vlan_id in ALLOWED_VLANS}
                    switch_names_by_dpid = {}
                    dpids_by_switch_name = {}
                    for row in payload.get("ports", []):
                        dpid, port_no = int(row["dpid"]), int(row["port_no"])
                        switch_name = str(row.get("switch", ""))
                        if switch_name not in EXPECTED_SWITCH_NAMES:
                            raise ValueError("invalid switch identity in VLAN map")
                        if (dpid in switch_names_by_dpid and switch_names_by_dpid[dpid] != switch_name) or (
                            switch_name in dpids_by_switch_name and dpids_by_switch_name[switch_name] != dpid
                        ):
                            raise ValueError("inconsistent switch DPID mapping")
                        switch_names_by_dpid[dpid] = switch_name
                        dpids_by_switch_name[switch_name] = dpid
                        kind = row["kind"]
                        if dpid <= 0 or port_no <= 0 or kind not in ("access", "trunk"):
                            raise ValueError("invalid port-map entry")
                        key = (dpid, port_no)
                        if key in port_map:
                            raise ValueError("duplicate switch port in VLAN map")
                        if kind == "access":
                            if "role" not in row:
                                raise ValueError("access port role missing from VLAN map")
                            vlan_id = int(row["vlan_id"])
                            if vlan_id not in ALLOWED_VLANS:
                                raise ValueError("access port uses disallowed VLAN")
                            role = row.get("role", "endpoint")
                            # Infrastructure/service hosts remain ordinary
                            # VLAN endpoints for forwarding and host learning.
                            if role not in ("endpoint", "infrastructure", "gateway"):
                                raise ValueError("invalid access-port role")
                            entry = {"kind": kind, "role": role, "vlan_id": vlan_id, "allowed_vlans": frozenset()}
                            access_count += 1
                            if role == "gateway":
                                gateway_count += 1
                                gateway_vlan_counts[vlan_id] += 1
                            else:
                                endpoint_count += 1
                                endpoint_vlan_counts[vlan_id] += 1
                        else:
                            allowed = frozenset(int(value) for value in row["allowed_vlans"])
                            if allowed != ALLOWED_VLANS or row.get("vlan_id") is not None:
                                raise ValueError("trunk VLAN set mismatch")
                            role = row.get("role", "endpoint")
                            if role not in ("endpoint", "infrastructure", "gateway"):
                                raise ValueError("invalid trunk-port role")
                            entry = {
                                "kind": kind, "role": role, "vlan_id": None,
                                "allowed_vlans": allowed,
                            }
                            trunk_count += 1
                            if role == "gateway":
                                gateway_trunk_count += 1
                                gateway_trunk_switches.add(switch_name)
                            else:
                                inter_switch_trunk_count += 1
                        port_map[key] = entry

                    dpids = {dpid for dpid, _port in port_map}
                    if (len(dpids) != EXPECTED_SWITCHES or access_count != 38
                            or endpoint_count != 38 or gateway_count != 0
                            or gateway_trunk_count != 1
                            or gateway_trunk_switches != {"s3"}
                            or inter_switch_trunk_count != EXPECTED_PHYSICAL_LINKS * 2
                            or trunk_count != EXPECTED_PHYSICAL_LINKS * 2 + 1
                            or len(port_map) != 38 + EXPECTED_PHYSICAL_LINKS * 2 + 1
                            or set(switch_names_by_dpid.values()) != EXPECTED_SWITCH_NAMES
                            or endpoint_vlan_counts != EXPECTED_ENDPOINTS_BY_VLAN
                            or gateway_vlan_counts != {vlan_id: 0 for vlan_id in ALLOWED_VLANS}):
                        raise ValueError("port-map inventory count mismatch")

                    if self.vlan_map_ready:
                        self._clear_tracked_forwarding_state()
                    self.vlan_port_map = port_map
                    self.vlan_networks = networks
                    self.vlan_map_topology_id = topology_id
                    self.vlan_map_ready = True
                    last_signature = signature
                    self.logger.info(
                        "VLAN map ready topology=%s access=%d trunks=%d",
                        self.vlan_map_topology_id, access_count, trunk_count)
            except FileNotFoundError:
                if self.vlan_map_ready:
                    self.logger.warning("VLAN map removed; data forwarding is fail-closed")
                    self._clear_tracked_forwarding_state()
                self.vlan_port_map = {}
                self.vlan_networks = {}
                self.vlan_map_topology_id = None
                self.vlan_map_ready = False
                last_signature = None
            except Exception:
                if self.vlan_map_ready:
                    self.logger.exception("Invalid VLAN map; data forwarding is fail-closed")
                    self._clear_tracked_forwarding_state()
                self.vlan_port_map = {}
                self.vlan_networks = {}
                self.vlan_map_topology_id = None
                self.vlan_map_ready = False
                last_signature = None
            hub.sleep(VLAN_PORT_MAP_POLL_INTERVAL)

    def _clear_tracked_forwarding_state(self):
        """Delete tracked forwarding flows and learned VLAN identities."""
        for key, match in list(self.installed_flows.items()):
            dpid, priority, _track_key = key
            if priority not in (NORMAL_PRIORITY, REROUTE_PRIORITY, REROUTE_PRIORITY + 1):
                continue
            datapath = self.datapaths.get(dpid)
            if datapath is not None:
                parser, ofproto = datapath.ofproto_parser, datapath.ofproto
                datapath.send_msg(parser.OFPFlowMod(
                    datapath=datapath,
                    command=ofproto.OFPFC_DELETE_STRICT,
                    table_id=0,
                    priority=priority,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=match))
            self.installed_flows.pop(key, None)
        self.host_location.clear()
        self.ip_to_mac.clear()
        self.mac_to_ip.clear()
        self.mac_vlan.clear()
        self.ip_vlan.clear()
        self.active_flows.clear()

    @staticmethod
    def _observed_vlan_id(msg, pkt):
        try:
            raw = msg.match.get("vlan_vid")
            if raw is not None:
                raw = int(raw)
                if raw & OFPVID_PRESENT:
                    return raw & 0x0FFF
                return None
        except (AttributeError, TypeError, ValueError):
            pass
        tag = pkt.get_protocol(vlan.vlan)
        return int(tag.vid) if tag is not None else None

    def _resolve_ingress_vlan(self, datapath, in_port, msg, pkt):
        if not self.vlan_map_ready:
            return None
        entry = self.vlan_port_map.get((int(datapath.id), int(in_port)))
        if entry is None:
            return None
        observed = self._observed_vlan_id(msg, pkt)
        if entry["kind"] == "access":
            expected = entry["vlan_id"]
            return expected if observed in (None, expected) else None
        if observed is None or observed not in entry["allowed_vlans"]:
            return None
        return observed

    def _source_ip_allowed(self, vlan_id, pkt, datapath, in_port):
        network = self.vlan_networks.get(vlan_id)
        if network is None:
            return False
        entry = self.vlan_port_map.get((int(datapath.id), int(in_port)), {})
        if entry.get("role") == "gateway":
            return True
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is not None:
            if ip_pkt.src == "0.0.0.0":
                return True
            try:
                return ipaddress.ip_address(ip_pkt.src) in network
            except ValueError:
                return False
        if pkt.get_protocol(ipv6.ipv6) is not None:
            return False
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt is not None and arp_pkt.src_ip not in (None, "0.0.0.0"):
            try:
                return ipaddress.ip_address(arp_pkt.src_ip) in network
            except ValueError:
                return False
        return True

    # ============================================================
    # Switch connect / disconnect
    # ============================================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        dpid = datapath.id

        self.datapaths[dpid] = datapath
        self.graph.add_node(dpid)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table miss.
        self._add_flow(
            datapath, 0, parser.OFPMatch(),
            [parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        )

        # LLDP to controller.
        self._add_flow(
            datapath, NORMAL_PRIORITY,
            parser.OFPMatch(eth_type=ETH_TYPE_LLDP),
            [parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        )

        # Reinstall Security blocks before the switch handles traffic.
        for mac in list(self.blocked_devices):
            try:
                self._install_device_block_rule(datapath, mac)
            except Exception:
                self.logger.exception(
                    "Failed to restore device block on s%d for %s", dpid, mac)

        for service in list(self.blocked_services):
            try:
                self._install_service_block_rules(datapath, service)
            except Exception:
                self.logger.exception(
                    "Failed to restore service block on s%d for %s", dpid, service)

        for endpoint in list(self.blocked_endpoints):
            endpoint_record = self.blocked_endpoints.get(endpoint, {})
            if endpoint_record.get("mac_only"):
                continue
            try:
                self._install_endpoint_block_rules(datapath, endpoint)
            except Exception:
                self.logger.exception(
                    "Failed to restore endpoint block on s%d for %s", dpid, endpoint)

        # This worker runs after the switch-features event returns. It
        # confirms the h38 MAC drop before restoring VIP dispatch rules.
        if any(
            (record or {}).get("ip") == "10.10.20.100"
            for record in self.blocked_devices.values()
        ):
            hub.spawn(self._restore_h38_vip_on_switch, datapath)

        datapath.send_msg(parser.OFPPortDescStatsRequest(datapath, 0))

        self.logger.info("Switch connected: s%d", dpid)

    def _port_desc_loop(self):
        """Refresh port descriptions for late-created internal OVS ports."""
        while True:
            for datapath in list(self.datapaths.values()):
                try:
                    datapath.send_msg(
                        datapath.ofproto_parser.OFPPortDescStatsRequest(
                            datapath, 0
                        )
                    )
                except Exception:
                    self.logger.debug(
                        "PortDesc refresh failed for s%d",
                        datapath.id,
                        exc_info=True,
                    )
            hub.sleep(2)

    def _send_security_flow_batch(self, datapath, messages, timeout=None):
        """Send FlowMods and confirm the complete batch with a BarrierReply."""
        messages = list(messages or [])
        if not messages:
            return {
                "success": False,
                "status": "empty_batch",
                "barrier_received": False,
                "barrier_error_received": False,
                "openflow_errors": [],
            }

        transaction = {
            "datapath_id": int(datapath.id),
            "event": hub.Event(),
            "xids": [],
            "barrier_xid": None,
            "barrier_received": False,
            "barrier_error_received": False,
            "openflow_errors": [],
            "send_failed": False,
            "send_error": None,
            "disconnected": False,
        }

        lock = self._security_pending_lock
        xid_map = self._security_xid_transactions
        parser = datapath.ofproto_parser

        try:
            # Register every XID before sending any message. This also
            # handles test doubles and fast switches that reply immediately.
            with lock:
                for message in messages:
                    assigned = datapath.set_xid(message)
                    xid = getattr(message, "xid", assigned)
                    if xid is None:
                        raise RuntimeError("FlowMod XID was not assigned")
                    transaction["xids"].append(xid)
                    xid_map[(int(datapath.id), xid)] = transaction

                barrier = parser.OFPBarrierRequest(datapath)
                assigned = datapath.set_xid(barrier)
                barrier_xid = getattr(barrier, "xid", assigned)
                if barrier_xid is None:
                    raise RuntimeError("Barrier XID was not assigned")

                transaction["barrier_xid"] = barrier_xid
                transaction["xids"].append(barrier_xid)
                xid_map[(int(datapath.id), barrier_xid)] = transaction

        except Exception as exc:
            transaction["send_failed"] = True
            transaction["send_error"] = str(exc)

        if not transaction["send_failed"]:
            try:
                for message in messages:
                    result = datapath.send_msg(message)
                    if result is False:
                        raise RuntimeError("FlowMod send_msg returned False")

                result = datapath.send_msg(barrier)
                if result is False:
                    raise RuntimeError("Barrier send_msg returned False")

            except Exception as exc:
                transaction["send_failed"] = True
                transaction["send_error"] = str(exc)
                transaction["event"].set()

        if not transaction["send_failed"]:
            wait_timeout = (
                self._security_openflow_timeout
                if timeout is None else max(0.01, float(timeout))
            )
            try:
                transaction["event"].wait(wait_timeout)
            except Exception as exc:
                transaction["send_failed"] = True
                transaction["send_error"] = "wait failed: %s" % exc

        # A transaction is complete only after a BarrierReply and without
        # an OpenFlow error. A barrier error is not a successful reply.
        if transaction["send_failed"]:
            status = "send_failed"
        elif transaction["disconnected"]:
            status = "disconnected"
        elif (transaction["openflow_errors"]
              or transaction["barrier_error_received"]):
            status = "openflow_error"
        elif transaction["barrier_received"]:
            status = "confirmed"
        else:
            status = "timeout"

        # Remove only this transaction's XID registrations.
        with lock:
            for xid in transaction["xids"]:
                key = (int(datapath.id), xid)
                if xid_map.get(key) is transaction:
                    xid_map.pop(key, None)

        return {
            "success": status == "confirmed",
            "status": status,
            "barrier_received": transaction["barrier_received"],
            "barrier_error_received": transaction["barrier_error_received"],
            "openflow_errors": list(transaction["openflow_errors"]),
            "error": transaction["send_error"],
        }

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def security_openflow_error_handler(self, ev):
        """Associate an OpenFlow error with its pending batch."""
        message = ev.msg
        datapath_id = int(message.datapath.id)
        xid = getattr(message, "xid", None)

        with self._security_pending_lock:
            transaction = self._security_xid_transactions.get(
                (datapath_id, xid)
            )
            if transaction is None:
                return

            if xid == transaction["barrier_xid"]:
                transaction["barrier_error_received"] = True
            else:
                transaction["openflow_errors"].append({
                    "xid": xid,
                    "type": getattr(message, "type", None),
                    "code": getattr(message, "code", None),
                    "data": repr(getattr(message, "data", None)),
                })

            transaction["event"].set()

    @set_ev_cls(ofp_event.EventOFPBarrierReply, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def security_barrier_reply_handler(self, ev):
        """Complete a batch only when its matching BarrierReply arrives."""
        message = ev.msg
        key = (int(message.datapath.id), getattr(message, "xid", None))

        with self._security_pending_lock:
            transaction = self._security_xid_transactions.get(key)
            if transaction is None:
                return
            if key[1] != transaction["barrier_xid"]:
                return

            transaction["barrier_received"] = True
            transaction["event"].set()

    def _fail_security_transactions_for_datapath(self, datapath):
        """Wake all pending batches when a switch disconnects."""
        datapath_id = int(datapath.id)
        with self._security_pending_lock:
            pending = {
                id(transaction): transaction
                for (dpid, _xid), transaction
                in self._security_xid_transactions.items()
                if dpid == datapath_id
            }

            for transaction in pending.values():
                transaction["disconnected"] = True
                transaction["event"].set()

    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def state_change_handler(self, ev):

        datapath = ev.datapath
        self._fail_security_transactions_for_datapath(datapath)

        if datapath is None:
            return

        dpid = datapath.id

        # Ignore if a newer connection already replaced this one.
        if self.datapaths.get(dpid) is not datapath:
            return

        del self.datapaths[dpid]

        # A disconnected switch no longer has confirmed block or VIP rules.
        for record in self.blocked_devices.values():
            if (record or {}).get("ip") == "10.10.20.100":
                confirmed = set(
                    int(value)
                    for value in record.get("confirmed_switches", [])
                )
                confirmed.discard(int(dpid))
                record["confirmed_switches"] = sorted(confirmed)
                record["enforcement_status"] = "partial_failure"

        self.vip_takeover_dispatch.pop(int(dpid), None)
        self.vip_takeover_flows = {
            key: value
            for key, value in self.vip_takeover_flows.items()
            if int(value[0]) != int(dpid)
        }

        self.logger.warning("Switch disconnected: s%d", dpid)

        for key, info in list(self.lldp_links.items()):
            if key[0] == dpid or info["remote_dpid"] == dpid:
                del self.lldp_links[key]

        for key in [k for k in self.port_desc if k[0] == dpid]:
            del self.port_desc[key]
            self.port_hw_addr.pop(key, None)

        for key in [k for k in self.installed_flows if k[0] == dpid]:
            del self.installed_flows[key]

        self._update_topology_from_lldp()

    # ============================================================
    # Port description / port status
    # ============================================================

    @staticmethod
    def _decode_port_name(name):
        if isinstance(name, bytes):
            try:
                return name.decode("utf-8", errors="ignore")
            except Exception:
                return str(name)
        return str(name)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_reply_handler(self, ev):

        dpid = ev.msg.datapath.id

        for port in ev.msg.body:
            port_no = int(port.port_no)
            key = (dpid, port_no)
            self.port_desc[key] = self._decode_port_name(port.name)
            hw_addr = getattr(port, "hw_addr", None)
            if hw_addr:
                self.port_hw_addr[key] = hw_addr

        # An isolated link must remain physically blocked if a switch
        # reconnects and its port configuration was reset by the switch.
        for endpoints in list(self.isolated_link_ports.values()):
            for endpoint_dpid, endpoint_port in endpoints:
                if endpoint_dpid == dpid:
                    self._set_port_admin_down(
                        endpoint_dpid, endpoint_port, down=True)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """Convert PortStats deltas into operational link utilization."""
        dpid = ev.msg.datapath.id
        now = time.time()

        for stat in ev.msg.body:
            port_no = int(stat.port_no)
            peer = self.port_to_link.get((dpid, port_no))

            if peer is None:
                continue

            counter = int(stat.rx_bytes) + int(stat.tx_bytes)
            key = (dpid, port_no)
            previous = self.port_stats_previous.get(key)
            self.port_stats_previous[key] = (counter, now)

            if previous is None:
                continue

            old_counter, old_time = previous
            elapsed = now - old_time

            if elapsed <= 0 or counter < old_counter:
                continue

            rate_bps = ((counter - old_counter) * 8.0) / elapsed
            utilization = min(rate_bps / LINK_CAPACITY_BPS, 1.0)

            self.update_link_metric(
                dpid,
                peer[0],
                utilization=utilization,
                rate_bps=rate_bps,
                capacity_bps=LINK_CAPACITY_BPS
            )

            self.logger.info(
                "LINK UTILIZATION: s%d-s%d rate=%.2f Mbps utilization=%.1f%%",
                dpid,
                peer[0],
                rate_bps / 1_000_000.0,
                utilization * 100.0,
            )

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        """
        FAST failure detection (well below the LLDP timeout).
        """

        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofp = datapath.ofproto
        desc = msg.desc
        port_no = desc.port_no

        if self._is_special_port(port_no):
            return

        key = (int(dpid), int(port_no))
        previous_name = self.port_desc.get(key, "")
        current_name = self._decode_port_name(
            getattr(desc, "name", "") or ""
        )

        # OVS mirror output ports are capture-only. Keep their identity
        # for filtering, but never start LLDP or modify topology for them.
        is_mirror = (
            current_name.startswith("sec-mir-")
            or str(previous_name).startswith("sec-mir-")
        )
        if is_mirror:
            if msg.reason == ofp.OFPPR_DELETE:
                self.port_desc.pop(key, None)
                getattr(self, "port_hw_addr", {}).pop(key, None)
            else:
                self.port_desc[key] = current_name
                hw_addr = getattr(desc, "hw_addr", None)
                if hw_addr:
                    self.port_hw_addr[key] = hw_addr
            return

        if msg.reason == ofp.OFPPR_DELETE:
            self.port_desc.pop(key, None)
            self.port_hw_addr.pop(key, None)
            down = True
        else:
            self.port_desc[key] = current_name
            down = bool(desc.state & ofp.OFPPS_LINK_DOWN) or \
                bool(desc.config & ofp.OFPPC_PORT_DOWN)

        if down:
            self.logger.warning(
                "PortStatus: s%d:%d is DOWN", dpid, port_no)

            self._remove_lldp_for_port(dpid, port_no)
            self._update_topology_from_lldp()

        else:
            # Port came back: probe immediately instead of waiting.
            try:
                self._send_lldp(datapath, port_no)
            except Exception:
                pass

    def _remove_lldp_for_port(self, dpid, port_no):

        self.lldp_links.pop((dpid, port_no), None)

        for key, info in list(self.lldp_links.items()):
            if (info["remote_dpid"] == dpid
                    and info["remote_port"] == port_no):
                del self.lldp_links[key]

    # SECUREIOT_ICMP_FLOWSTATS_V1: build exact IPv4 matches for FlowStats.
    @staticmethod
    def _flow_stats_match_fields(pkt):
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            return None

        try:
            protocol = int(ip_pkt.proto)
        except (TypeError, ValueError):
            return None

        fields = {
            "eth_type": 0x0800,
            "ipv4_src": str(ip_pkt.src),
            "ipv4_dst": str(ip_pkt.dst),
            "ip_proto": protocol,
        }

        if protocol == 6:
            transport = pkt.get_protocol(tcp.tcp)
            if transport is None:
                return None
            fields["tcp_src"] = int(transport.src_port)
            fields["tcp_dst"] = int(transport.dst_port)
        elif protocol == 17:
            transport = pkt.get_protocol(udp.udp)
            if transport is None:
                return None
            fields["udp_src"] = int(transport.src_port)
            fields["udp_dst"] = int(transport.dst_port)
        elif protocol == 1:
            # ICMPv4 has no TCP/UDP ports. The IP 5-tuple equivalent is the
            # two IP addresses plus protocol number; echo request/reply are
            # separated by direction (src/dst are reversed).
            pass
        else:
            return None

        return fields

    @staticmethod
    def _reverse_flow_stats_fields(flow_match_fields):
        if not flow_match_fields:
            return None
        fields = dict(flow_match_fields)
        if "ipv4_src" in fields and "ipv4_dst" in fields:
            fields["ipv4_src"], fields["ipv4_dst"] = (
                fields["ipv4_dst"], fields["ipv4_src"]
            )
        for source_field, destination_field in (
            ("tcp_src", "tcp_dst"),
            ("udp_src", "udp_dst"),
        ):
            if source_field in fields and destination_field in fields:
                fields[source_field], fields[destination_field] = (
                    fields[destination_field], fields[source_field]
                )
        return fields

    # ============================================================
    # Packet-In
    # ============================================================

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        if "in_port" not in msg.match:
            return

        try:
            in_port = int(msg.match["in_port"])
        except (TypeError, ValueError):
            return

        # Mirrored copies must never enter the normal learning/forwarding path.
        if self._is_security_mirror_port(dpid, in_port):
            return

        try:
            pkt = packet.Packet(msg.data)
        except Exception:
            return

        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        if eth_pkt is None:
            return

        src_mac = eth_pkt.src
        dst_mac = eth_pkt.dst

        # LLDP.
        if eth_pkt.ethertype == ETH_TYPE_LLDP:
            self._handle_lldp(datapath, in_port, pkt)
            return

        if str(dst_mac).lower() == LLDP_MAC:
            return

        # Defense-in-depth if a packet reaches the controller before a
        # datapath drop rule has taken effect.
        if self.is_device_blocked(src_mac):
            self.logger.warning(
                "Packet dropped from explicitly blocked MAC %s on s%d",
                src_mac, dpid)
            return

        # Do not learn / forward before the baseline topology exists.
        # (Otherwise inter-switch ports look like host ports.)
        if not self.full_topology_discovered:
            return

        vlan_id = self._resolve_ingress_vlan(datapath, in_port, msg, pkt)
        if vlan_id is None:
            self.logger.warning(
                "Drop packet with unknown/invalid VLAN membership on s%d:%d",
                dpid, in_port)
            return
        if not self._source_ip_allowed(vlan_id, pkt, datapath, in_port):
            self.logger.warning(
                "Drop source IP outside VLAN %d subnet on s%d:%d",
                vlan_id, dpid, in_port)
            return

        # VIP takeover claims matching packets before normal ARP,
        # learning, flooding, or unicast forwarding.
        if self._handle_vip_packet(
                datapath, msg, pkt, vlan_id, defer=True):
            return

        # Build a protocol-specific IPv4 classifier. These rules preserve the
        # same VLAN-aware forwarding actions while exposing per-flow counters.
        flow_match_fields = self._flow_stats_match_fields(pkt)
        ipv4_packet = pkt.get_protocol(ipv4.ipv4) is not None

        # ARP: learn, and answer from the controller when possible.
        arp_pkt = pkt.get_protocol(arp.arp)

        if arp_pkt is not None:
            if str(arp_pkt.src_mac).lower() != str(src_mac).lower():
                self.logger.warning("Drop ARP Ethernet/source MAC mismatch on s%d:%d", dpid, in_port)
                return

            self._learn_from_arp(dpid, in_port, arp_pkt, vlan_id)

            if (arp_pkt.opcode == arp.ARP_REQUEST
                    and self._try_proxy_arp(datapath, in_port, arp_pkt, vlan_id)):
                return

        # Host learning.
        if not self.is_inter_switch_port(dpid, in_port):
            self._learn_host(dpid, in_port, src_mac, pkt, vlan_id)
        if self.mac_vlan.get(src_mac) != vlan_id:
            self.logger.warning("Drop source MAC %s outside learned VLAN %d", src_mac, vlan_id)
            return

        # Broadcast / multicast -> CLFF.
        if self._is_broadcast_or_multicast(dst_mac):
            self._flood_ethernet(datapath, msg, in_port, vlan_id)
            return

        # Known destination.
        destination = self.host_location.get(dst_mac)

        if destination is None:
            self._flood_ethernet(datapath, msg, in_port, vlan_id)
            return

        if self.mac_vlan.get(dst_mac) != vlan_id:
            self.logger.warning(
                "Drop cross-VLAN unicast VLAN %d -> learned VLAN %s MAC %s",
                vlan_id, self.mac_vlan.get(dst_mac), dst_mac)
            return

        dst_dpid, dst_port = destination

        # Same switch.
        if dst_dpid == dpid:

            if dst_port == in_port:
                return

            if flow_match_fields is not None:
                self._install_output_flow(
                    datapath, in_port, dst_mac, dst_port, vlan_id,
                    flow_match_fields=flow_match_fields,
                )
            elif not ipv4_packet and arp_pkt is None:
                self._install_output_flow(
                    datapath, in_port, dst_mac, dst_port, vlan_id
                )
            # Do not install an L2-only rule for ARP or an unsupported IPv4
            # packet: it would mask later protocol-specific FlowStats rules.
            self._packet_out(datapath, msg, dst_port, vlan_id)
            return

        # Different switch: prefer the full path from the source's switch.
        src_loc = self.host_location.get(src_mac)

        path = None

        if src_loc is not None:
            candidate = self._shortest_path(src_loc[0], dst_dpid)
            if candidate and dpid in candidate:
                path = candidate

        if path is None:
            path = self._shortest_path(dpid, dst_dpid)

        if not path:
            self.logger.warning(
                "No path from s%d to s%d for %s", dpid, dst_dpid, dst_mac)
            return

        out_port = self._next_port_on_path(path, dpid, dst_port)

        if out_port is None:
            self.logger.warning(
                "No forwarding port on s%d towards s%d", dpid, dst_dpid)
            return

        if flow_match_fields is not None:
            self._install_path(
                path, src_mac, dst_mac, vlan_id,
                flow_match_fields=flow_match_fields,
            )
        elif not ipv4_packet and arp_pkt is None:
            self._install_path(path, src_mac, dst_mac, vlan_id)
        # ARP and unsupported IPv4 packets use PacketOut only. This prevents
        # a broad L2 path rule from swallowing the subsequent ICMP/TCP/UDP flow.

        self.register_active_flow(
            ("vlan_mac", vlan_id, src_mac, dst_mac),
            {
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "vlan_id": vlan_id,
                "src_ip": self.mac_to_ip.get(src_mac),
                "dst_ip": self.mac_to_ip.get(dst_mac),
                "flow_match_fields": (
                    dict(flow_match_fields) if flow_match_fields else None
                ),
                "path": list(path),
            }
        )

        self._packet_out(datapath, msg, out_port, vlan_id)

    # ============================================================
    # LLDP receive
    # ============================================================

    def _handle_lldp(self, datapath, in_port, pkt):

        if lldp is None or not self.vlan_map_ready:
            return
        ingress = self.vlan_port_map.get((int(datapath.id), int(in_port)))
        if ingress is None or ingress["kind"] != "trunk":
            return

        dpid = datapath.id

        lldp_pkt = pkt.get_protocol(lldp.lldp)

        if lldp_pkt is None:
            return

        remote_dpid = None
        remote_port = None

        for tlv in lldp_pkt.tlvs:

            if isinstance(tlv, lldp.ChassisID):
                try:
                    remote_dpid = int(tlv.chassis_id.decode())
                except Exception:
                    try:
                        remote_dpid = int(tlv.chassis_id)
                    except Exception:
                        pass

            elif isinstance(tlv, lldp.PortID):
                try:
                    remote_port = int(tlv.port_id.decode())
                except Exception:
                    try:
                        remote_port = int(tlv.port_id)
                    except Exception:
                        pass

        if remote_dpid is None or remote_port is None:
            return

        if remote_dpid == dpid:
            return

        # Remember forever: these are inter-switch ports.
        self.known_switch_ports.add((dpid, in_port))
        self.known_switch_ports.add((remote_dpid, remote_port))

        self.lldp_links[(dpid, in_port)] = {
            "remote_dpid": remote_dpid,
            "remote_port": remote_port,
            "last_seen": time.time(),
        }

        self._update_topology_from_lldp()

    # ============================================================
    # Topology signature / readiness
    # ============================================================

    @staticmethod
    def _calculate_topology_signature(edges):
        """Order-independent signature of the physical links."""

        normalized = set()

        for a, b in edges:
            try:
                edge = tuple(sorted((int(a), int(b))))
            except (TypeError, ValueError):
                continue

            if edge[0] != edge[1]:
                normalized.add(edge)

        return tuple(sorted(normalized))

    def _check_topology_readiness(self):
        """
        Baseline (first time): 6 switches + 11 links + connected.
        After baseline: only "connected" matters, so the network stays
        operational (and CLFF keeps being rebuilt) while degraded.
        """

        node_count = self.graph.number_of_nodes()

        if node_count == 0:
            return False

        if not self.full_topology_discovered:

            if node_count != EXPECTED_SWITCHES:
                return False

            if self.graph.number_of_edges() != EXPECTED_PHYSICAL_LINKS:
                return False

            if not nx.is_connected(self.graph):
                return False

            self.full_topology_discovered = True
            return True

        return nx.is_connected(self.graph)

    # ============================================================
    # Update topology from LLDP state
    # ============================================================

    def _update_topology_from_lldp(self):

        now = time.time()

        # Drop stale LLDP entries.
        for key in [k for k, v in self.lldp_links.items()
                    if now - v["last_seen"] > LLDP_STALE_TIMEOUT]:
            del self.lldp_links[key]

        new_port_to_link = {}
        new_link_to_port = {}
        new_edges = set()

        for (ldpid, lport), info in list(self.lldp_links.items()):

            rdpid = info["remote_dpid"]
            rport = info["remote_port"]

            if ldpid == rdpid:
                continue

            # Both ends must be connected switches.
            if ldpid not in self.datapaths or rdpid not in self.datapaths:
                continue

            # Require a reciprocal LLDP observation. A single stale
            # observation from one side must not recreate a failed link.
            reverse = self.lldp_links.get((rdpid, rport))

            if reverse is None:
                continue

            if (
                reverse["remote_dpid"] != ldpid
                or reverse["remote_port"] != lport
            ):
                continue

            new_port_to_link[(ldpid, lport)] = (rdpid, rport)
            new_port_to_link[(rdpid, rport)] = (ldpid, lport)

            new_edges.add(tuple(sorted((ldpid, rdpid))))

            new_link_to_port[(ldpid, rdpid)] = (lport, rport)
            new_link_to_port[(rdpid, ldpid)] = (rport, lport)

        old_edges = set(self.edges)
        previous_signature = self.topology_signature
        new_signature = self._calculate_topology_signature(new_edges)

        topology_changed = new_signature != previous_signature
        was_discovered = self.full_topology_discovered
        was_ready = self.topology_ready

        # Publish new physical state.
        self.graph.clear()

        for dpid in self.datapaths:
            self.graph.add_node(dpid)

        for a, b in new_edges:
            self.graph.add_edge(a, b, weight=1)

        self.port_to_link = new_port_to_link
        self.link_to_port = new_link_to_port
        self.edges = new_edges
        self.topology_signature = new_signature

        self._rebuild_operational_graph()

        self.topology_ready = self._check_topology_readiness()

        became_ready = self.topology_ready and not was_ready

        # A "real" change = after the baseline was established.
        real_change = topology_changed and was_discovered

        added = new_edges - old_edges
        removed = old_edges - new_edges

        if became_ready and not was_discovered:
            self.logger.info(
                "NETWORK READY: switches=%d links=%d connected=True",
                self.graph.number_of_nodes(),
                self.graph.number_of_edges())

        if real_change:

            self.topology_change_count += 1

            self.logger.warning(
                "PHYSICAL TOPOLOGY CHANGED (#%d): added=%s removed=%s",
                self.topology_change_count, sorted(added), sorted(removed))

            # Rules built on the old topology may point to dead ports.
            if removed:
                self._flush_forwarding_flows()

        if real_change or became_ready:
            self._refresh_clff()

        if real_change:
            self.send_event_to_observers(
                EventTopologyChanged(
                    previous_signature,
                    new_signature,
                    added,
                    removed,
                    topology_ready=self.topology_ready
                )
            )

        if was_ready and not self.topology_ready:
            self.logger.warning(
                "NETWORK NO LONGER READY (graph disconnected): "
                "switches=%d links=%d",
                self.graph.number_of_nodes(),
                self.graph.number_of_edges())

    # ============================================================
    # Explicit Security device enforcement (MAC identity)
    # ============================================================

    @staticmethod
    def normalize_device_mac(mac):
        if not isinstance(mac, str):
            raise ValueError("mac is required and must be a string")
        mac = mac.strip().lower()
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            raise ValueError("mac must be a colon-separated 6-byte address")
        return mac

    def is_device_blocked(self, mac):
        try:
            return self.normalize_device_mac(mac) in self.blocked_devices
        except ValueError:
            return False

    def _install_device_block_rule(self, datapath, mac):
        mac = self.normalize_device_mac(mac)
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_src=mac)
        # Empty actions are an OpenFlow drop. Priority overrides every
        # normal/reroute flow, and the source-MAC match is IP-independent.
        self._add_flow(
            datapath, DEVICE_BLOCK_PRIORITY, match, [],
            track_key=None)

    def _delete_device_block_rule(self, datapath, mac):
        mac = self.normalize_device_mac(mac)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE_STRICT,
            table_id=0,
            priority=DEVICE_BLOCK_PRIORITY,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch(eth_src=mac)))

    @staticmethod
    def _service_rule_specs(service):
        if service not in SERVICE_PAIRS:
            raise ValueError("unknown service: %s" % service)
        pair = SERVICE_PAIRS[service]
        address = host_ip(pair["primary"])
        if not address:
            raise ValueError("no primary address configured for service: %s" % service)
        port = int(pair["port"])
        protocols = (17, 6) if port == 53 else (6,)
        return address, port, protocols

    def classify_security_target(self, ip=None, mac=None):
        """Resolve a Security MAC/IP to a known service, LB, or device.

        Security can keep sending the existing ``mac``/``ip`` contract.  The
        controller owns the topology inventory and therefore decides whether
        the identity is an IoT device, a primary service backend, or the LB.
        Only a *primary* backend is promoted to a service failover target;
        backup and unknown hosts remain ordinary device targets.
        """
        address = str(ip).strip() if ip else None
        if not address and mac:
            try:
                normalized = self.normalize_device_mac(mac)
                address = self.mac_to_ip.get(normalized)
            except ValueError:
                address = None
        if address:
            try:
                address = str(ipaddress.ip_address(address))
            except ValueError:
                address = None
        if not address:
            return {"target_type": "device", "ip": None, "service": None}
        lb_address = host_ip(LOAD_BALANCER["host"])
        if address == lb_address:
            return {"target_type": "load_balancer", "ip": address, "service": None}
        for service, pair in SERVICE_PAIRS.items():
            if address == host_ip(pair["primary"]):
                return {"target_type": "service", "ip": address, "service": service}
        return {"target_type": "device", "ip": address, "service": None}

    def _install_service_block_rules(self, datapath, service):
        address, port, protocols = self._service_rule_specs(service)
        parser = datapath.ofproto_parser
        for protocol in protocols:
            fields = {
                "eth_type": 0x0800,
                "ipv4_dst": address,
                "ip_proto": protocol,
            }
            fields["udp_dst" if protocol == 17 else "tcp_dst"] = port
            self._add_flow(datapath, SERVICE_BLOCK_PRIORITY,
                           parser.OFPMatch(**fields), [], track_key=None)

    def _install_endpoint_block_rules(self, endpoint):
        address = str(self.blocked_endpoints[endpoint]["ip"])
        for datapath in list(self.datapaths.values()):
            parser = datapath.ofproto_parser
            for field in ("ipv4_src", "ipv4_dst"):
                self._add_flow(
                    datapath, ENDPOINT_BLOCK_PRIORITY,
                    parser.OFPMatch(eth_type=0x0800, **{field: address}),
                    [], track_key=None)

    def _delete_service_block_rules(self, datapath, service):
        address, port, protocols = self._service_rule_specs(service)
        parser, ofproto = datapath.ofproto_parser, datapath.ofproto
        for protocol in protocols:
            fields = {"eth_type": 0x0800, "ipv4_dst": address, "ip_proto": protocol}
            fields["udp_dst" if protocol == 17 else "tcp_dst"] = port
            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath, command=ofproto.OFPFC_DELETE_STRICT,
                table_id=0, priority=SERVICE_BLOCK_PRIORITY,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                match=parser.OFPMatch(**fields)))

    def _delete_endpoint_block_rules(self, datapath, address):
        parser, ofproto = datapath.ofproto_parser, datapath.ofproto
        for field in ("ipv4_src", "ipv4_dst"):
            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath, command=ofproto.OFPFC_DELETE_STRICT,
                table_id=0, priority=ENDPOINT_BLOCK_PRIORITY,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                match=parser.OFPMatch(eth_type=0x0800, **{field: address})))

    def block_service(self, service, request_id=None, reason=None):
        """Block only the primary backend; LB health checks then select backup."""
        service = str(service).strip().lower()
        address, port, _protocols = self._service_rule_specs(service)
        self.blocked_services[service] = {
            "service": service, "primary_ip": address, "port": port,
            "request_id": request_id, "reason": reason, "blocked_at": time.time(),
        }
        failed = []
        for datapath in list(self.datapaths.values()):
            try:
                self._install_service_block_rules(datapath, service)
            except Exception:
                failed.append(datapath.id)
                self.logger.exception("Failed to block service %s on s%d", service, datapath.id)
        return {"success": not failed, "status": "executed" if not failed else "partial_failure",
                "action": "BLOCK_SERVICE", "service": service, "primary_ip": address,
                "failed_switches": failed, "request_id": request_id}

    def unblock_service(self, service, request_id=None, reason=None):
        service = str(service).strip().lower()
        if service not in self.blocked_services:
            return {"success": False, "status": "not_blocked", "action": "UNBLOCK_SERVICE",
                    "service": service, "request_id": request_id}
        failed = []
        for datapath in list(self.datapaths.values()):
            try:
                self._delete_service_block_rules(datapath, service)
            except Exception:
                failed.append(datapath.id)
                self.logger.exception("Failed to unblock service %s on s%d", service, datapath.id)
        if failed:
            return {"success": False, "status": "partial_failure", "action": "UNBLOCK_SERVICE",
                    "service": service, "failed_switches": failed, "request_id": request_id}
        self.blocked_services.pop(service, None)
        return {"success": True, "status": "executed", "action": "UNBLOCK_SERVICE",
                "service": service, "request_id": request_id}

    def _emergency_service_specs(self):
        """Return the temporary frontend -> backup service mappings.

        Every configured service pair is eligible only when its service port
        is explicitly exposed by LOAD_BALANCER.frontends.
        """
        lb_ip = host_ip(LOAD_BALANCER["host"])
        frontend_ports = {int(port) for port in LOAD_BALANCER.get("frontends", ())}
        specs = {}
        public_names = {
            "dns": "dns", "http_api": "http",
            "https": "https", "ssh": "ssh",
        }
        for service, pair in SERVICE_PAIRS.items():
            port = int(pair["port"])
            if port not in frontend_ports or service not in public_names:
                continue
            primary_ip = host_ip(pair["primary"])
            backup_ip = host_ip(pair["backup"])
            if not primary_ip or not backup_ip:
                continue
            public_name = public_names[service]
            specs[public_name] = {
                "service": service,
                "frontend_ip": lb_ip,
                "primary_ip": primary_ip,
                "backup_ip": backup_ip,
                "port": port,
                "protocols": (17, 6) if port == 53 else (6,),
                "vlan": int(pair.get("vlan", self.ip_vlan.get(
                    primary_ip, 20))),
            }
        return specs

    def _install_emergency_flow(self, datapath, match, actions, public_name):
        self._add_flow(datapath, EMERGENCY_FAILOVER_PRIORITY, match, actions)
        self.emergency_failover_flows.append((datapath, match, public_name))

    def _install_emergency_service(self, public_name, spec, frontend_mac=None):
        """Forward a VIP frontend through Ryu from the gateway to its backup.

        Requests enter on the gateway trunk after DNAT. Responses return to
        that trunk after their source identity is restored to the VIP; neither
        direction is sent to the blocked h38 access port.
        """
        endpoint = self.blocked_endpoints.get("load_balancer", {})
        frontend_mac = (endpoint.get("mac") or frontend_mac
                        or self.ip_to_mac.get(spec["frontend_ip"]))
        backup_mac = self.ip_to_mac.get(spec["backup_ip"])
        frontend_mac = self.normalize_device_mac(frontend_mac) if frontend_mac else None
        backup_loc = self.host_location.get(backup_mac) if backup_mac else None
        gateway_ports = [
            (int(dpid), int(port_no))
            for (dpid, port_no), entry in self.vlan_port_map.items()
            if entry.get("role") == "gateway"
            and entry.get("kind") == "trunk"
            and spec["vlan"] in entry.get("allowed_vlans", ())
        ]
        if len(gateway_ports) != 1:
            raise RuntimeError("expected one gateway trunk for %s failover" % public_name)
        gateway_dpid, gateway_port = gateway_ports[0]
        if not frontend_mac or not backup_mac or not backup_loc:
            raise RuntimeError("missing learned MAC/location for %s failover" % public_name)
        path = nx.shortest_path(self.operational_graph, gateway_dpid, backup_loc[0])
        reverse_path = list(reversed(path))
        if not path:
            raise RuntimeError("empty path for %s failover" % public_name)

        path_dpids = set(path) | set(reverse_path)
        parser_by_dpid = {dpid: self.datapaths.get(dpid) for dpid in path_dpids}
        if any(dp is None for dp in parser_by_dpid.values()):
            raise RuntimeError("disconnected switch on %s failover path" % public_name)

        def install_direction(direction, source_ip, destination_ip,
                              source_mac, destination_mac, path_nodes,
                              final_port, protocol):
            for index, dpid in enumerate(path_nodes):
                datapath = parser_by_dpid.get(dpid) or self.datapaths.get(dpid)
                parser = datapath.ofproto_parser
                if index == len(path_nodes) - 1:
                    out_port = final_port
                else:
                    out_port = self.link_to_port[(dpid, path_nodes[index + 1])][0]
                first_hop = index == 0
                if direction == "reverse" and first_hop:
                    actions = [
                        parser.OFPActionSetField(ipv4_src=source_ip),
                        parser.OFPActionSetField(eth_src=source_mac),
                    ]
                elif direction == "forward" and first_hop:
                    actions = [
                        parser.OFPActionSetField(ipv4_dst=destination_ip),
                        parser.OFPActionSetField(eth_dst=destination_mac),
                    ]
                else:
                    actions = []
                egress = self.vlan_port_map.get((int(dpid), int(out_port)))
                if not egress or not self._port_allows_vlan(dpid, out_port, spec["vlan"]):
                    raise RuntimeError("VLAN path unavailable on s%d:%d" % (dpid, out_port))
                # VLAN is already present on trunk hops. Only a backend access
                # egress needs the normal tag pop; the gateway trunk retains it.
                if egress["kind"] == "access":
                    actions.append(parser.OFPActionPopVlan())
                actions.append(parser.OFPActionOutput(int(out_port)))
                fields = {"eth_type": 0x0800,
                          "vlan_vid": OFPVID_PRESENT | spec["vlan"]}
                if first_hop:
                    fields["ip_proto"] = protocol
                if direction == "reverse" and first_hop:
                    fields["ipv4_src"] = source_ip
                    fields["udp_src" if spec["port"] == 53 else "tcp_src"] = spec["port"]
                elif direction == "forward" and first_hop:
                    fields["ipv4_dst"] = source_ip
                    fields["udp_dst" if spec["port"] == 53 else "tcp_dst"] = spec["port"]
                else:
                    fields["eth_dst" if direction == "forward" else "eth_src"] = destination_mac
                self._install_emergency_flow(
                    datapath, parser.OFPMatch(**fields), actions, public_name)

        for protocol in spec["protocols"]:
            # Request: gateway-facing VIP identity -> backup identity.
            install_direction("forward", spec["frontend_ip"], spec["backup_ip"],
                              frontend_mac, backup_mac, path, backup_loc[1], protocol)
            # Response: backup identity -> restored VIP identity at the gateway.
            install_direction("reverse", spec["backup_ip"], spec["frontend_ip"],
                              backup_mac, frontend_mac, reverse_path, gateway_port, protocol)
        return True

    def _remove_emergency_failover(self, public_name=None):
        removed = 0
        remaining = []
        for datapath, match, flow_service in list(self.emergency_failover_flows):
            if public_name is not None and flow_service != public_name:
                remaining.append((datapath, match, flow_service))
                continue
            parser, ofproto = datapath.ofproto_parser, datapath.ofproto
            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath, command=ofproto.OFPFC_DELETE_STRICT,
                table_id=0, priority=EMERGENCY_FAILOVER_PRIORITY,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                match=match))
            removed += 1
        self.emergency_failover_flows[:] = remaining
        return removed

    def _normalize_lb_service(self, service):
        aliases = {"http_api": "http", "http": "http",
                   "dns": "dns", "https": "https", "ssh": "ssh"}
        public_name = aliases.get(str(service or "").strip().lower())
        spec = self._emergency_service_specs().get(public_name)
        if not public_name or not spec:
            raise ValueError("service is not an exposed Load Balancer frontend: %s" % service)
        return public_name, spec

    def block_load_balancer_service(self, service, ip=None, mac=None,
                                    request_id=None, reason=None):
        """Redirect only one VIP service to its backup; keep other VIP ports intact."""
        public_name, spec = self._normalize_lb_service(service)
        record = {"service": public_name, "ip": str(ip or spec["frontend_ip"]),
                  "mac": self.normalize_device_mac(mac) if mac else self.ip_to_mac.get(spec["frontend_ip"]),
                  "request_id": request_id, "reason": reason,
                  "blocked_at": time.time(), "backup_ip": spec["backup_ip"]}
        self.blocked_lb_services[public_name] = record
        if "load_balancer" in self.blocked_endpoints:
            return {"success": True, "status": "covered_by_global_block",
                    "action": "BLOCK_LOAD_BALANCER_SERVICE", "service": public_name,
                    "backup_ip": spec["backup_ip"], "request_id": request_id}
        self._remove_emergency_failover(public_name)
        try:
            self._install_emergency_service(public_name, spec, frontend_mac=record["mac"])
        except Exception as exc:
            self._remove_emergency_failover(public_name)
            self.blocked_lb_services.pop(public_name, None)
            self.logger.exception("Failed service-scoped LB failover for %s", public_name)
            return {"success": False, "status": "partial_failure",
                    "action": "BLOCK_LOAD_BALANCER_SERVICE", "service": public_name,
                    "backup_ip": spec["backup_ip"], "error": str(exc),
                    "request_id": request_id}
        return {"success": True, "status": "executed",
                "action": "BLOCK_LOAD_BALANCER_SERVICE", "service": public_name,
                "backup_ip": spec["backup_ip"], "request_id": request_id,
                "other_services_unchanged": True}

    def unblock_load_balancer_service(self, service, request_id=None, reason=None):
        """Remove only one service's emergency redirect, preserving other failovers."""
        public_name, spec = self._normalize_lb_service(service)
        if "load_balancer" in self.blocked_endpoints:
            return {"success": False, "status": "global_block_active",
                    "action": "UNBLOCK_LOAD_BALANCER_SERVICE", "service": public_name,
                    "request_id": request_id}
        if public_name not in self.blocked_lb_services:
            return {"success": False, "status": "not_blocked",
                    "action": "UNBLOCK_LOAD_BALANCER_SERVICE", "service": public_name,
                    "request_id": request_id}
        try:
            self._remove_emergency_failover(public_name)
        except Exception as exc:
            return {"success": False, "status": "partial_failure",
                    "action": "UNBLOCK_LOAD_BALANCER_SERVICE", "service": public_name,
                    "error": str(exc), "request_id": request_id}
        self.blocked_lb_services.pop(public_name, None)
        return {"success": True, "status": "executed",
                "action": "UNBLOCK_LOAD_BALANCER_SERVICE", "service": public_name,
                "normal_lb_service_restored": True, "request_id": request_id}

    def block_load_balancer(self, ip=None, mac=None,
                            request_id=None, reason=None):
        """Block h38 by MAC and activate the confirmed VIP takeover."""
        address = str(ip or host_ip(LOAD_BALANCER["host"]))
        ipaddress.ip_address(address)

        if address != "10.10.20.100":
            return {
                "success": False,
                "status": "invalid_load_balancer_address",
                "action": "BLOCK_LOAD_BALANCER",
                "ip": address,
                "request_id": request_id,
            }

        resolved_mac = mac or self.ip_to_mac.get(address)
        if not resolved_mac:
            return {
                "success": False,
                "status": "mac_unavailable",
                "action": "BLOCK_LOAD_BALANCER",
                "ip": address,
                "request_id": request_id,
                "message": "Cannot enforce an h38 block without its learned MAC",
            }

        resolved_mac = self.normalize_device_mac(resolved_mac)

        result = self.block_device(
            mac=resolved_mac,
            ip=address,
            request_id=request_id,
            reason=reason,
        )

        if result.get("status") != "no_switches":
            self.blocked_endpoints["load_balancer"] = {
                "ip": address,
                "mac": resolved_mac,
                "request_id": request_id,
                "reason": reason,
                "blocked_at": time.time(),
                "mac_only": True,
                "emergency_failover": False,
            }

        result["action"] = "BLOCK_LOAD_BALANCER"
        result["ip"] = address
        result["emergency_failover"] = bool(
            (result.get("vip_takeover") or {}).get("success")
        )
        result["failover_services"] = (
            ["http", "https", "ssh", "dns"]
            if result["emergency_failover"] else []
        )
        result["request_id"] = request_id
        return result

    def unblock_load_balancer(self, request_id=None, reason=None):
        """Restore h38 only after VIP dispatch and per-flow rules are removed."""
        record = self.blocked_endpoints.get("load_balancer")

        if record:
            address = str(record.get("ip") or "10.10.20.100")
            mac = record.get("mac")
        else:
            address = "10.10.20.100"
            mac = None

        if not mac:
            for candidate_mac, candidate_record in self.blocked_devices.items():
                if (candidate_record or {}).get("ip") == address:
                    mac = candidate_mac
                    break

        if not mac:
            return {
                "success": False,
                "status": "not_blocked",
                "action": "UNBLOCK_LOAD_BALANCER",
                "request_id": request_id,
            }

        result = self.unblock_device(
            mac=mac,
            ip=address,
            request_id=request_id,
            reason=reason,
        )

        if not result.get("success"):
            result["action"] = "UNBLOCK_LOAD_BALANCER"
            return result

        self.blocked_endpoints.pop("load_balancer", None)

        # A service-specific failover requested during the global block
        # remains active after h38 is restored.
        restored_specific = []
        failed = []

        for public_name, service_record in self.blocked_lb_services.items():
            spec = self._emergency_service_specs().get(public_name)
            if not spec:
                failed.append(public_name)
                continue

            try:
                self._install_emergency_service(
                    public_name,
                    spec,
                    frontend_mac=service_record.get("mac"),
                )
                restored_specific.append(public_name)
            except Exception:
                failed.append(public_name)
                self.logger.exception(
                    "Failed to restore service-scoped failover for %s",
                    public_name,
                )

        if failed:
            return {
                "success": False,
                "status": "partial_failure",
                "action": "UNBLOCK_LOAD_BALANCER",
                "failed_services": failed,
                "service_failovers_retained": restored_specific,
                "request_id": request_id,
            }

        return {
            "success": True,
            "status": "executed",
            "action": "UNBLOCK_LOAD_BALANCER",
            "emergency_failover_removed": True,
            "service_failovers_retained": restored_specific,
            "request_id": request_id,
        }

    def _vip_dispatch_mod(self, datapath, service):
        """Build one controller-dispatch rule for a VIP service."""
        vip_ip, vlan_id, protocol, port = service
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        transport_field = "tcp_dst" if int(protocol) == 6 else "udp_dst"

        match_fields = {
            "eth_type": 0x0800,
            "ipv4_dst": vip_ip,
            "vlan_vid": OFPVID_PRESENT | int(vlan_id),
            "ip_proto": int(protocol),
            transport_field: int(port),
        }

        match = parser.OFPMatch(**match_fields)
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        return parser.OFPFlowMod(
            datapath=datapath,
            table_id=0,
            priority=self.VIP_TAKEOVER_PRIORITY,
            match=match,
            instructions=[
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions
                )
            ],
            idle_timeout=0,
            hard_timeout=0,
        )

    def _vip_direction_flows(
        self, path, in_port, final_port, vlan_id,
        src_mac, dst_mac, output_mac,
        src_ip, dst_ip, ip_dst_rest, protocol,
        src_port, dst_port,
        rewrite_dst=None, rewrite_src=None,
        rewrite_eth_dst=None, ip_src_rest=None, output_vlan=None
    ):
        """Build one direction of a stateful, two-way VIP flow path.

        Returns:
            ([(dpid, FlowMod), ...], first_hop_packetout_actions)
        """
        entries = []
        first_actions = []

        if not path:
            return entries, first_actions

        protocol = int(protocol)
        vlan_id = int(vlan_id)
        transit_vlan = int(
            vlan_id if output_vlan is None else output_vlan
        )
        src_port = int(src_port)
        dst_port = int(dst_port)
        transport = "tcp" if protocol == 6 else "udp"

        for index, switch_id in enumerate(path):
            switch_id = int(switch_id)
            datapath = self.datapaths.get(switch_id)

            if datapath is None:
                return [], []

            if index == 0:
                current_in_port = int(in_port)
            else:
                previous_switch = int(path[index - 1])
                link = self.link_to_port.get((previous_switch, switch_id))
                if not link:
                    return [], []
                current_in_port = int(link[1])

            if index == len(path) - 1:
                out_port = int(final_port)
            else:
                next_switch = int(path[index + 1])
                link = self.link_to_port.get((switch_id, next_switch))
                if not link:
                    return [], []
                out_port = int(link[0])

            current_vlan = (
                vlan_id if index == 0 else transit_vlan
            )

            ingress_entry = self.vlan_port_map.get(
                (switch_id, current_in_port)
            )
            if not isinstance(ingress_entry, dict):
                return [], []

            if not self._port_allows_vlan(
                switch_id, current_in_port, current_vlan
            ):
                return [], []

            ingress_kind = ingress_entry.get("kind")
            if ingress_kind == "access":
                match_vlan = OFPVID_NONE
            elif ingress_kind == "trunk":
                match_vlan = OFPVID_PRESENT | current_vlan
            else:
                return [], []

            output_actions = self._vip_flow_output_actions(
                datapath,
                current_in_port,
                out_port,
                current_vlan,
                transit_vlan,
            )
            if output_actions is None:
                return [], []

            fields = {
                "in_port": current_in_port,
                "eth_src": src_mac,
                "eth_dst": dst_mac if index == 0 else output_mac,
                "eth_type": 0x0800,
                "vlan_vid": match_vlan,
                "ip_proto": protocol,
                "ipv4_src": (
                    src_ip if index == 0 else (ip_src_rest or src_ip)
                ),
                "ipv4_dst": (
                    dst_ip if index == 0 else (ip_dst_rest or dst_ip)
                ),
            }

            fields[transport + "_src"] = src_port
            fields[transport + "_dst"] = dst_port

            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            match = parser.OFPMatch(**fields)

            actions = []

            if index == 0:
                if rewrite_src is not None:
                    actions.append(
                        parser.OFPActionSetField(ipv4_src=rewrite_src)
                    )
                if rewrite_dst is not None:
                    actions.append(
                        parser.OFPActionSetField(ipv4_dst=rewrite_dst)
                    )
                if rewrite_eth_dst is not None:
                    actions.append(
                        parser.OFPActionSetField(eth_dst=rewrite_eth_dst)
                    )

            actions.extend(output_actions)

            flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                table_id=0,
                priority=self.VIP_TAKEOVER_PRIORITY + 1,
                match=match,
                instructions=[
                    parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions
                    )
                ],
                idle_timeout=self.VIP_FLOW_IDLE_TIMEOUT,
                hard_timeout=self.VIP_FLOW_HARD_TIMEOUT,
            )

            entries.append((switch_id, flow_mod))

            if index == 0:
                first_actions = actions

        return entries, first_actions

    def _vip_backend(self, service):
        """Select an eligible backend using its actual backend VLAN."""
        backend_pairs = {
            ("10.10.20.100", 20, 6, 5000):
                ("10.10.20.2", "10.10.20.8"),
            ("10.10.20.100", 20, 6, 443):
                ("10.10.20.3", "10.10.20.19"),
            ("10.10.20.100", 20, 6, 22):
                ("10.10.20.4", "10.10.20.20"),
            ("10.10.20.100", 20, 6, 53):
                ("10.10.30.2", "10.10.30.17"),
            ("10.10.20.100", 20, 17, 53):
                ("10.10.30.2", "10.10.30.17"),
        }

        candidates = backend_pairs.get(tuple(service))
        if not candidates:
            return None

        port = int(service[3])
        backend_vlan = (
            30 if port == 53 and service[0] == "10.10.20.100"
            else int(service[1])
        )

        for backend_ip in candidates:
            backend_mac = self.ip_to_mac.get(backend_ip)
            if not backend_mac:
                continue

            if self.mac_vlan.get(backend_mac) != backend_vlan:
                continue

            if self.host_location.get(backend_mac) is None:
                continue

            if self.is_device_blocked(backend_mac):
                continue

            return backend_ip, backend_mac, port

        return None

    def _handle_vip_packet(self, datapath, msg, pkt, vlan_id, defer=False):
        """Install a bidirectional VIP path and rewrite the first packet."""
        if not self.vip_takeover_active:
            return False

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        if ip_pkt is None or eth_pkt is None:
            return False

        transport_pkt = pkt.get_protocol(tcp.tcp)
        protocol = 6

        if transport_pkt is None:
            transport_pkt = pkt.get_protocol(udp.udp)
            protocol = 17

        if transport_pkt is None:
            return False

        service = (
            str(ip_pkt.dst),
            int(vlan_id),
            protocol,
            int(transport_pkt.dst_port),
        )

        if service not in self.VIP_DISPATCH_SERVICES:
            return False

        # The PacketIn event loop must remain free to process BarrierReply
        # events while the VIP worker waits for OpenFlow confirmation.
        if defer:
            try:
                hub.spawn(
                    self._handle_vip_packet,
                    datapath,
                    msg,
                    pkt,
                    vlan_id,
                )
                self.logger.info(
                    "LB VIP PacketIn deferred to worker: "
                    "service=%s switch=s%d",
                    service,
                    int(datapath.id),
                )
            except Exception:
                self.logger.exception(
                    "Failed to start VIP worker for %s", service
                )
            return True

        self.logger.info(
            "LB VIP PacketIn received: service=%s switch=s%d in_port=%s "
            "src_ip=%s src_mac=%s dst_mac=%s",
            service,
            int(datapath.id),
            msg.match.get("in_port"),
            ip_pkt.src,
            eth_pkt.src,
            eth_pkt.dst,
        )

        selected = self._vip_backend(service)
        if selected is None:
            self.logger.warning(
                "VIP takeover has no eligible backend for %s", service
            )
            return True

        backend_ip, backend_mac, backend_port = selected

        self.logger.info(
            "LB VIP backend selected: service=%s backend=%s mac=%s vlan=%s location=%s",
            service,
            backend_ip,
            backend_mac,
            self.mac_vlan.get(backend_mac),
            self.host_location.get(backend_mac),
        )

        backend_vlan = (
            30 if backend_port == 53 and service[0] == "10.10.20.100"
            else int(service[1])
        )

        try:
            in_port = int(msg.match["in_port"])
            client_mac = str(eth_pkt.src).lower()
            vip_mac = str(eth_pkt.dst).lower()
            client_ip = str(ip_pkt.src)
            client_port = int(transport_pkt.src_port)

            client_location = self.host_location.get(
                client_mac, (int(datapath.id), in_port)
            )
            backend_location = self.host_location.get(backend_mac)

            if backend_location is None:
                self.logger.warning(
                    "VIP backend location is unknown: %s", backend_ip
                )
                return True

            forward_path = self._shortest_path(
                int(datapath.id), int(backend_location[0])
            )
            reverse_path = self._shortest_path(
                int(backend_location[0]), int(client_location[0])
            )

            if not forward_path or not reverse_path:
                self.logger.error(
                    "LB VIP path unavailable: service=%s "
                    "forward_path=%s reverse_path=%s "
                    "client_location=%s backend_location=%s",
                    service,
                    forward_path,
                    reverse_path,
                    client_location,
                    backend_location,
                )
                return True

            self.logger.info(
                "LB VIP paths built: service=%s forward=%s reverse=%s "
                "backend_vlan=%s",
                service,
                forward_path,
                reverse_path,
                backend_vlan,
            )

            forward = self._vip_direction_flows(
                forward_path,
                in_port,
                int(backend_location[1]),
                vlan_id,
                client_mac,
                vip_mac,
                backend_mac,
                client_ip,
                service[0],
                backend_ip,
                protocol,
                client_port,
                backend_port,
                rewrite_dst=backend_ip,
                rewrite_eth_dst=backend_mac,
                output_vlan=backend_vlan,
            )

            reverse_match_dst_mac = client_mac
            reverse_output_mac = client_mac
            reverse_rewrite_eth_dst = None

            # DNS replies arrive from VLAN 30, but must return through
            # the gateway's VLAN 20 interface after VIP translation.
            if int(backend_port) == 53 and int(backend_vlan) == 30:
                gateway_macs = []

                for candidate_mac, candidate_vlan in self.mac_vlan.items():
                    if int(candidate_vlan) != int(backend_vlan):
                        continue

                    candidate_location = self.host_location.get(candidate_mac)
                    if not candidate_location:
                        continue

                    candidate_entry = self.vlan_port_map.get(
                        (
                            int(candidate_location[0]),
                            int(candidate_location[1]),
                        ),
                        {},
                    )

                    if candidate_entry.get("role") == "gateway":
                        gateway_macs.append(candidate_mac)

                gateway_macs = sorted(set(gateway_macs))

                if len(gateway_macs) != 1:
                    self.logger.error(
                        "DNS VIP reverse path cannot resolve VLAN %d "
                        "gateway MAC: candidates=%s",
                        backend_vlan,
                        gateway_macs,
                    )
                    return True

                # Match the actual destination MAC used by h1 on VLAN 30.
                reverse_match_dst_mac = gateway_macs[0]

                # Translate Ethernet destination to the VLAN 20 gateway MAC
                # before forwarding the response toward s3.
                reverse_rewrite_eth_dst = client_mac

            reverse = self._vip_direction_flows(
                reverse_path,
                int(backend_location[1]),
                int(client_location[1]),
                backend_vlan,
                backend_mac,
                reverse_match_dst_mac,
                reverse_output_mac,
                backend_ip,
                client_ip,
                client_ip,
                protocol,
                backend_port,
                client_port,
                rewrite_src=service[0],
                ip_src_rest=service[0],
                rewrite_eth_dst=reverse_rewrite_eth_dst,
                output_vlan=int(service[1]),
            )

            # Keep both directions together so partial installation can
            # be rolled back before the first packet is released.
            flow_entries = forward[0] + reverse[0]

            if not forward[0] or not reverse[0]:
                self.logger.error(
                    "LB VIP flow construction failed: service=%s "
                    "forward_entries=%d reverse_entries=%d",
                    service,
                    len(forward[0]),
                    len(reverse[0]),
                )
                return True

            self.logger.info(
                "LB VIP flow construction complete: service=%s "
                "forward_entries=%d reverse_entries=%d",
                service,
                len(forward[0]),
                len(reverse[0]),
            )

            messages_by_switch = {}
            for switch_id, flow_mod in flow_entries:
                messages_by_switch.setdefault(switch_id, []).append(flow_mod)

            install_ok = True
            install_results = []

            for switch_id in sorted(messages_by_switch):
                switch = self.datapaths.get(switch_id)
                if switch is None:
                    install_ok = False
                    break

                result = self._send_security_flow_batch(
                    switch, messages_by_switch[switch_id]
                )
                install_results.append((switch_id, result))

                if not result.get("success"):
                    install_ok = False
                    break

            if not install_ok:
                self.logger.error(
                    "LB VIP OpenFlow installation failed: service=%s "
                    "results=%s",
                    service,
                    install_results,
                )
                # Delete every generated tuple, including entries on the
                # switch whose batch failed after partially sending.
                rollback_by_switch = {}
                for switch_id, flow_mod in flow_entries:
                    switch = self.datapaths.get(switch_id)
                    if switch is None:
                        continue
                    parser = switch.ofproto_parser
                    ofproto = switch.ofproto
                    delete_mod = parser.OFPFlowMod(
                        datapath=switch,
                        command=ofproto.OFPFC_DELETE_STRICT,
                        table_id=0,
                        priority=flow_mod.priority,
                        out_port=ofproto.OFPP_ANY,
                        out_group=ofproto.OFPG_ANY,
                        match=flow_mod.match,
                    )
                    rollback_by_switch.setdefault(
                        switch_id, []
                    ).append(delete_mod)

                for switch_id, delete_messages in rollback_by_switch.items():
                    switch = self.datapaths.get(switch_id)
                    if switch is not None:
                        self._send_security_flow_batch(
                            switch, delete_messages
                        )
                return True

            for switch_id, flow_mod in flow_entries:
                flow_key = (
                    switch_id,
                    flow_mod.priority,
                    repr(flow_mod.match),
                )
                self.vip_takeover_flows[flow_key] = (
                    switch_id, flow_mod.match
                )

            self.logger.info(
                "LB VIP OpenFlow installation confirmed: service=%s "
                "switches=%s flow_entries=%d",
                service,
                sorted(messages_by_switch),
                len(flow_entries),
            )

            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            packet_out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=forward[1],
                data=msg.data,
            )
            datapath.send_msg(packet_out)

            self.logger.info(
                "LB VIP first packet forwarded by Ryu: service=%s switch=s%d",
                service,
                int(datapath.id),
            )
            return True

        except Exception:
            self.logger.exception(
                "VIP packet handling failed for %s", service
            )
            return True

    def _install_vip_dispatch_on_switch(self, datapath):
        """Restore VIP dispatch rules on one reconnected switch."""
        services = sorted(self.VIP_DISPATCH_SERVICES)
        messages = []
        records = []

        for service in services:
            flow_mod = self._vip_dispatch_mod(datapath, service)
            messages.append(flow_mod)
            records.append((service, flow_mod.match))

        result = self._send_security_flow_batch(datapath, messages)

        if not result.get("success"):
            self.logger.error(
                "VIP dispatch restore failed on s%d: %s",
                datapath.id, result
            )
            return result

        self.vip_takeover_dispatch[int(datapath.id)] = records
        return {"success": True, "status": "confirmed"}

    def _restore_h38_vip_on_switch(self, datapath):
        """Confirm the h38 MAC drop, then restore dispatch on reconnect."""
        dpid = int(datapath.id)
        expected = set(range(1, EXPECTED_SWITCHES + 1))

        matching = [
            (mac, record)
            for mac, record in self.blocked_devices.items()
            if (record or {}).get("ip") == "10.10.20.100"
        ]

        if not matching:
            return

        mac, record = matching[0]
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        block_mod = parser.OFPFlowMod(
            datapath=datapath,
            table_id=0,
            priority=DEVICE_BLOCK_PRIORITY,
            match=parser.OFPMatch(eth_src=mac),
            instructions=[
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, []
                )
            ],
        )

        result = self._send_security_flow_batch(datapath, [block_mod])

        if not result.get("success"):
            self.logger.error(
                "h38 MAC block was not confirmed after s%d reconnect: %s",
                dpid, result
            )
            return

        confirmed = set(
            int(value) for value in record.get("confirmed_switches", [])
        )
        confirmed.add(dpid)

        record["confirmed_switches"] = sorted(confirmed)

        if confirmed == expected:
            record["enforcement_status"] = "executed"
        else:
            record["enforcement_status"] = "partial_failure"
            return

        if not all(switch_id in self.datapaths for switch_id in expected):
            return

        if self.vip_takeover_active:
            for candidate in sorted(
                self.datapaths.values(), key=lambda item: int(item.id)
            ):
                candidate_id = int(candidate.id)
                if candidate_id in self.vip_takeover_dispatch:
                    continue

                restored = self._install_vip_dispatch_on_switch(candidate)
                if not restored.get("success"):
                    self.logger.error(
                        "VIP dispatch restore failed on s%d: %s",
                        candidate_id, restored
                    )
        else:
            result = self.activate_vip_takeover()
            if not result.get("success"):
                self.logger.error(
                    "VIP takeover activation after reconnect failed: %s",
                    result
                )

    def activate_vip_takeover(self, reason="security"):
        """Activate VIP dispatch for a confirmed Security block or LB failure."""
        if reason not in ("security", "lb_health"):
            return {
                "success": False,
                "status": "invalid_takeover_reason",
                "reason": reason,
            }

        reasons = set(getattr(self, "vip_takeover_reasons", set()))

        # Security takeover still requires a fully confirmed h38 MAC block.
        # A Load Balancer process failure does not create or imply a device block.
        if reason == "security":
            expected_switches = set(
                range(1, int(EXPECTED_SWITCHES) + 1)
            )
            h38_block_confirmed = False

            for owner_mac, record in self.blocked_devices.items():
                record = record or {}
                confirmed = set(
                    int(value)
                    for value in record.get("confirmed_switches", [])
                )
                record_macs = record.get("macs", [owner_mac])

                if (
                    record.get("ip") == "10.10.20.100"
                    and record.get("enforcement_status")
                    in ("executed", "confirmed")
                    and confirmed == expected_switches
                    and record_macs
                ):
                    h38_block_confirmed = True
                    break

            if not h38_block_confirmed:
                return {
                    "success": False,
                    "status": "h38_block_not_fully_confirmed",
                }

        if reason in reasons:
            return {
                "success": True,
                "status": "already_active",
                "reason": reason,
            }

        # If another independent reason already installed the rules, retain
        # them and record this reason rather than reinstalling duplicate flows.
        if self.vip_takeover_active:
            reasons.add(reason)
            self.vip_takeover_reasons = reasons
            return {
                "success": True,
                "status": "already_active",
                "reason": reason,
                "active_reasons": sorted(reasons),
            }

        if not self.vlan_map_ready or not self.full_topology_discovered:
            return {
                "success": False,
                "status": "topology_not_ready",
            }

        expected_switches = set(
            range(1, int(EXPECTED_SWITCHES) + 1)
        )

        services = sorted(self.VIP_DISPATCH_SERVICES)
        failed_switches = []
        installed = {}

        for switch_id in sorted(expected_switches):
            switch = self.datapaths.get(switch_id)

            if switch is None:
                failed_switches.append(switch_id)
                continue

            messages = []
            records = []

            for service in services:
                flow_mod = self._vip_dispatch_mod(switch, service)
                messages.append(flow_mod)
                records.append((service, flow_mod.match))

            result = self._send_security_flow_batch(switch, messages)

            if result.get("success"):
                installed[switch_id] = records
            else:
                failed_switches.append(switch_id)

        if failed_switches:
            cleanup_failed_switches = []
            remaining_dispatch = {}

            # Roll back on every connected switch. This also covers a
            # switch whose batch failed after some FlowMods were sent.
            for switch_id in sorted(expected_switches):
                switch = self.datapaths.get(switch_id)

                if switch is None:
                    continue

                parser = switch.ofproto_parser
                ofproto = switch.ofproto
                delete_messages = []
                records = []

                for service in services:
                    add_mod = self._vip_dispatch_mod(switch, service)
                    delete_messages.append(parser.OFPFlowMod(
                        datapath=switch,
                        command=ofproto.OFPFC_DELETE_STRICT,
                        table_id=0,
                        priority=self.VIP_TAKEOVER_PRIORITY,
                        out_port=ofproto.OFPP_ANY,
                        out_group=ofproto.OFPG_ANY,
                        match=add_mod.match,
                    ))
                    records.append((service, add_mod.match))

                cleanup = self._send_security_flow_batch(
                    switch, delete_messages
                )

                if not cleanup.get("success"):
                    cleanup_failed_switches.append(switch_id)
                    remaining_dispatch[switch_id] = records

            self.vip_takeover_dispatch = remaining_dispatch
            self.vip_takeover_active = False

            if cleanup_failed_switches:
                return {
                    "success": False,
                    "status": "dispatch_rollback_failed",
                    "failed_switches": sorted(set(failed_switches)),
                    "cleanup_failed_switches": sorted(
                        set(cleanup_failed_switches)
                    ),
                }

            return {
                "success": False,
                "status": "dispatch_install_failed",
                "failed_switches": sorted(set(failed_switches)),
            }

        self.vip_takeover_dispatch = installed
        self.vip_takeover_reasons = set(
            getattr(self, "vip_takeover_reasons", set())
        ) | {reason}
        self.vip_takeover_active = True

        return {
            "success": True,
            "status": "active",
            "reason": reason,
            "active_reasons": sorted(self.vip_takeover_reasons),
            "switches": sorted(installed),
            "services": len(services),
        }

    def deactivate_vip_takeover(self, reason="security"):
        """Remove VIP steering only when no independent takeover reason remains."""
        if reason not in ("security", "lb_health"):
            return {
                "success": False,
                "status": "invalid_takeover_reason",
                "reason": reason,
            }

        reasons = set(getattr(self, "vip_takeover_reasons", set()))
        other_reasons = reasons - {reason}

        if other_reasons:
            reasons.discard(reason)
            self.vip_takeover_reasons = reasons
            self.vip_takeover_active = True
            return {
                "success": True,
                "status": "takeover_still_required",
                "active_reasons": sorted(reasons),
            }

        dispatch = self.vip_takeover_dispatch or {}
        flow_records = self.vip_takeover_flows or {}

        if (
            not dispatch
            and not flow_records
            and not self.vip_takeover_active
        ):
            reasons.discard(reason)
            self.vip_takeover_reasons = reasons
            return {
                "success": True,
                "status": "not_active",
            }

        messages_by_switch = {}
        dispatch_by_switch = {}
        flow_keys_by_switch = {}

        for switch_id, records in dispatch.items():
            switch_id = int(switch_id)
            switch = self.datapaths.get(switch_id)

            if switch is None:
                dispatch_by_switch[switch_id] = records
                continue

            parser = switch.ofproto_parser
            ofproto = switch.ofproto

            for service, match in records:
                delete_mod = parser.OFPFlowMod(
                    datapath=switch,
                    command=ofproto.OFPFC_DELETE_STRICT,
                    table_id=0,
                    priority=self.VIP_TAKEOVER_PRIORITY,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=match,
                )
                messages_by_switch.setdefault(
                    switch_id, []
                ).append(delete_mod)

        for flow_key, flow_record in flow_records.items():
            switch_id, match = flow_record
            switch_id = int(switch_id)
            switch = self.datapaths.get(switch_id)

            if switch is None:
                flow_keys_by_switch.setdefault(
                    switch_id, {}
                )[flow_key] = flow_record
                continue

            parser = switch.ofproto_parser
            ofproto = switch.ofproto
            delete_mod = parser.OFPFlowMod(
                datapath=switch,
                command=ofproto.OFPFC_DELETE_STRICT,
                table_id=0,
                priority=self.VIP_TAKEOVER_PRIORITY + 1,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match,
            )
            messages_by_switch.setdefault(
                switch_id, []
            ).append(delete_mod)
            flow_keys_by_switch.setdefault(
                switch_id, {}
            )[flow_key] = flow_record

        failed_switches = []
        remaining_dispatch = dict(dispatch_by_switch)
        remaining_flows = {}

        for switch_id in sorted(messages_by_switch):
            switch = self.datapaths.get(switch_id)
            if switch is None:
                failed_switches.append(switch_id)
                if switch_id in dispatch:
                    remaining_dispatch[switch_id] = dispatch[switch_id]
                remaining_flows.update(
                    flow_keys_by_switch.get(switch_id, {})
                )
                continue

            result = self._send_security_flow_batch(
                switch, messages_by_switch[switch_id]
            )

            if not result.get("success"):
                failed_switches.append(switch_id)

                if switch_id in dispatch:
                    remaining_dispatch[switch_id] = dispatch[switch_id]

                remaining_flows.update(
                    flow_keys_by_switch.get(switch_id, {})
                )

        self.vip_takeover_dispatch = remaining_dispatch
        self.vip_takeover_flows = remaining_flows

        if failed_switches:
            # Keep the reason and takeover active so cleanup can be retried.
            self.vip_takeover_reasons = reasons
            self.vip_takeover_active = True
            return {
                "success": False,
                "status": "dispatch_cleanup_failed",
                "failed_switches": sorted(set(failed_switches)),
            }

        reasons.discard(reason)
        self.vip_takeover_reasons = reasons
        self.vip_takeover_active = bool(reasons)

        return {
            "success": True,
            "status": "deactivated" if not reasons else "takeover_still_required",
            "active_reasons": sorted(reasons),
        }

    def block_device(self, mac, ip=None, request_id=None, reason=None):
        """Block a MAC and activate VIP takeover only after h38 is confirmed."""
        mac = self.normalize_device_mac(mac)

        location = self.host_location.get(mac)
        if location is not None:
            port_entry = self.vlan_port_map.get(
                (int(location[0]), int(location[1])), {}
            )
            if port_entry.get("role") == "gateway":
                return {
                    "success": False,
                    "status": "gateway-owned",
                    "action": "BLOCK_DEVICE",
                    "mac": mac,
                    "ip": ip,
                    "request_id": request_id,
                    "message": "A gateway-owned MAC is not a host endpoint",
                }

        block_macs = [mac]
        target_ip = str(ip).strip() if ip is not None else ""

        record = {
            "mac": mac,
            "macs": list(block_macs),
            "ip": ip,
            "request_id": request_id,
            "reason": reason,
            "blocked_at": time.time(),
            "enforcement_status": "pending",
            "confirmed_switches": [],
        }
        self.blocked_devices[mac] = record

        datapaths = sorted(
            self.datapaths.values(), key=lambda item: int(item.id)
        )

        if not datapaths:
            record["enforcement_status"] = "no_switches"
            return {
                "success": False,
                "status": "no_switches",
                "mac": mac,
                "ip": ip,
                "message": "Block is recorded; no switch is connected",
            }

        failed = []
        confirmed = []

        for datapath in datapaths:
            try:
                for block_mac in block_macs:
                    if target_ip == "10.10.20.100":
                        parser = datapath.ofproto_parser
                        ofproto = datapath.ofproto
                        flow_mod = parser.OFPFlowMod(
                            datapath=datapath,
                            table_id=0,
                            priority=DEVICE_BLOCK_PRIORITY,
                            match=parser.OFPMatch(eth_src=block_mac),
                            instructions=[
                                parser.OFPInstructionActions(
                                    ofproto.OFPIT_APPLY_ACTIONS, []
                                )
                            ],
                        )
                        result = self._send_security_flow_batch(
                            datapath, [flow_mod]
                        )
                        if not result.get("success"):
                            raise RuntimeError(
                                "MAC block not confirmed: %s" %
                                result.get("status")
                            )
                    else:
                        self._install_device_block_rule(
                            datapath, block_mac
                        )

                confirmed.append(int(datapath.id))

            except Exception:
                failed.append(int(datapath.id))
                self.logger.exception(
                    "Failed to install device block on s%d for %s",
                    datapath.id, mac
                )

        if target_ip == "10.10.20.100":
            expected = set(range(1, EXPECTED_SWITCHES + 1))
            missing = expected - set(confirmed)
            failed.extend(missing)

        failed = sorted(set(failed))
        confirmed = sorted(set(confirmed))

        record["confirmed_switches"] = confirmed
        record["enforcement_status"] = (
            "executed" if not failed else "partial_failure"
        )

        vip_result = None
        if target_ip == "10.10.20.100" and not failed:
            vip_result = self.activate_vip_takeover()
            record["vip_takeover_status"] = vip_result.get("status")

            if not vip_result.get("success"):
                self.logger.error(
                    "h38 is blocked but VIP takeover did not activate: %s",
                    vip_result
                )
                return {
                    "success": False,
                    "status": "partial_failure",
                    "action": "BLOCK_DEVICE",
                    "mac": mac,
                    "ip": ip,
                    "switches": confirmed,
                    "failed_switches": [],
                    "vip_takeover": vip_result,
                    "request_id": request_id,
                }

        success = not failed

        self.logger.warning(
            "BLOCK_DEVICE %s ip=%s switches=%s failed=%s request_id=%s reason=%s",
            mac, ip, confirmed, failed, request_id, reason
        )

        return {
            "success": success,
            "status": "executed" if success else "partial_failure",
            "action": "BLOCK_DEVICE",
            "mac": mac,
            "ip": ip,
            "switches": confirmed,
            "failed_switches": failed,
            "vip_takeover": vip_result,
            "request_id": request_id,
        }

    def unblock_device(self, mac, ip=None, request_id=None, reason=None):
        """Remove Security MAC rules and restore the normal h38 frontend."""
        mac = self.normalize_device_mac(mac)
        record = self.blocked_devices.get(mac)

        if mac not in self.blocked_devices:
            return {
                "success": False,
                "status": "not_blocked",
                "action": "UNBLOCK_DEVICE",
                "mac": mac,
                "ip": ip,
                "request_id": request_id,
            }

        target_ip = str(ip or (record or {}).get("ip") or "")
        block_macs = (record or {}).get("macs", [mac])

        if not isinstance(block_macs, (list, tuple, set)):
            block_macs = [mac]

        block_macs = [
            self.normalize_device_mac(value) for value in block_macs
        ]

        # h38 requires confirmed removal on every expected switch.
        # Ordinary endpoint unblock behavior remains unchanged.
        if target_ip == "10.10.20.100":
            if not block_macs:
                block_macs = [mac]

            expected_switches = set(
                range(1, int(EXPECTED_SWITCHES) + 1)
            )

            connected = {
                int(datapath.id): datapath
                for datapath in self.datapaths.values()
                if int(datapath.id) in expected_switches
            }

            missing_switches = sorted(
                expected_switches - set(connected)
            )

            if missing_switches:
                return {
                    "success": False,
                    "status": "switches_unavailable",
                    "action": "UNBLOCK_DEVICE",
                    "mac": mac,
                    "ip": target_ip,
                    "required_switches": sorted(expected_switches),
                    "connected_switches": sorted(connected),
                    "failed_switches": missing_switches,
                    "request_id": request_id,
                }

            # Remove VIP steering while h38 remains MAC-blocked.
            vip_result = self.deactivate_vip_takeover()

            if not vip_result.get("success"):
                return {
                    "success": False,
                    "status": "partial_failure",
                    "action": "UNBLOCK_DEVICE",
                    "mac": mac,
                    "ip": target_ip,
                    "vip_takeover": vip_result,
                    "request_id": request_id,
                }

            # Delete the h38 MAC drop and wait for a BarrierReply
            # from every expected switch.
            delete_failed = []

            for switch_id in sorted(expected_switches):
                datapath = connected[switch_id]
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto

                messages = [
                    parser.OFPFlowMod(
                        datapath=datapath,
                        command=ofproto.OFPFC_DELETE_STRICT,
                        table_id=0,
                        priority=DEVICE_BLOCK_PRIORITY,
                        out_port=ofproto.OFPP_ANY,
                        out_group=ofproto.OFPG_ANY,
                        match=parser.OFPMatch(eth_src=block_mac),
                    )
                    for block_mac in block_macs
                ]

                result = self._send_security_flow_batch(
                    datapath, messages
                )

                if not result.get("success"):
                    delete_failed.append(switch_id)
                    self.logger.error(
                        "h38 MAC unblock not confirmed on s%d: %s",
                        switch_id,
                        result,
                    )

            if delete_failed:
                # A delete may have succeeded on some switches.
                # Reinstall the MAC drop everywhere and confirm it.
                restored_switches = []
                restore_failed = []

                for switch_id in sorted(expected_switches):
                    datapath = connected[switch_id]
                    parser = datapath.ofproto_parser
                    ofproto = datapath.ofproto

                    restore_messages = [
                        parser.OFPFlowMod(
                            datapath=datapath,
                            command=ofproto.OFPFC_ADD,
                            table_id=0,
                            priority=DEVICE_BLOCK_PRIORITY,
                            match=parser.OFPMatch(eth_src=block_mac),
                            instructions=[
                                parser.OFPInstructionActions(
                                    ofproto.OFPIT_APPLY_ACTIONS, []
                                )
                            ],
                        )
                        for block_mac in block_macs
                    ]

                    result = self._send_security_flow_batch(
                        datapath, restore_messages
                    )

                    if result.get("success"):
                        restored_switches.append(switch_id)
                    else:
                        restore_failed.append(switch_id)
                        self.logger.error(
                            "h38 MAC block restoration not confirmed "
                            "on s%d: %s",
                            switch_id,
                            result,
                        )

                block_record = self.blocked_devices.get(mac)

                if isinstance(block_record, dict):
                    block_record["confirmed_switches"] = sorted(
                        restored_switches
                    )
                    block_record["enforcement_status"] = (
                        "executed"
                        if not restore_failed
                        else "partial_failure"
                    )

                vip_restore = None

                # Restore VIP dispatch only after all six MAC drops
                # have been confirmed again.
                if not restore_failed:
                    vip_restore = self.activate_vip_takeover()

                if restore_failed:
                    status = "unblock_failed_rollback_incomplete"
                elif vip_restore and vip_restore.get("success"):
                    status = "unblock_failed_block_restored"
                else:
                    status = "unblock_failed_vip_restore_failed"

                return {
                    "success": False,
                    "status": status,
                    "action": "UNBLOCK_DEVICE",
                    "mac": mac,
                    "ip": target_ip,
                    "delete_failed_switches": sorted(delete_failed),
                    "restored_switches": sorted(restored_switches),
                    "restore_failed_switches": sorted(restore_failed),
                    "vip_takeover": vip_restore,
                    "request_id": request_id,
                }

            # All six switches confirmed removal.
            self.blocked_devices.pop(mac, None)

            self.logger.info(
                "UNBLOCK_DEVICE h38 %s ip=%s confirmed_switches=%s "
                "request_id=%s reason=%s",
                mac,
                target_ip,
                sorted(expected_switches),
                request_id,
                reason,
            )

            return {
                "success": True,
                "status": "executed",
                "action": "UNBLOCK_DEVICE",
                "mac": mac,
                "ip": target_ip,
                "switches": sorted(expected_switches),
                "request_id": request_id,
            }

        # Existing ordinary-device behavior: intentionally unchanged.
        datapaths = list(self.datapaths.values())

        try:
            for datapath in datapaths:
                for block_mac in block_macs:
                    self._delete_device_block_rule(
                        datapath, block_mac
                    )

        except Exception:
            self.logger.exception(
                "Failed to remove device block for %s; restoring block rules",
                mac
            )

            for datapath in datapaths:
                for block_mac in block_macs:
                    try:
                        self._install_device_block_rule(
                            datapath, block_mac
                        )
                    except Exception:
                        self.logger.exception(
                            "Failed to restore device block on s%d for %s",
                            datapath.id, block_mac
                        )

            return {
                "success": False,
                "status": "partial_failure",
                "action": "UNBLOCK_DEVICE",
                "mac": mac,
                "ip": ip,
                "request_id": request_id,
            }

        self.blocked_devices.pop(mac, None)

        self.logger.info(
            "UNBLOCK_DEVICE %s ip=%s request_id=%s reason=%s",
            mac, ip, request_id, reason
        )

        return {
            "success": True,
            "status": "executed",
            "action": "UNBLOCK_DEVICE",
            "mac": mac,
            "ip": ip,
            "switches": [dp.id for dp in datapaths],
            "request_id": request_id,
        }



    # ============================================================

    def _rebuild_operational_graph(self):

        self.operational_graph = self.graph.copy()

        for edge in self.isolated_links:
            if self.operational_graph.has_edge(*edge):
                self.operational_graph.remove_edge(*edge)

        self.path_engine.set_graph(self.operational_graph)

    def update_link_metric(
        self,
        src_dpid,
        dst_dpid,
        utilization=None,
        rate_bps=None,
        capacity_bps=None
    ):
        """Update traffic cost for a currently operational link."""
        self.path_engine.update_link_metric(
            src_dpid,
            dst_dpid,
            utilization=utilization,
            rate_bps=rate_bps,
            capacity_bps=capacity_bps
        )
        self.operational_graph = self.path_engine.graph.copy()

    def get_path_engine_status(self):
        return self.path_engine.status()

    def _set_port_admin_down(self, dpid, port_no, down):
        """Set/clear OpenFlow's administrative PORT_DOWN bit."""
        datapath = self.datapaths.get(int(dpid))
        key = (int(dpid), int(port_no))
        hw_addr = self.port_hw_addr.get(key)

        if datapath is None:
            self.logger.warning(
                "Cannot change port state: switch s%d is disconnected", dpid)
            return False

        if not hw_addr:
            self.logger.warning(
                "Cannot change port state: missing hardware address for s%d:%d",
                dpid, port_no)
            return False

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        port_down = ofproto.OFPPC_PORT_DOWN
        config = port_down if down else 0

        try:
            datapath.send_msg(parser.OFPPortMod(
                datapath,
                int(port_no),
                hw_addr,
                config,
                port_down,
                0
            ))
            return True
        except Exception:
            self.logger.exception(
                "OFPPortMod failed for s%d:%d (down=%s)",
                dpid, port_no, down)
            return False

    def isolate_link(self, dpid_a, dpid_b):
        """Physically disable both switch ports of an inter-switch link."""
        edge = tuple(sorted((int(dpid_a), int(dpid_b))))

        if edge not in self.edges:
            self.logger.warning("Cannot isolate unknown link %s", edge)
            return False

        if edge in self.isolated_links:
            return True

        dpid_a, dpid_b = edge
        ports = self.link_to_port.get((dpid_a, dpid_b))
        if ports is None:
            self.logger.warning(
                "Cannot physically isolate %s: LLDP port mapping unavailable",
                edge)
            return False

        endpoints = (
            (dpid_a, int(ports[0])),
            (dpid_b, int(ports[1])),
        )
        for dpid, port_no in endpoints:
            if dpid not in self.datapaths or not self.port_hw_addr.get(
                    (dpid, port_no)):
                self.logger.warning(
                    "Cannot physically isolate %s: missing switch/port data "
                    "for s%d:%d", edge, dpid, port_no)
                return False

        self.isolated_link_ports[edge] = endpoints
        changed = []
        for dpid, port_no in endpoints:
            if not self._set_port_admin_down(dpid, port_no, down=True):
                for old_dpid, old_port in reversed(changed):
                    self._set_port_admin_down(
                        old_dpid, old_port, down=False)
                self.isolated_link_ports.pop(edge, None)
                return False
            changed.append((dpid, port_no))

        self.isolated_links.add(edge)
        self._rebuild_operational_graph()
        self._flush_forwarding_flows()
        self._refresh_clff()
        # Reinstall only affected normal flows on the operational backup path.
        self.reroute_active_flows(failed_links={edge})

        self.logger.warning(
            "Link PHYSICALLY ISOLATED: %s ports=%s", edge, endpoints)
        return True

    def restore_link(self, dpid_a, dpid_b):
        """Re-enable both link ports without changing Zero-Trust state.

        Existing flows are not moved back automatically, avoiding route
        flapping. LLDP will rediscover the physical link after ports return.
        """
        edge = tuple(sorted((int(dpid_a), int(dpid_b))))

        if edge not in self.isolated_links:
            return False

        endpoints = self.isolated_link_ports.get(edge)
        if not endpoints:
            self.logger.warning(
                "Cannot restore %s: saved endpoint port mapping is missing",
                edge)
            return False

        for dpid, port_no in endpoints:
            if dpid not in self.datapaths or not self.port_hw_addr.get(
                    (dpid, port_no)):
                self.logger.warning(
                    "Cannot restore %s: missing switch/port data for s%d:%d",
                    edge, dpid, port_no)
                return False

        restored = []
        for dpid, port_no in endpoints:
            if not self._set_port_admin_down(dpid, port_no, down=False):
                for old_dpid, old_port in reversed(restored):
                    self._set_port_admin_down(
                        old_dpid, old_port, down=True)
                return False
            restored.append((dpid, port_no))

        self.isolated_links.discard(edge)
        self.isolated_link_ports.pop(edge, None)
        self._rebuild_operational_graph()
        self._refresh_clff()

        self.logger.info(
            "Link physically restored: %s ports=%s; LLDP will rediscover it",
            edge, endpoints)
        return True

    # ============================================================
    # CLFF management
    # ============================================================

    def _refresh_clff(self):
        """Drop old packet state, then rebuild or invalidate CLFF."""

        self.clff_packet_state.clear()

        usable = (
            self.topology_ready
            and self.operational_graph.number_of_nodes() > 0
            and nx.is_connected(self.operational_graph)
        )

        if usable:
            self._rebuild_clff()
        else:
            self._invalidate_clff()

    def _rebuild_clff(self):

        if self.clff is None:
            return False

        try:
            success = self.clff.build_trees(
                self.operational_graph.copy(),
                dict(self.link_to_port))

            self._clff_valid = bool(success)

            if success:
                self.logger.info("CLFF rebuilt: %s", self.clff.summary())
            else:
                self.logger.warning("CLFF rebuild failed")

            return bool(success)

        except Exception as exc:
            self._clff_valid = False
            self.logger.exception("CLFF rebuild error: %s", exc)
            return False

    def _invalidate_clff(self):

        self._clff_valid = False

        if self.clff is None:
            return

        for name in ("invalidate", "clear", "reset"):
            fn = getattr(self.clff, name, None)

            if callable(fn):
                try:
                    fn()
                except Exception as exc:
                    self.logger.exception("CLFF %s() failed: %s", name, exc)
                break

        self.logger.warning("CLFF invalidated")

    def _clff_usable(self):
        return (
            self.clff is not None
            and self._clff_valid
            and self.clff.is_ready()
        )

    def _flush_forwarding_flows(self):
        """Strict-delete only the rules this app installed."""

        count = 0

        for (dpid, priority, _key), match in list(
                self.installed_flows.items()):

            datapath = self.datapaths.get(dpid)

            if datapath is None:
                continue

            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE_STRICT,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=priority,
                match=match))

            count += 1

        self.installed_flows.clear()

        self.logger.info("Flushed %d forwarding rule(s)", count)

    # ============================================================
    # Host learning / ARP
    # ============================================================

    def _learn_ip(self, ip, mac, vlan_id):

        if not ip or ip == "0.0.0.0" or not mac:
            return

        if ip in self.ip_vlan and (
            self.ip_vlan[ip] != vlan_id or self.ip_to_mac.get(ip) != mac
        ):
            self.logger.warning("Ignoring conflicting IP learning for %s", ip)
            return

        self.ip_to_mac[ip] = mac
        self.mac_to_ip[mac] = ip
        self.ip_vlan[ip] = vlan_id

    def _learn_host(self, dpid, in_port, src_mac, pkt=None, vlan_id=None):
        try:
            dpid = int(dpid)
            in_port = int(in_port)
        except (TypeError, ValueError):
            return False

        if vlan_id not in ALLOWED_VLANS:
            return False
        if self._is_security_mirror_port(dpid, in_port):
            return False
        if self.is_inter_switch_port(dpid, in_port):
            return False

        entry = self.vlan_port_map.get((dpid, in_port))
        if not isinstance(entry, dict):
            return False

        kind = entry.get("kind")
        role = entry.get("role")
        is_gateway_trunk = kind == "trunk" and role == "gateway"
        is_forwarding_access = (
            kind == "access" and role in ("endpoint", "infrastructure")
        )
        if not (is_gateway_trunk or is_forwarding_access):
            return False
        if not self._port_allows_vlan(dpid, in_port, vlan_id):
            return False

        known_vlan = self.mac_vlan.get(src_mac)
        if known_vlan is not None and known_vlan != vlan_id:
            self.logger.warning(
                "Ignoring MAC %s seen in VLAN %d; already learned in VLAN %d",
                src_mac, vlan_id, known_vlan)
            return False

        if src_mac and src_mac.startswith("02:00:00:00:00:"):
            return False

        if self._is_broadcast_or_multicast(src_mac):
            return False

        new_location = (dpid, in_port)
        old_location = self.host_location.get(src_mac)

        if old_location is not None and old_location != new_location:

            if old_location[0] != dpid:
                self.logger.debug(
                    "Ignoring MAC flap: %s s%d:%d -> s%d:%d",
                    src_mac, old_location[0], old_location[1],
                    dpid, in_port)
                return False

            self.logger.warning(
                "Host MAC moved: %s s%d:%d -> s%d:%d",
                src_mac, old_location[0], old_location[1], dpid, in_port)

        if old_location != new_location:
            self.host_location[src_mac] = new_location
            self.logger.info(
                "Host learned: %s VLAN %d -> s%d:%d", src_mac, vlan_id, dpid, in_port)
        self.mac_vlan[src_mac] = vlan_id

        # Learn the gateway MAC/location for forwarding, but do not register
        # the gateway's IP as an endpoint identity.
        if not is_gateway_trunk and pkt is not None:
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            if ipv4_pkt is not None:
                self._learn_ip(ipv4_pkt.src, src_mac, vlan_id)
        return True

    def _learn_from_arp(self, dpid, in_port, arp_pkt, vlan_id):
        learned = self._learn_host(
            dpid, in_port, arp_pkt.src_mac, vlan_id=vlan_id
        )
        if not learned:
            return False

        entry = self.vlan_port_map.get((int(dpid), int(in_port)), {})
        if entry.get("role") != "gateway":
            self._learn_ip(arp_pkt.src_ip, arp_pkt.src_mac, vlan_id)
        return True

    def _try_proxy_arp(self, datapath, in_port, arp_pkt, vlan_id):
        """Answer an ARP request from the controller. True if answered."""

        if arp_pkt.dst_ip == arp_pkt.src_ip:
            return False

        target_mac = self.ip_to_mac.get(arp_pkt.dst_ip)

        if (target_mac is None or target_mac not in self.host_location
                or self.ip_vlan.get(arp_pkt.dst_ip) != vlan_id
                or self.mac_vlan.get(target_mac) != vlan_id):
            return False

        self._send_arp_reply(
            datapath, in_port,
            arp_pkt.src_mac, arp_pkt.src_ip,
            target_mac, arp_pkt.dst_ip, vlan_id)

        return True

    def _send_arp_reply(self, datapath, out_port,
                        requester_mac, requester_ip,
                        target_mac, target_ip, vlan_id):

        pkt = packet.Packet()

        pkt.add_protocol(ethernet.ethernet(
            dst=requester_mac, src=target_mac, ethertype=ETH_TYPE_ARP))

        pkt.add_protocol(arp.arp(
            hwtype=1, proto=0x0800, hlen=6, plen=4,
            opcode=arp.ARP_REPLY,
            src_mac=target_mac, src_ip=target_ip,
            dst_mac=requester_mac, dst_ip=requester_ip))

        pkt.serialize()

        self._send_packet_out_bytes(
            datapath, datapath.ofproto.OFPP_CONTROLLER, out_port,
            pkt.data, vlan_id, data_has_vlan=False)

    # ============================================================
    # Broadcast / unknown unicast  (CLFF)
    # ============================================================

    def _port_allows_vlan(self, dpid, port_no, vlan_id):
        try:
            dpid = int(dpid)
            port_no = int(port_no)
        except (TypeError, ValueError):
            return False

        if self._is_security_mirror_port(dpid, port_no):
            return False

        entry = self.vlan_port_map.get((dpid, port_no))
        if not isinstance(entry, dict):
            return False

        kind = entry.get("kind")
        if kind == "trunk":
            return vlan_id in entry.get("allowed_vlans", ())
        if kind == "access":
            return entry.get("vlan_id") == vlan_id
        return False

    def _vip_flow_output_actions(
        self, datapath, in_port, out_port,
        ingress_vlan, egress_vlan=None
    ):
        """Build VLAN-aware output actions, including VLAN translation."""
        dpid = int(datapath.id)
        in_port = int(in_port)
        out_port = int(out_port)
        ingress_vlan = int(ingress_vlan)
        egress_vlan = int(
            ingress_vlan if egress_vlan is None else egress_vlan
        )

        ingress = self.vlan_port_map.get((dpid, in_port))
        egress = self.vlan_port_map.get((dpid, out_port))

        if not ingress or not egress:
            return None

        if not self._port_allows_vlan(dpid, in_port, ingress_vlan):
            return None

        if not self._port_allows_vlan(dpid, out_port, egress_vlan):
            return None

        parser = datapath.ofproto_parser
        actions = []

        if egress.get("kind") == "trunk":
            if ingress.get("kind") == "access":
                actions.extend([
                    parser.OFPActionPushVlan(0x8100),
                    parser.OFPActionSetField(
                        vlan_vid=OFPVID_PRESENT | egress_vlan
                    ),
                ])
            elif ingress.get("kind") == "trunk":
                if ingress_vlan != egress_vlan:
                    actions.append(
                        parser.OFPActionSetField(
                            vlan_vid=OFPVID_PRESENT | egress_vlan
                        )
                    )
            else:
                return None

        elif egress.get("kind") == "access":
            if ingress.get("kind") == "trunk":
                actions.append(parser.OFPActionPopVlan())
            elif ingress.get("kind") == "access":
                if ingress_vlan != egress_vlan:
                    return None
            else:
                return None
        else:
            return None

        actions.append(parser.OFPActionOutput(out_port))
        return actions


    def _flow_output_actions(self, datapath, in_port, out_port, vlan_id):
        """Build fail-closed VLAN-aware actions for one installed flow hop."""
        dpid = int(datapath.id)
        ingress = self.vlan_port_map.get((dpid, int(in_port)))
        egress = self.vlan_port_map.get((dpid, int(out_port)))
        if (ingress is None or egress is None
                or not self._port_allows_vlan(dpid, in_port, vlan_id)
                or not self._port_allows_vlan(dpid, out_port, vlan_id)):
            return None

        parser = datapath.ofproto_parser
        data_has_vlan = ingress["kind"] == "trunk"
        actions = []
        if egress["kind"] == "trunk" and not data_has_vlan:
            actions.extend((
                parser.OFPActionPushVlan(0x8100),
                parser.OFPActionSetField(vlan_vid=OFPVID_PRESENT | vlan_id),
            ))
        elif egress["kind"] == "access" and data_has_vlan:
            actions.append(parser.OFPActionPopVlan())
        actions.append(parser.OFPActionOutput(int(out_port)))
        return actions

    def _get_gateway_trunk_ports(self, dpid, in_port, vlan_id):
        """Return this switch's eligible gateway trunk, if one exists."""
        try:
            dpid = int(dpid)
            in_port = int(in_port)
        except (TypeError, ValueError):
            return set()

        if not getattr(self, "vlan_map_ready", False):
            return set()
        if vlan_id not in ALLOWED_VLANS:
            return set()

        result = set()
        for (port_dpid, port_no), entry in self.vlan_port_map.items():
            if int(port_dpid) != dpid or int(port_no) == in_port:
                continue
            if not isinstance(entry, dict):
                continue
            if entry.get("role") != "gateway" or entry.get("kind") != "trunk":
                continue
            if self._is_special_port(port_no):
                continue
            if self._is_security_mirror_port(dpid, port_no):
                continue
            if self._port_allows_vlan(dpid, port_no, vlan_id):
                result.add(int(port_no))
        return result

    def _flood_ethernet(self, datapath, msg, in_port, vlan_id):

        dpid = datapath.id

        self._cleanup_clff_packet_state()

        key = (vlan_id, self._get_clff_packet_key(msg))
        state = self.clff_packet_state.get(key)

        if state is None:
            state = {
                "root": self._get_clff_root(dpid, msg),
                "created": time.time(),
            }
            self.clff_packet_state[key] = state

        processed_switches = state.setdefault(
            "processed_switches",
            set()
        )

        if dpid in processed_switches:
            self.logger.debug(
                "CLFF duplicate suppressed: packet=%s switch=s%d",
                key,
                dpid
            )
            return

        processed_switches.add(dpid)

        root = state["root"]

        ports = set(self._collect_host_ports(dpid, in_port))

        # The gateway trunk participates in broadcast/multicast only.
        # Unknown unicast must never be flooded toward the gateway.
        try:
            eth_pkt = packet.Packet(msg.data).get_protocol(ethernet.ethernet)
        except Exception:
            eth_pkt = None
        if eth_pkt is not None and self._is_broadcast_or_multicast(eth_pkt.dst):
            ports.update(
                self._get_gateway_trunk_ports(dpid, in_port, vlan_id)
            )

        if self._clff_usable() and self.clff.get_tree(root) is not None:

            for port_no in self.clff.get_forward_ports(root, dpid):

                try:
                    port_no = int(port_no)
                except (TypeError, ValueError):
                    continue

                if port_no == in_port or port_no <= 0:
                    continue

                if self._is_special_port(port_no):
                    continue

                # Only LIVE inter-switch ports.
                if (dpid, port_no) not in self.port_to_link:
                    continue

                ports.add(port_no)

        else:
            self.logger.debug(
                "CLFF unusable on s%d (root=s%d): host ports only",
                dpid, root)

        ports = {
            port_no for port_no in ports
            if self._port_allows_vlan(dpid, port_no, vlan_id)
        }
        if not ports:
            return

        self._packet_out(datapath, msg, sorted(ports), vlan_id)

    def _collect_host_ports(self, dpid, in_port):

        ports = set(self._get_host_ports_from_desc(dpid))

        for _mac, (host_dpid, host_port) in list(
                self.host_location.items()):

            if (host_dpid == dpid
                    and self._is_forwarding_access_port(dpid, host_port)):
                ports.add(host_port)

        ports.discard(in_port)

        return ports

    def _get_host_ports_from_desc(self, dpid):

        ports = set()

        for (port_dpid, port_no) in list(self.port_desc.keys()):

            if port_dpid != dpid:
                continue

            if self._is_forwarding_access_port(dpid, port_no):
                ports.add(port_no)

        return ports

    def _get_clff_packet_key(self, msg):
        """Same packet -> same key on every switch."""

        try:
            data = bytes(msg.data)
        except Exception:
            data = str(msg.data).encode("utf-8", errors="ignore")

        src = dst = ethertype = None

        try:
            eth = packet.Packet(data).get_protocol(ethernet.ethernet)
            if eth is not None:
                src, dst, ethertype = eth.src, eth.dst, eth.ethertype
        except Exception:
            pass

        return (src, dst, ethertype, hash(data))

    def _get_clff_root(self, ingress_dpid, msg):
        """Root = switch where the source host is attached."""

        try:
            eth = packet.Packet(msg.data).get_protocol(ethernet.ethernet)
        except Exception:
            return ingress_dpid

        if eth is not None:
            location = self.host_location.get(eth.src)

            if location is not None and location[0] in self.graph:
                return location[0]

        return ingress_dpid

    def _cleanup_clff_packet_state(self):

        now = time.time()

        for key in [k for k, s in self.clff_packet_state.items()
                    if now - s.get("created", now)
                    > CLFF_PACKET_STATE_TIMEOUT]:
            self.clff_packet_state.pop(key, None)

    # ============================================================
    # Port classification
    # ============================================================

    def is_inter_switch_port(self, dpid, port_no):

        try:
            port_no = int(port_no)
        except (TypeError, ValueError):
            return False

        return (
            (dpid, port_no) in self.port_to_link
            or (dpid, port_no) in self.known_switch_ports
        )

    def _is_security_mirror_port(self, dpid, port_no):
        """Security mirror ports carry copies only; never treat them as hosts."""
        try:
            key = (int(dpid), int(port_no))
        except (TypeError, ValueError):
            return False
        name = getattr(self, "port_desc", {}).get(key, "")
        return str(name).startswith("sec-mir-")

    def _is_forwarding_access_port(self, dpid, port_no):
        """Return whether a configured access port may carry host forwarding."""
        try:
            dpid = int(dpid)
            port_no = int(port_no)
        except (TypeError, ValueError):
            return False

        if port_no <= 0 or self._is_special_port(port_no):
            return False
        if self._is_security_mirror_port(dpid, port_no):
            return False
        if self.is_inter_switch_port(dpid, port_no):
            return False

        entry = self.vlan_port_map.get((dpid, port_no))
        if not isinstance(entry, dict):
            return False

        return (
            entry.get("kind") == "access"
            and entry.get("role") in ("endpoint", "infrastructure")
        )

    def is_host_port(self, dpid, port_no):
        try:
            dpid = int(dpid)
            port_no = int(port_no)
        except (TypeError, ValueError):
            return False

        if port_no <= 0 or self._is_special_port(port_no):
            return False
        if self._is_security_mirror_port(dpid, port_no):
            return False
        if self.is_inter_switch_port(dpid, port_no):
            return False

        entry = self.vlan_port_map.get((dpid, port_no))
        if not isinstance(entry, dict):
            return False

        # A host-facing access port must be explicitly present in the
        # controller's VLAN inventory. Trunks are never host ports.
        return (
            entry.get("kind") == "access"
            and entry.get("role") == "endpoint"
        )

    def _is_special_port(self, port_no):

        try:
            port_no = int(port_no)
        except Exception:
            return False

        return (
            port_no >= ofproto_v1_3.OFPP_MAX
            or port_no == ofproto_v1_3.OFPP_LOCAL
        )

    def _is_broadcast_or_multicast(self, mac):

        mac = str(mac).lower()

        if mac == "ff:ff:ff:ff:ff:ff":
            return True

        try:
            return bool(int(mac.split(":")[0], 16) & 1)
        except Exception:
            return False

    # ============================================================
    # Shortest path (operational graph)
    # ============================================================

    def _shortest_path(self, src_dpid, dst_dpid):
        """Return the best operational path, including live utilization."""
        try:
            result = self.path_engine.get_best_path(
                src=src_dpid,
                dst=dst_dpid,
                graph=self.operational_graph,
                network_state=self.path_engine.network_state,
            )
            if result.get("success") and result.get("path"):
                self.logger.info(
                    "VIP PATH ENGINE OK: src=%s dst=%s path=%s "
                    "operational_nodes=%s operational_edges=%s "
                    "engine_nodes=%s engine_edges=%s",
                    src_dpid, dst_dpid, result.get("path"),
                    list(self.operational_graph.nodes()),
                    list(self.operational_graph.edges()),
                    list(self.path_engine.graph.nodes()),
                    list(self.path_engine.graph.edges()),
                )
                return result["path"]

            self.logger.error(
                "VIP PATH ENGINE NO ROUTE: src=%s dst=%s result=%s "
                "operational_nodes=%s operational_edges=%s "
                "engine_nodes=%s engine_edges=%s",
                src_dpid, dst_dpid, result,
                list(self.operational_graph.nodes()),
                list(self.operational_graph.edges()),
                list(self.path_engine.graph.nodes()),
                list(self.path_engine.graph.edges()),
            )
            return None

        except Exception:
            self.logger.exception(
                "VIP PATH ENGINE EXCEPTION: src=%s dst=%s",
                src_dpid, dst_dpid,
            )
            return None

    def get_forwarding_port(self, src_dpid, dst_dpid):

        if src_dpid == dst_dpid:
            return None

        path = self._shortest_path(src_dpid, dst_dpid)

        if not path or len(path) < 2:
            return None

        link = self.link_to_port.get((src_dpid, path[1]))

        return link[0] if link else None

    def _next_port_on_path(self, path, dpid, dst_port):
        """Output port on `dpid` for a path that contains it."""

        if dpid not in path:
            return None

        index = path.index(dpid)

        if index == len(path) - 1:
            return dst_port

        link = self.link_to_port.get((dpid, path[index + 1]))

        return link[0] if link else None

    # ============================================================
    # Flow installation
    # ============================================================

    def _install_path(self, path, src_mac, dst_mac, vlan_id=None, flow_match_fields=None):
        """
        Install priority-100 rules along `path`, INCLUDING the last hop
        to the destination host port. The reverse direction is installed
        only when the path starts on the source host's switch.
        """

        if vlan_id is None:
            vlan_id = self.mac_vlan.get(src_mac)
        if vlan_id not in ALLOWED_VLANS:
            return False

        dst_loc = self.host_location.get(dst_mac)
        src_loc = self.host_location.get(src_mac)

        if not path or dst_loc is None:
            return False

        dst_dpid, dst_port = dst_loc

        if path[-1] != dst_dpid:
            return False

        self._install_direction(
            path, src_mac, dst_mac, dst_port, vlan_id,
            flow_match_fields=flow_match_fields,
        )

        if src_loc is not None and src_loc[0] == path[0]:
            reverse_fields = self._reverse_flow_stats_fields(flow_match_fields)
            self._install_direction(
                list(reversed(path)), dst_mac, src_mac, src_loc[1], vlan_id,
                flow_match_fields=reverse_fields,
            )

        return True

    def _install_direction(self, path, eth_src, eth_dst, final_port, vlan_id, flow_match_fields=None):

        hops = []
        src_loc = self.host_location.get(eth_src)
        if src_loc is None:
            return False

        for i in range(len(path) - 1):
            link = self.link_to_port.get((path[i], path[i + 1]))

            if link is None:
                self.logger.warning(
                    "Missing port mapping s%d->s%d", path[i], path[i + 1])
                return False

            ingress_port = src_loc[1] if i == 0 else self.link_to_port[(path[i - 1], path[i])][1]
            hops.append((path[i], ingress_port, link[0]))

        last_ingress = src_loc[1] if len(path) == 1 else self.link_to_port[(path[-2], path[-1])][1]
        hops.append((path[-1], last_ingress, final_port))

        flow_rules = []
        for dpid, in_port, out_port in hops:
            datapath = self.datapaths.get(dpid)
            if datapath is None:
                self.logger.warning("Cannot install path: s%d is disconnected", dpid)
                return False

            parser = datapath.ofproto_parser
            actions = self._flow_output_actions(
                datapath, in_port, out_port, vlan_id)
            if actions is None:
                self.logger.warning(
                    "Cannot install VLAN %d path on s%d:%d -> %d",
                    vlan_id, dpid, in_port, out_port)
                return False
            match_fields = {
                "in_port": in_port,
                "eth_src": eth_src,
                "eth_dst": eth_dst,
                "vlan_vid": OFPVID_PRESENT | vlan_id,
            }
            if flow_match_fields:
                match_fields.update(flow_match_fields)
            match = parser.OFPMatch(**match_fields)
            priority = (REROUTE_PRIORITY + 1) if flow_match_fields else REROUTE_PRIORITY
            track_key = ("path", vlan_id, eth_src, eth_dst)
            if flow_match_fields:
                track_key += ("ip_flow", tuple(sorted(flow_match_fields.items())))
            flow_rules.append((datapath, match, actions, priority, track_key))

        for datapath, match, actions, priority, track_key in flow_rules:
            self._add_flow(
                datapath, priority, match, actions,
                idle_timeout=HOST_FLOW_IDLE_TIMEOUT,
                hard_timeout=HOST_FLOW_HARD_TIMEOUT,
                track_key=track_key)

        return True

    def _install_output_flow(self, datapath, in_port, dst_mac, out_port, vlan_id, flow_match_fields=None):

        parser = datapath.ofproto_parser

        src_mac = None
        for mac, location in self.host_location.items():
            if location == (datapath.id, in_port):
                src_mac = mac
                break
        if src_mac is None:
            return
        match_fields = {
            "in_port": in_port,
            "eth_src": src_mac,
            "eth_dst": dst_mac,
            "vlan_vid": OFPVID_PRESENT | vlan_id,
        }
        if flow_match_fields:
            match_fields.update(flow_match_fields)
        match = parser.OFPMatch(**match_fields)

        actions = self._flow_output_actions(
            datapath, in_port, out_port, vlan_id)
        if actions is None:
            self.logger.warning(
                "Cannot install VLAN %d output flow on s%d:%d -> %d",
                vlan_id, datapath.id, in_port, out_port)
            return

        priority = (REROUTE_PRIORITY + 1) if flow_match_fields else NORMAL_PRIORITY
        track_key = ("out", vlan_id, in_port, src_mac, dst_mac)
        if flow_match_fields:
            track_key += ("ip_flow", tuple(sorted(flow_match_fields.items())))
        self._add_flow(
            datapath, priority, match, actions,
            idle_timeout=HOST_FLOW_IDLE_TIMEOUT,
            hard_timeout=HOST_FLOW_HARD_TIMEOUT,
            track_key=track_key)

    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0, track_key=None):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=[parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)],
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout))

        if track_key is not None:
            self.installed_flows[
                (datapath.id, priority, track_key)] = match

    def _packet_out(self, datapath, msg, out_port, vlan_id):
        in_port = int(msg.match["in_port"])
        ingress = self.vlan_port_map.get((int(datapath.id), in_port), {})
        data_has_vlan = ingress.get("kind") == "trunk"
        ports = out_port if isinstance(out_port, (list, tuple, set)) else [out_port]
        self._send_packet_out_bytes(
            datapath, in_port, ports, msg.data, vlan_id,
            data_has_vlan=data_has_vlan)

    def _send_packet_out_bytes(self, datapath, in_port, out_ports,
                               data, vlan_id, data_has_vlan):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        if not isinstance(out_ports, (list, tuple, set)):
            out_ports = [out_ports]
        for port_no in out_ports:
            if not self._port_allows_vlan(datapath.id, port_no, vlan_id):
                continue
            entry = self.vlan_port_map[(int(datapath.id), int(port_no))]
            actions = []
            if entry["kind"] == "trunk" and not data_has_vlan:
                actions.extend((
                    parser.OFPActionPushVlan(0x8100),
                    parser.OFPActionSetField(vlan_vid=OFPVID_PRESENT | vlan_id),
                ))
            elif entry["kind"] == "access" and data_has_vlan:
                actions.append(parser.OFPActionPopVlan())
            actions.append(parser.OFPActionOutput(int(port_no)))
            datapath.send_msg(parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=data))

    # ============================================================
    # PortStats sampler
    # ============================================================

    def _port_stats_loop(self):
        while True:
            try:
                for datapath in list(self.datapaths.values()):
                    parser = datapath.ofproto_parser
                    ofproto = datapath.ofproto
                    datapath.send_msg(
                        parser.OFPPortStatsRequest(
                            datapath,
                            0,
                            ofproto.OFPP_ANY
                        )
                    )
            except Exception as exc:
                self.logger.debug("PortStats loop error: %s", exc)

            hub.sleep(PORT_STATS_INTERVAL)

    def _congestion_reoptimization_loop(self):
        """Re-evaluate active paths using the latest link utilization.

        This is deliberately a network decision only: security components may
        request isolation/rerouting, but this worker never classifies traffic
        or changes trust/security state.  Physical failure recovery remains
        handled by the topology-change/resilience workflow.
        """
        while True:
            try:
                if self.topology_ready and self.active_flows:
                    self._reroute_congested_flows()
            except Exception:
                self.logger.exception(
                    "Congestion reoptimization loop error"
                )

            hub.sleep(CONGESTION_REEVAL_INTERVAL)

    def _reroute_congested_flows(self):
        """Move active flows only when the new path materially improves cost."""
        rerouted = 0

        for flow_id, flow in list(self.active_flows.items()):
            if not isinstance(flow, dict):
                continue

            last_reroute = self.congestion_last_reroute.get(flow_id)
            if (
                last_reroute is not None
                and time.time() - last_reroute
                < CONGESTION_REROUTE_COOLDOWN
            ):
                continue

            src_mac = flow.get("src_mac")
            dst_mac = flow.get("dst_mac")
            src_location = self.host_location.get(src_mac)
            dst_location = self.host_location.get(dst_mac)
            current_path = flow.get("path") or []

            if (
                not src_location
                or not dst_location
                or not current_path
            ):
                continue

            proposed_path = self._shortest_path(
                src_location[0], dst_location[0]
            )

            if not proposed_path or not self.path_engine.should_reroute(
                current_path,
                proposed_path,
                network_state=self.path_engine.network_state,
                graph=self.operational_graph,
            ):
                continue

            current_eval = self.path_engine.evaluate_path(
                current_path,
                network_state=self.path_engine.network_state,
            )
            proposed_eval = self.path_engine.evaluate_path(
                proposed_path,
                network_state=self.path_engine.network_state,
            )

            # Hysteresis gate: do not migrate a flow merely because another
            # path is marginally cheaper.  A congestion migration starts only
            # when the currently used path is actually above the configured
            # congestion threshold.  This prevents oscillation such as
            # direct-path -> alternate-path -> direct-path at 40-50% load.
            if (
                current_eval.max_utilization
                < self.path_engine.congestion_threshold
            ):
                continue

            # Do not move congestion from one saturated path to another.
            # If every available alternative is also above the threshold,
            # keep the current route and wait for the next telemetry sample.
            if (
                proposed_eval.max_utilization
                >= self.path_engine.congestion_threshold
            ):
                self.logger.debug(
                    "CONGESTION REROUTE skipped flow=%s: "
                    "current=%.1f%% proposed=%.1f%%",
                    flow_id,
                    current_eval.max_utilization * 100.0,
                    proposed_eval.max_utilization * 100.0,
                )
                continue

            if not self._install_path(proposed_path, src_mac, dst_mac):
                self.logger.warning(
                    "CONGESTION REROUTE failed flow=%s proposed=%s",
                    flow_id,
                    proposed_path,
                )
                continue

            flow["path"] = list(proposed_path)
            self.congestion_last_reroute[flow_id] = time.time()
            rerouted += 1
            self.logger.warning(
                "CONGESTION REROUTE flow=%s old_path=%s new_path=%s "
                "old_cost=%.3f new_cost=%.3f old_max_util=%.1f%% "
                "new_max_util=%.1f%%",
                flow_id,
                current_path,
                proposed_path,
                current_eval.cost,
                proposed_eval.cost,
                current_eval.max_utilization * 100.0,
                proposed_eval.max_utilization * 100.0,
            )

        if rerouted:
            self.logger.info(
                "CONGESTION REOPTIMIZATION completed rerouted=%d",
                rerouted,
            )

    # ============================================================
    # LLDP sender
    # ============================================================

    def _lldp_loop(self):

        while True:

            try:
                self._send_lldp_once()

                # Also prune stale links even if no LLDP arrives.
                self._update_topology_from_lldp()

            except Exception as exc:
                self.logger.exception("LLDP loop error: %s", exc)

            hub.sleep(LLDP_INTERVAL)

    def _send_lldp_once(self):

        if lldp is None or not self.vlan_map_ready:
            return

        for dpid, datapath in list(self.datapaths.items()):

            for port_no in self._get_valid_physical_ports(dpid):
                entry = self.vlan_port_map.get((int(dpid), int(port_no)))
                if entry is None or entry["kind"] != "trunk":
                    continue

                try:
                    self._send_lldp(datapath, port_no)
                except Exception as exc:
                    self.logger.debug(
                        "LLDP send failed s%d:%d: %s", dpid, port_no, exc)

    def _get_valid_physical_ports(self, dpid):

        return {
            port_no
            for (port_dpid, port_no) in list(self.port_desc.keys())
            if port_dpid == dpid
            and port_no > 0
            and not self._is_special_port(port_no)
        }
    def _send_lldp(self, datapath, port_no):

        if lldp is None or not self.vlan_map_ready:
            return
        entry = self.vlan_port_map.get((int(datapath.id), int(port_no)))
        if entry is None or entry["kind"] != "trunk":
            return

        dpid = datapath.id

        lldp_pkt = lldp.lldp(tlvs=[
            lldp.ChassisID(
                subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
                chassis_id=str(dpid).encode()),
            lldp.PortID(
                subtype=lldp.PortID.SUB_PORT_COMPONENT,
                port_id=str(port_no).encode()),
            lldp.TTL(ttl=LLDP_INTERVAL * 2),
            lldp.End(),
        ])

        pkt = packet.Packet()

        pkt.add_protocol(ethernet.ethernet(
            dst=LLDP_MAC,
            src=self._get_switch_mac(dpid),
            ethertype=ETH_TYPE_LLDP))

        pkt.add_protocol(lldp_pkt)
        pkt.serialize()

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(port_no)],
            data=pkt.data))

    @staticmethod
    def _get_switch_mac(dpid):

        return "02:%02x:%02x:%02x:%02x:%02x" % (
            (dpid >> 32) & 0xff,
            (dpid >> 24) & 0xff,
            (dpid >> 16) & 0xff,
            (dpid >> 8) & 0xff,
            dpid & 0xff)

    # ============================================================
    # Reroute host event
    # ============================================================

    @set_ev_cls(EventRerouteHost)
    def handle_reroute_host(self, ev):

        host_ip = ev.host_ip
        request_id = ev.request_id

        mac = self.ip_to_mac.get(host_ip)

        if mac is None or mac not in self.host_location:
            self.logger.warning(
                "Reroute: unknown host %s (request_id=%s)",
                host_ip, request_id)
            return

        self.logger.info(
            "Reroute requested for %s (request_id=%s)", host_ip, request_id)

        rerouted = 0

        for _fid, flow in list(self.active_flows.items()):

            if not isinstance(flow, dict):
                continue

            if host_ip not in (flow.get("src_ip"), flow.get("dst_ip")):
                continue

            src_mac = flow.get("src_mac")
            dst_mac = flow.get("dst_mac")

            src_loc = self.host_location.get(src_mac)
            dst_loc = self.host_location.get(dst_mac)

            if src_loc is None or dst_loc is None:
                continue

            current_path = None
            for flow in self.active_flows.values():
                if isinstance(flow, dict) and flow.get("src_mac") == src_mac and flow.get("dst_mac") == dst_mac:
                    current_path = flow.get("path") or []
                    break
            if not current_path:
                current_path = [src_loc[0], dst_loc[0]]

            decision = self.path_engine.get_backup_path(
                current_path=current_path,
                src=src_loc[0],
                dst=dst_loc[0],
                graph=self.operational_graph,
                network_state=self.path_engine.network_state,
            )
            path = decision.get("path") if decision.get("success") else None

            if path and self._install_path(
                    path, src_mac, dst_mac, flow.get("vlan_id"),
                    flow_match_fields=flow.get("flow_match_fields")):
                rerouted += 1

        self.logger.info(
            "Reroute done for %s: %d flow(s) (request_id=%s)",
            host_ip, rerouted, request_id)

    @staticmethod
    def _path_uses_failed_link(path, failed_links):
        """Return True when a flow path traverses one of the failed edges."""
        if not path or not failed_links:
            return False

        failed = {
            tuple(sorted((int(src), int(dst))))
            for src, dst in failed_links
        }
        path_edges = {
            tuple(sorted((int(path[index]), int(path[index + 1]))))
            for index in range(len(path) - 1)
        }
        return bool(path_edges & failed)

    def reroute_active_flows(self, failed_links=None):
        """Reroute active flows after a physical topology failure.

        ResilienceEngine orchestrates the recovery request. PathEngine
        selects an operational path, while TopologyMonitor installs the
        resulting OpenFlow rules. When failed_links is supplied, only flows
        whose current path traverses a failed edge are rerouted.
        """
        if not self.active_flows:
            self.logger.info(
                "SELF-HEALING: No active flows to reroute"
            )
            return {
                "success": True,
                "rerouted": 0,
                "failed": 0
            }

        rerouted = 0
        failed = 0

        self.logger.warning(
            "SELF-HEALING: Starting recovery for %d active flow(s) "
            "failed_links=%s",
            len(self.active_flows),
            sorted(failed_links or ()),
        )

        for flow_id, flow in list(self.active_flows.items()):
            if not isinstance(flow, dict):
                self.logger.warning(
                    "SELF-HEALING: Invalid flow record flow=%s",
                    flow_id
                )
                failed += 1
                continue

            src_mac = flow.get("src_mac")
            dst_mac = flow.get("dst_mac")
            src_ip = flow.get("src_ip")
            dst_ip = flow.get("dst_ip")
            old_path = flow.get("path") or []

            if (
                failed_links is not None
                and not self._path_uses_failed_link(old_path, failed_links)
            ):
                self.logger.info(
                    "SELF-HEALING: keeping unaffected flow=%s path=%s",
                    flow_id,
                    old_path,
                )
                continue

            if not src_mac or not dst_mac:
                self.logger.warning(
                    "SELF-HEALING: Missing MAC information for flow=%s",
                    flow_id
                )
                failed += 1
                continue

            src_location = self.host_location.get(src_mac)
            dst_location = self.host_location.get(dst_mac)

            if not src_location or not dst_location:
                self.logger.warning(
                    "SELF-HEALING: Cannot locate flow=%s src=%s dst=%s",
                    flow_id,
                    src_ip or src_mac,
                    dst_ip or dst_mac
                )
                failed += 1
                continue

            src_dpid = src_location[0]
            dst_dpid = dst_location[0]

            backup_result = self.path_engine.get_backup_path(
                current_path=old_path,
                src=src_dpid,
                dst=dst_dpid,
                graph=self.operational_graph,
                network_state=self.path_engine.network_state,
            )
            new_path = backup_result.get("path")

            if not new_path:
                self.logger.warning(
                    "SELF-HEALING: No operational path for flow=%s",
                    flow_id
                )
                failed += 1
                continue

            try:
                installed = self._install_path(
                    new_path,
                    src_mac,
                    dst_mac,
                    flow.get("vlan_id"),
                    flow_match_fields=flow.get("flow_match_fields"),
                )
            except Exception:
                self.logger.exception(
                    "SELF-HEALING: Failed to install flow=%s",
                    flow_id
                )
                installed = False

            if installed:
                old_path = flow.get("path")
                flow["path"] = list(new_path)
                rerouted += 1
                self.logger.info(
                    "SELF-HEALING: flow=%s old_path=%s new_path=%s",
                    flow_id,
                    old_path,
                    new_path
                )
            else:
                failed += 1

        success = failed == 0

        self.logger.warning(
            "SELF-HEALING: completed rerouted=%d failed=%d",
            rerouted,
            failed
        )

        return {
            "success": success,
            "rerouted": rerouted,
            "failed": failed
        }

    def register_active_flow(self, flow_id, flow_data):
        self.active_flows[flow_id] = flow_data

    def remove_active_flow(self, flow_id):
        self.active_flows.pop(flow_id, None)
        self.congestion_last_reroute.pop(flow_id, None)

    def clear_all_flows(self):
        """Delete every forwarding rule this app installed."""
        self._flush_forwarding_flows()
        self.congestion_last_reroute.clear()

    # ============================================================
    # Status / queries
    # ============================================================

    def get_topology_status(self):

        return {
            "topology_ready": self.topology_ready,
            "full_topology_discovered": self.full_topology_discovered,
            "switch_count": self.graph.number_of_nodes(),
            "link_count": self.graph.number_of_edges(),
            "host_count": len(self.host_location),
            "blocked_device_count": len(self.blocked_devices),
            "blocked_macs": sorted(self.blocked_devices),
            "blocked_services": sorted(self.blocked_services),
            "blocked_endpoints": {
                name: dict(record) for name, record in self.blocked_endpoints.items()
            },
            "switches": sorted(self.graph.nodes()),
            "links": [list(e) for e in sorted(self.edges)],
            "isolated_links": [list(e) for e in sorted(self.isolated_links)],
            "operational_links": [
                list(e) for e in sorted(self.operational_graph.edges())],
            "path_engine": self.get_path_engine_status(),
            "topology_signature": self.topology_signature,
            "topology_change_count": self.topology_change_count,
            "clff_ready": self._clff_usable(),
            "clff_trees": (
                len(self.clff.trees)
                if self.clff is not None and hasattr(self.clff, "trees")
                else 0),
        }

    def get_host_status(self):

        return {
            mac: {
"ip": self.mac_to_ip.get(mac),
                "dpid": loc[0],
                "port": loc[1],
            }
            for mac, loc in list(self.host_location.items())
        }

    def get_graph(self):
        return self.graph.copy()

    def get_operational_graph(self):
        return self.operational_graph.copy()

    def get_links(self):

        result = []

        for a, b in self.graph.edges():
            ports = self.link_to_port.get((a, b))

            result.append({
                "src_dpid": a,
                "dst_dpid": b,
                "src_port": ports[0] if ports else None,
                "dst_port": ports[1] if ports else None,
                "isolated": tuple(sorted((a, b))) in self.isolated_links,
            })

        return result

    def print_topology_summary(self):

        self.logger.info("========== TOPOLOGY SUMMARY ==========")
        self.logger.info("Switches: %s", sorted(self.graph.nodes()))
        self.logger.info("Physical links: %s", sorted(self.edges))
        self.logger.info("Isolated links: %s", sorted(self.isolated_links))
        self.logger.info("Hosts: %s", self.host_location)
        self.logger.info("Ready: %s", self.topology_ready)
        self.logger.info("Signature: %s", self.topology_signature)
        self.logger.info("Changes: %d", self.topology_change_count)
        self.logger.info("CLFF usable: %s", self._clff_usable())
        self.logger.info("=======================================")
