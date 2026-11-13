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
from ryu.lib.packet import (
    packet,
    ethernet,
    arp,
    ipv4,
    ipv6,
    vlan,
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
VLAN_PORT_MAP_POLL_INTERVAL = 1

NORMAL_PRIORITY = 10
REROUTE_PRIORITY = 100
DEVICE_BLOCK_PRIORITY = 50000

HOST_FLOW_IDLE_TIMEOUT = 30
HOST_FLOW_HARD_TIMEOUT = 0

ETH_TYPE_LLDP = 0x88CC
ETH_TYPE_ARP = 0x0806

CLFF_PACKET_STATE_TIMEOUT = 5
PORT_STATS_INTERVAL = 5
HOST_TRAFFIC_ACTIVE_WINDOW = 15
LINK_CAPACITY_BPS = 10_000_000
CONGESTION_REEVAL_INTERVAL = 5
CONGESTION_REROUTE_COOLDOWN = 15


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
        # Recent endpoint traffic, separate from inter-switch utilization.
        # Host activity is keyed by (dpid, access_port); switch activity is
        # aggregated separately for the switch-level API.
        self.host_traffic_last_seen = {}
        self.switch_traffic_last_seen = {}

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
        # Dashboard-facing firewall history.  Keep this separate from Ryu's
        # internal event queue and from forwarding-flow bookkeeping.
        self.firewall_events = []

        # Active host-to-host flows (for rerouting).
        self.active_flows = {}
        self.topology_events = []
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
        self._clff_last_rebuild_at = None
        self._clff_last_rebuild_reason = None
        self._clff_last_error = None

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

        self.logger.info("TopologyMonitor initialized")
        self.logger.info("Forwarding owner: TopologyMonitor")
        self.logger.info("CLFF: %s",
                         "available" if self.clff else "NOT available")

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
                            if role not in ("endpoint", "gateway"):
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
                            if role not in ("endpoint", "gateway"):
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
            if priority not in (NORMAL_PRIORITY, REROUTE_PRIORITY):
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

    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def state_change_handler(self, ev):

        datapath = ev.datapath

        if datapath is None:
            return

        dpid = datapath.id

        # Ignore if a newer connection already replaced this one.
        if self.datapaths.get(dpid) is not datapath:
            return

        del self.datapaths[dpid]

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
        """Track endpoint traffic and convert link deltas to utilization."""
        dpid = ev.msg.datapath.id
        now = time.time()

        for stat in ev.msg.body:
            port_no = int(stat.port_no)
            counter = int(stat.rx_bytes) + int(stat.tx_bytes)
            key = (dpid, port_no)
            previous = self.port_stats_previous.get(key)
            self.port_stats_previous[key] = (counter, now)

            entry = self.vlan_port_map.get(key, {})
            if (previous is not None
                    and entry.get("kind") == "access"
                    and entry.get("role") == "endpoint"):
                old_counter, old_time = previous
                if counter > old_counter and now > old_time:
                    self.switch_traffic_last_seen[dpid] = now
                    self.host_traffic_last_seen[key] = now

            peer = self.port_to_link.get((dpid, port_no))

            if peer is None:
                continue

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

        if msg.reason == ofp.OFPPR_DELETE:
            self.port_desc.pop((dpid, port_no), None)
            down = True
        else:
            self.port_desc[(dpid, port_no)] = \
                self._decode_port_name(desc.name)
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
        src_loc = self.host_location.get(src_mac)

        # Same-switch means the source host and destination host are
        # attached to the same switch, not merely that the current PacketIn
        # arrived at the destination switch after traversing a path.
        if src_loc is not None and dst_dpid == src_loc[0]:

            if dst_port == in_port and dpid == src_loc[0]:
                return

            if dpid != src_loc[0]:
                # This packet is already on an inter-switch hop; do not
                # overwrite the source flow with a false same-switch path.
                return

            self._install_output_flow(datapath, in_port, dst_mac, dst_port, vlan_id)
            self.register_active_flow(
                ("vlan_mac", vlan_id, src_mac, dst_mac),
                {
                    "src_mac": src_mac, "dst_mac": dst_mac,
                    "vlan_id": vlan_id,
                    "src_ip": self.mac_to_ip.get(src_mac),
                    "dst_ip": self.mac_to_ip.get(dst_mac),
                    "path": [int(src_loc[0])],
                    "path_type": "same_switch",
                    "path_status": "active",
                }
            )
            self._packet_out(datapath, msg, dst_port, vlan_id)
            return

        # Different switch: prefer the full path from the source's switch.

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

        self._install_path(path, src_mac, dst_mac, vlan_id)

        self.register_active_flow(
            ("vlan_mac", vlan_id, src_mac, dst_mac),
            {
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "vlan_id": vlan_id,
                "src_ip": self.mac_to_ip.get(src_mac),
                "dst_ip": self.mac_to_ip.get(dst_mac),
                "path": list(path),
                "path_type": "inter_switch",
                "path_status": "active",
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

    def block_device(self, mac, ip=None, request_id=None, reason=None):
        """Block all traffic sourced by a MAC on all connected switches.

        IP is stored for audit only. The block survives IP changes, host
        movement between connected switches, and switch reconnections while
        this controller process remains running.
        """
        mac = self.normalize_device_mac(mac)
        self.blocked_devices[mac] = {
            "mac": mac, "ip": ip, "request_id": request_id,
            "reason": reason, "blocked_at": time.time(),
        }

        datapaths = list(self.datapaths.values())
        if not datapaths:
            result = {"success": False, "status": "no_switches",
                    "mac": mac, "ip": ip,
                    "message": "Block is recorded; no switch is connected"}
            self._record_firewall_event(result, reason=reason)
            return result

        failed = []
        for datapath in datapaths:
            try:
                self._install_device_block_rule(datapath, mac)
            except Exception:
                failed.append(datapath.id)
                self.logger.exception(
                    "Failed to install device block on s%d for %s",
                    datapath.id, mac)

        success = not failed
        self.logger.warning(
            "BLOCK_DEVICE %s ip=%s switches=%s failed=%s request_id=%s reason=%s",
            mac, ip, [dp.id for dp in datapaths], failed, request_id, reason)
        result = {"success": success,
                "status": "executed" if success else "partial_failure",
                "action": "BLOCK_DEVICE", "mac": mac, "ip": ip,
                "switches": [dp.id for dp in datapaths],
                "failed_switches": failed, "request_id": request_id}
        self._record_firewall_event(result, reason=reason)
        return result

    def unblock_device(self, mac, ip=None, request_id=None, reason=None):
        """Remove a Security block without changing Trust Score/state."""
        mac = self.normalize_device_mac(mac)
        if mac not in self.blocked_devices:
            result = {"success": False, "status": "not_blocked",
                    "action": "UNBLOCK_DEVICE", "mac": mac, "ip": ip,
                    "request_id": request_id}
            self._record_firewall_event(result, reason=reason)
            return result

        datapaths = list(self.datapaths.values())
        removed = []
        try:
            for datapath in datapaths:
                self._delete_device_block_rule(datapath, mac)
                removed.append(datapath)
        except Exception:
            self.logger.exception(
                "Failed to remove device block for %s; restoring block rules", mac)
            for datapath in datapaths:
                try:
                    self._install_device_block_rule(datapath, mac)
                except Exception:
                    self.logger.exception(
                        "Failed to restore device block on s%d for %s",
                        datapath.id, mac)
            result = {"success": False, "status": "partial_failure",
                    "action": "UNBLOCK_DEVICE", "mac": mac, "ip": ip,
                    "request_id": request_id}
            self._record_firewall_event(result, reason=reason)
            return result

        self.blocked_devices.pop(mac, None)
        self.logger.info(
            "UNBLOCK_DEVICE %s ip=%s request_id=%s reason=%s",
            mac, ip, request_id, reason)
        result = {"success": True, "status": "executed",
                "action": "UNBLOCK_DEVICE", "mac": mac, "ip": ip,
                "switches": [dp.id for dp in datapaths],
                "request_id": request_id}
        self._record_firewall_event(result, reason=reason)
        return result

    def _record_firewall_event(self, result, reason=None):
        """Record a dashboard-safe security action without raw packet data."""
        event = dict(result)
        event.update({"event_type": "firewall_action", "reason": reason,
                      "timestamp": time.time()})
        self.firewall_events.append(event)
        self.firewall_events[:] = self.firewall_events[-200:]

    def get_firewall_events(self):
        """Return recent block/unblock actions for the runtime dashboard."""
        return [dict(event) for event in self.firewall_events[-200:]]

    def get_firewall_rules(self):
        """Project installed device blocks into the dashboard rule schema."""
        rules = [{"rule_id": "default-deny", "priority": 1000,
                  "action": "DROP", "direction": "both", "source": "any",
                  "destination": "any", "enabled": True, "status": "installed",
                  "source_provider": "TopologyMonitor"}]
        for mac, block in sorted(self.blocked_devices.items()):
            rules.append({"rule_id": "device-block-" + mac.replace(":", ""),
                          "priority": DEVICE_BLOCK_PRIORITY, "action": "DROP",
                          "direction": "ingress", "source": mac,
                          "destination": "any", "enabled": True,
                          "status": "installed", "ip": block.get("ip"),
                          "switches": sorted(int(dpid) for dpid in self.datapaths),
                          "reason": block.get("reason"),
                          "request_id": block.get("request_id"),
                          "blocked_at": block.get("blocked_at"),
                          "source_provider": "TopologyMonitor"})
        return rules

    # ============================================================
    # Operational graph / link isolation (called by Person 3)
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
        self._record_topology_event({
            "event_type": "link_isolation", "status": "executed",
            "failed_link": list(edge), "timestamp": time.time(),
        })
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
        self._record_topology_event({
            "event_type": "link_restore", "status": "executed",
            "restored_link": list(edge), "timestamp": time.time(),
        })
        return True

    def _record_topology_event(self, event):
        self.topology_events.append(dict(event))
        self.topology_events[:] = self.topology_events[-200:]

    def get_network_events(self):
        return [dict(event) for event in self.topology_events[-200:]]

    # ============================================================
    # CLFF management
    # ============================================================

    def _refresh_clff(self):
        """Drop old packet state, then rebuild or invalidate CLFF."""

        self.clff_packet_state.clear()
        self._clff_last_rebuild_reason = (
            "isolated_link_change" if self.isolated_links else "topology_change"
        )

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
            self._clff_last_rebuild_at = time.time()
            self._clff_last_error = None if success else "CLFF rebuild failed"

            if success:
                self.logger.info("CLFF rebuilt: %s", self.clff.summary())
            else:
                self.logger.warning("CLFF rebuild failed")

            return bool(success)

        except Exception as exc:
            self._clff_valid = False
            self._clff_last_rebuild_at = time.time()
            self._clff_last_error = str(exc)
            self.logger.exception("CLFF rebuild error: %s", exc)
            return False

    def _invalidate_clff(self):

        self._clff_valid = False
        self._clff_last_rebuild_at = time.time()
        self._clff_last_error = "operational graph is not connected"

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

        if self.is_inter_switch_port(dpid, in_port):
            return False

        if vlan_id not in ALLOWED_VLANS:
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

        if pkt is not None:
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

            if ipv4_pkt is not None:
                self._learn_ip(ipv4_pkt.src, src_mac, vlan_id)
        return True

    def _learn_from_arp(self, dpid, in_port, arp_pkt, vlan_id):

        if self.is_inter_switch_port(dpid, in_port):
            return

        self._learn_host(dpid, in_port, arp_pkt.src_mac, vlan_id=vlan_id)
        self._learn_ip(arp_pkt.src_ip, arp_pkt.src_mac, vlan_id)

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
        entry = self.vlan_port_map.get((int(dpid), int(port_no)))
        if entry is None:
            return False
        if entry["kind"] == "trunk":
            return vlan_id in entry["allowed_vlans"]
        return entry["vlan_id"] == vlan_id

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

            if host_dpid == dpid and self.is_host_port(dpid, host_port):
                ports.add(host_port)

        ports.discard(in_port)

        return ports

    def _get_host_ports_from_desc(self, dpid):

        ports = set()

        for (port_dpid, port_no) in list(self.port_desc.keys()):

            if port_dpid != dpid:
                continue

            if self.is_host_port(dpid, port_no):
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

    def is_host_port(self, dpid, port_no):

        try:
            port_no = int(port_no)
        except (TypeError, ValueError):
            return False

        if port_no <= 0 or self._is_special_port(port_no):
            return False

        return not self.is_inter_switch_port(dpid, port_no)

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
        result = self.path_engine.get_best_path(
            src=src_dpid,
            dst=dst_dpid,
            graph=self.operational_graph,
            network_state=self.path_engine.network_state,
        )
        return result.get("path") if result.get("success") else None

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

    def _install_path(self, path, src_mac, dst_mac, vlan_id=None):
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

        self._install_direction(path, src_mac, dst_mac, dst_port, vlan_id)

        if src_loc is not None and src_loc[0] == path[0]:
            self._install_direction(
                list(reversed(path)), dst_mac, src_mac, src_loc[1], vlan_id)

        return True

    def _install_direction(self, path, eth_src, eth_dst, final_port, vlan_id):

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
            match = parser.OFPMatch(
                in_port=in_port, eth_src=eth_src, eth_dst=eth_dst,
                vlan_vid=OFPVID_PRESENT | vlan_id)
            flow_rules.append((datapath, match, actions))

        for datapath, match, actions in flow_rules:
            self._add_flow(
                datapath, REROUTE_PRIORITY, match, actions,
                idle_timeout=HOST_FLOW_IDLE_TIMEOUT,
                hard_timeout=HOST_FLOW_HARD_TIMEOUT,
                track_key=("path", vlan_id, eth_src, eth_dst))

        return True

    def _install_output_flow(self, datapath, in_port, dst_mac, out_port, vlan_id):

        parser = datapath.ofproto_parser

        src_mac = None
        for mac, location in self.host_location.items():
            if location == (datapath.id, in_port):
                src_mac = mac
                break
        if src_mac is None:
            return
        match = parser.OFPMatch(
            in_port=in_port, eth_src=src_mac, eth_dst=dst_mac,
            vlan_vid=OFPVID_PRESENT | vlan_id)

        actions = self._flow_output_actions(
            datapath, in_port, out_port, vlan_id)
        if actions is None:
            self.logger.warning(
                "Cannot install VLAN %d output flow on s%d:%d -> %d",
                vlan_id, datapath.id, in_port, out_port)
            return

        self._add_flow(
            datapath, NORMAL_PRIORITY, match, actions,
            idle_timeout=HOST_FLOW_IDLE_TIMEOUT,
            hard_timeout=HOST_FLOW_HARD_TIMEOUT,
            track_key=("out", vlan_id, in_port, src_mac, dst_mac))

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

            if path and self._install_path(path, src_mac, dst_mac):
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
                    flow.get("vlan_id")
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

    def get_clff_status(self):
        """Return live CLFF state for the runtime dashboard."""
        summary = self.clff.summary() if self.clff is not None else {}
        return {
            "enabled": self.clff is not None,
            "ready": bool(self._clff_usable()),
            "algorithm": "bfs_per_root",
            "root_count": len(self.clff.trees) if self.clff is not None and hasattr(self.clff, "trees") else 0,
            "tree_count": summary.get("trees", 0),
            "broadcast_ports": summary.get("broadcast_ports", 0),
            "uses_ofpp_flood": False,
            "uses_stp": False,
            "physical_graph_nodes": self.graph.number_of_nodes(),
            "physical_graph_edges": self.graph.number_of_edges(),
            "operational_graph_nodes": self.operational_graph.number_of_nodes(),
            "operational_graph_edges": self.operational_graph.number_of_edges(),
            "last_rebuild_at": self._clff_last_rebuild_at,
            "last_rebuild_reason": self._clff_last_rebuild_reason,
            "last_error": self._clff_last_error,
        }

    def get_host_status(self):
        result = {}
        for mac, loc in list(self.host_location.items()):
            flows = []
            for flow in self.active_flows.values():
                if not isinstance(flow, dict) or flow.get("src_mac") != mac:
                    continue
                item = dict(flow)
                item.pop("src_mac", None)
                item.pop("dst_mac", None)
                flows.append(item)
            result[mac] = {
                "ip": self.mac_to_ip.get(mac),
                "dpid": loc[0],
                "port": loc[1],
                "active_flows": flows,
            }
        return result

    def get_active_flow_paths(self):
        """Return flow-specific paths currently known by the controller."""
        result = []
        for flow in self.active_flows.values():
            if not isinstance(flow, dict):
                continue
            item = dict(flow)
            item.pop("src_mac", None)
            item.pop("dst_mac", None)
            result.append(item)
        return result

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
