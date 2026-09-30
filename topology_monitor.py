#!/usr/bin/env python3

# ================================================================
# TrustFlow - Topology Monitor
#
# Responsibilities:
#   - Discover OpenFlow switches
#   - Discover physical inter-switch links using LLDP
#   - Maintain NetworkX topology graph
#   - Learn directly connected hosts
#   - Handle ARP
#   - Perform normal L2 forwarding
#   - Perform shortest-path forwarding using NetworkX
#   - Provide loop-free forwarding information
#   - Support host rerouting events
#   - Maintain CLFF broadcast tree
#   - Perform CLFF forwarding for broadcast / unknown traffic
#
# OpenFlow:
#   OpenFlow 1.3
#
# Architecture:
#   TopologyMonitor OWNS ALL FORWARDING.
#
#   TopologyMonitor:
#       - LLDP
#       - topology discovery
#       - host learning
#       - ARP
#       - known unicast
#       - unknown unicast
#       - broadcast / multicast
#       - CLFF
#       - Dijkstra
#       - rerouting
#
#   TrafficMonitorMerged:
#       - packet observation
#       - CSV
#       - FlowStats
#       - trust / security telemetry
#       - quarantine / restore
#       - Security actions
#
# IMPORTANT:
#   TrafficMonitorMerged MUST NOT send forwarding PacketOuts.
#
# CLFF:
#   - No OFPP_FLOOD
#   - No STP dependency
#   - Physical topology remains unchanged
#   - One BFS tree exists for every possible root
#   - A broadcast packet keeps the SAME root while traversing
#     the topology
#   - Known unicast remains Dijkstra-based
# ================================================================


import time
import heapq
from collections import defaultdict

import networkx as nx

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import event as controller_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import (
    packet,
    ethernet,
    ether_types,
    arp,
    ipv4,
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

OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

LLDP_INTERVAL = 3
LLDP_STALE_TIMEOUT = 30

LLDP_MAC = "01:80:c2:00:00:0e"

EXPECTED_SWITCHES = 5
EXPECTED_PHYSICAL_LINKS = 7

NORMAL_PRIORITY = 10
REROUTE_PRIORITY = 100

HOST_FLOW_IDLE_TIMEOUT = 30
HOST_FLOW_HARD_TIMEOUT = 0

ETH_TYPE_LLDP = 0x88CC
ETH_TYPE_ARP = 0x0806

SPECIAL_PORT_NAMES = {
    "local",
}


# ================================================================
# CLFF Packet State
# ================================================================

CLFF_PACKET_STATE_TIMEOUT = 5


# ================================================================
# Custom Ryu Event
# ================================================================

class EventRerouteHost(controller_event.EventBase):
    """
    Event used by other Network components to request host rerouting.
    """

    def __init__(self, host_ip, request_id=None):
        super(EventRerouteHost, self).__init__()

        self.host_ip = host_ip
        self.request_id = request_id


# ================================================================
# Topology Monitor
# ================================================================

class TopologyMonitor(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {}

    def __init__(self, *args, **kwargs):
        super(TopologyMonitor, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.graph = nx.Graph()
        self.edges = set()

        self.port_to_link = {}
        self.link_to_port = {}

        self.lldp_links = {}
        self.port_desc = {}

        self.host_location = {}
        self.ip_to_mac = {}

        self.active_flows = {}

        self.topology_ready = False
        self.full_topology_discovered = False

        if CLFFEngine is not None:
            self.clff = CLFFEngine(logger=self.logger)
        else:
            self.clff = None

        self.clff_packet_state = {}

        self.lldp_thread = hub.spawn(self._lldp_loop)

        self.logger.info("TopologyMonitor initialized")
        self.logger.info("Forwarding owner: TopologyMonitor")
        self.logger.info("CLFF forwarding: ENABLED (when topology is ready)")
        self.logger.info("TrafficMonitor forwarding: DELEGATED")

    # ============================================================
    # Switch Features
    # ============================================================

    @set_ev_cls(
        ofp_event.EventOFPSwitchFeatures,
        CONFIG_DISPATCHER
    )
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        dpid = datapath.id

        self.datapaths[dpid] = datapath
        self.graph.add_node(dpid)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table miss
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self._add_flow(datapath, 0, match, actions)

        # LLDP
        lldp_match = parser.OFPMatch(eth_type=ETH_TYPE_LLDP)
        lldp_actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self._add_flow(
            datapath,
            NORMAL_PRIORITY,
            lldp_match,
            lldp_actions
        )

        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

        self.logger.info("Switch connected: s%d", dpid)

    # ============================================================
    # Port Description
    # ============================================================

    @set_ev_cls(
        ofp_event.EventOFPPortDescStatsReply,
        MAIN_DISPATCHER
    )
    def port_desc_reply_handler(self, ev):

        datapath = ev.msg.datapath
        dpid = datapath.id

        for port in ev.msg.body:

            port_no = port.port_no
            port_name = port.name

            if isinstance(port_name, bytes):
                try:
                    port_name = port_name.decode("utf-8", errors="ignore")
                except Exception:
                    port_name = str(port_name)

            self.port_desc[(dpid, port_no)] = str(port_name)

        self.logger.debug("Port descriptions updated for s%d", dpid)

    # ============================================================
    # Packet-In
    # ============================================================

    @set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER
    )
    def packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        if "in_port" not in msg.match:
            return

        in_port = msg.match["in_port"]

        try:
            in_port = int(in_port)
        except (TypeError, ValueError):
            pass

        try:
            pkt = packet.Packet(msg.data)
        except Exception:
            return

        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        if eth_pkt is None:
            return

        src_mac = eth_pkt.src
        dst_mac = eth_pkt.dst

        # LLDP
        if eth_pkt.ethertype == ETH_TYPE_LLDP:
            self._handle_lldp(datapath, in_port, pkt)
            return

        # Ignore LLDP MAC
        if str(dst_mac).lower() == LLDP_MAC:
            return

        # ARP
        arp_pkt = pkt.get_protocol(arp.arp)

        if arp_pkt is not None:
            self._handle_arp(datapath, in_port, pkt, arp_pkt)
            return

        # Host learning
        if not self.is_inter_switch_port(dpid, in_port):
            self._learn_host(dpid, in_port, src_mac, pkt)

        # Broadcast / multicast
        if self._is_broadcast_or_multicast(dst_mac):
            self._flood_ethernet(datapath, msg, in_port)
            return

        # Known destination
        destination = self.host_location.get(dst_mac)

        if destination is not None:

            dst_dpid, dst_port = destination

            if dst_dpid == dpid:

                if dst_port == in_port:
                    return

                self._install_output_flow(
                    datapath, in_port, dst_mac, dst_port
                )
                self._packet_out(datapath, msg, dst_port)
                return

            path = self._shortest_path(dpid, dst_dpid)

            if not path:
                self.logger.warning(
                    "No path from s%d to s%d for %s",
                    dpid, dst_dpid, dst_mac
                )
                self._flood_ethernet(datapath, msg, in_port)
                return

            out_port = self.get_forwarding_port(dpid, dst_dpid)

            if out_port is None:
                self.logger.warning(
                    "No forwarding port from s%d to s%d",
                    dpid, dst_dpid
                )
                return

            self._install_path(path, src_mac, dst_mac)
            self._packet_out(datapath, msg, out_port)
            return

        # Unknown destination
        self._flood_ethernet(datapath, msg, in_port)

    # ============================================================
    # LLDP Handling
    # ============================================================

    def _handle_lldp(self, datapath, in_port, pkt):

        if lldp is None:
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

        if remote_dpid is None:
            return

        if remote_port is None:
            return

        try:
            local_port = int(in_port)
        except (TypeError, ValueError):
            local_port = in_port

        try:
            remote_dpid_int = int(remote_dpid)
        except (TypeError, ValueError):
            return

        try:
            remote_port_int = int(remote_port)
        except (TypeError, ValueError):
            return

        now = time.time()

        self.lldp_links[(dpid, local_port)] = {
            "remote_dpid": remote_dpid_int,
            "remote_port": remote_port_int,
            "last_seen": now
        }

        self._update_topology_from_lldp()

    # ============================================================
    # Update Topology from LLDP
    # ============================================================

    def _update_topology_from_lldp(self):

        now = time.time()

        stale = []

        for local_key, info in list(self.lldp_links.items()):

            if (now - info["last_seen"]) > LLDP_STALE_TIMEOUT:
                stale.append(local_key)

        for key in stale:
            del self.lldp_links[key]

        new_port_to_link = {}
        new_link_to_port = {}
        new_edges = set()

        for (local_dpid, local_port), info in list(self.lldp_links.items()):

            remote_dpid = info["remote_dpid"]
            remote_port = info["remote_port"]

            if local_dpid == remote_dpid:
                continue

            try:
                local_dpid = int(local_dpid)
                local_port = int(local_port)
                remote_dpid = int(remote_dpid)
                remote_port = int(remote_port)
            except (TypeError, ValueError):
                continue

            new_port_to_link[(local_dpid, local_port)] = (
                remote_dpid, remote_port
            )
            new_port_to_link[(remote_dpid, remote_port)] = (
                local_dpid, local_port
            )

            link_key = tuple(sorted([local_dpid, remote_dpid]))
            new_edges.add(link_key)

            new_link_to_port[(local_dpid, remote_dpid)] = (
                local_port, remote_port
            )
            new_link_to_port[(remote_dpid, local_dpid)] = (
                remote_port, local_port
            )

        self.graph.clear()

        for dpid in self.datapaths:
            self.graph.add_node(dpid)

        for dpid_a, dpid_b in new_edges:
            self.graph.add_edge(dpid_a, dpid_b)

        self.port_to_link = new_port_to_link
        self.link_to_port = new_link_to_port
        self.edges = new_edges

        switch_count = len(self.graph.nodes())
        link_count = len(self.graph.edges())

        self.topology_ready = (switch_count > 0 and link_count > 0)

        if (
            switch_count >= EXPECTED_SWITCHES
            and link_count >= EXPECTED_PHYSICAL_LINKS
        ):

            if not self.full_topology_discovered:
                self.full_topology_discovered = True
                self.logger.info("FULL EXPECTED TOPOLOGY DISCOVERED.")

            self._rebuild_clff()

        self.logger.debug(
            "Topology update: switches=%d links=%d",
            switch_count, link_count
        )

    # ============================================================
    # Host Learning
    # ============================================================

    def _learn_host(self, dpid, in_port, src_mac, pkt=None):

        if self.is_inter_switch_port(dpid, in_port):
            return

        if src_mac and src_mac.startswith("02:00:00:00:00:"):
            return

        if self._is_broadcast_or_multicast(src_mac):
            return

        new_location = (dpid, in_port)
        old_location = self.host_location.get(src_mac)

        if old_location is not None and old_location != new_location:

            old_dpid, old_port = old_location

            if old_dpid != dpid:
                self.logger.debug(
                    "Ignoring MAC flap: %s s%d:%d -> s%d:%d",
                    src_mac, old_dpid, old_port, dpid, in_port
                )
                return

            self.logger.warning(
                "Host MAC moved: %s from s%d:%d to s%d:%d",
                src_mac, old_dpid, old_port, dpid, in_port
            )

        if old_location != new_location:
            self.host_location[src_mac] = new_location
            self.logger.info(
                "Host learned: %s -> s%d:%d",
                src_mac, dpid, in_port
            )

        if pkt is not None:
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            if ipv4_pkt is not None:
                self.ip_to_mac[ipv4_pkt.src] = src_mac

    # ============================================================
    # ARP Handler
    # ============================================================

    def _handle_arp(self, datapath, in_port, pkt, arp_pkt):

        dpid = datapath.id

        if (
            arp_pkt.src_ip
            and arp_pkt.src_mac
            and not self.is_inter_switch_port(dpid, in_port)
        ):
            self.ip_to_mac[arp_pkt.src_ip] = arp_pkt.src_mac
            self.host_location[arp_pkt.src_mac] = (dpid, in_port)

            self.logger.debug(
                "ARP learned: %s -> %s -> s%d:%d",
                arp_pkt.src_ip, arp_pkt.src_mac, dpid, in_port
            )

        if arp_pkt.opcode == arp.ARP_REQUEST:

            target_ip = arp_pkt.dst_ip
            target_mac = self.ip_to_mac.get(target_ip)

            if target_mac is not None:

                target_location = self.host_location.get(target_mac)

                if target_location is not None:

                    target_dpid, target_port = target_location

                    self._send_arp_reply(
                        datapath, in_port,
                        arp_pkt.src_mac, arp_pkt.src_ip,
                        target_mac, target_ip
                    )

                    self.logger.debug(
                        "Proxy ARP: %s is at %s",
                        target_ip, target_mac
                    )

                    return

            self._flood_arp(datapath, in_port, pkt)
            return

        if arp_pkt.opcode == arp.ARP_REPLY:

            destination_mac = self.ip_to_mac.get(arp_pkt.dst_ip)

            if destination_mac is not None:

                destination = self.host_location.get(destination_mac)

                if destination is not None:

                    dst_dpid, dst_port = destination

                    if dst_dpid == dpid:

                        if dst_port != in_port:
                            self._packet_out_raw(
                                datapath, pkt.data, dst_port, in_port
                            )
                        return

                    path = self._shortest_path(dpid, dst_dpid)

                    if path:

                        out_port = self.get_forwarding_port(dpid, dst_dpid)

                        if out_port is not None:
                            self._packet_out_raw(
                                datapath, pkt.data, out_port, in_port
                            )
                            return

            self._flood_arp(datapath, in_port, pkt)

    # ============================================================
    # ARP Flooding
    # ============================================================

    def _flood_arp(self, datapath, in_port, pkt):

        dpid = datapath.id
        ports = set()

        for host_mac, location in list(self.host_location.items()):

            host_dpid, host_port = location

            if host_dpid != dpid:
                continue

            if host_port == in_port:
                continue

            if self.is_inter_switch_port(dpid, host_port):
                continue

            if not self.is_host_port(dpid, host_port):
                continue

            ports.add(host_port)

        ports.update(self._get_host_ports_from_desc(dpid))

        final_ports = set()

        for port_no in ports:

            if port_no == in_port:
                continue

            if port_no <= 0:
                continue

            if self._is_special_port(port_no):
                continue

            if self.is_inter_switch_port(dpid, port_no):
                continue

            if not self.is_host_port(dpid, port_no):
                continue

            final_ports.add(port_no)

        if not final_ports:
            self.logger.warning(
                "No host ports available for ARP flooding on s%d", dpid
            )
            return

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        actions = [
            parser.OFPActionOutput(port_no)
            for port_no in sorted(final_ports)
        ]

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=pkt.data
        )

        datapath.send_msg(out)

        self.logger.debug(
            "ARP flood on s%d: host-facing ports=%s",
            dpid, sorted(final_ports)
        )

    # ============================================================
    # Host Port Discovery
    # ============================================================

    def _get_host_ports_from_desc(self, dpid):

        ports = set()

        for (port_key, port_name) in list(self.port_desc.items()):

            port_dpid, port_no = port_key

            if port_dpid != dpid:
                continue

            if port_no <= 0:
                continue

            if self._is_special_port(port_no):
                continue

            if self.is_inter_switch_port(dpid, port_no):
                continue

            ports.add(port_no)

        return ports

    # ============================================================
    # Ethernet Flooding / CLFF
    # ============================================================

    def _flood_ethernet(self, datapath, msg, in_port):

        dpid = datapath.id

        self._cleanup_clff_packet_state()

        packet_key = self._get_clff_packet_key(msg)

        state = self.clff_packet_state.get(packet_key)

        if state is None:

            root_dpid = self._get_clff_root(dpid, msg)

            self.clff_packet_state[packet_key] = {
                "root": root_dpid,
                "created": time.time()
            }

        else:
            root_dpid = state["root"]

        processed_switches = state.get(
            "processed_switches", set()
        ) if state is not None else set()

        if dpid in processed_switches:
            self.logger.debug(
                "CLFF duplicate suppressed: packet=%s switch=s%d",
                packet_key, dpid
            )
            return

        if state is None:
            state = self.clff_packet_state[packet_key]

        state.setdefault("processed_switches", set()).add(dpid)

        if self.clff is None or not self.clff.is_ready():

            self.logger.warning(
                "CLFF unavailable on s%d (root=s%d). "
                "No inter-switch flooding will be used.",
                dpid, root_dpid
            )

            self._flood_ethernet_host_only(datapath, msg, in_port)
            return

        tree = self.clff.get_tree(root_dpid)

        if tree is None:

            self.logger.warning(
                "CLFF root s%d has no tree. "
                "Packet stays local on s%d.",
                root_dpid, dpid
            )

            self._flood_ethernet_host_only(datapath, msg, in_port)
            return

        child_ports = self.clff.get_forward_ports(root_dpid, dpid)

        host_ports = self._get_host_ports_from_desc(dpid)

        for host_mac, location in list(self.host_location.items()):

            host_dpid, host_port = location

            if host_dpid != dpid:
                continue

            if not self.is_host_port(dpid, host_port):
                continue

            host_ports.add(host_port)

        final_ports = set()

        for port_no in child_ports:

            try:
                port_no = int(port_no)
            except (TypeError, ValueError):
                continue

            if port_no == in_port:
                continue

            if port_no <= 0:
                continue

            if self._is_special_port(port_no):
                continue

            if not self.is_inter_switch_port(dpid, port_no):
                continue

            final_ports.add(port_no)

        for port_no in host_ports:

            try:
                port_no = int(port_no)
            except (TypeError, ValueError):
                continue

            if port_no == in_port:
                continue

            if port_no <= 0:
                continue

            if self._is_special_port(port_no):
                continue

            if self.is_inter_switch_port(dpid, port_no):
                continue

            final_ports.add(port_no)

        if not final_ports:
            self.logger.debug(
                "CLFF: no output ports on s%d (root=s%d, in_port=%s)",
                dpid, root_dpid, in_port
            )
            return

        self._packet_out(datapath, msg, sorted(final_ports))

        self.logger.debug(
            "CLFF forward: packet=%s root=s%d current=s%d "
            "in=%s outputs=%s",
            packet_key, root_dpid, dpid, in_port, sorted(final_ports)
        )

    # ============================================================
    # CLFF Packet Key
    # ============================================================

    def _get_clff_packet_key(self, msg):

        try:
            data = bytes(msg.data)
        except Exception:
            data = str(msg.data).encode("utf-8", errors="ignore")

        try:
            data_hash = hash(data)
        except Exception:
            data_hash = id(data)

        return (
            msg.datapath.id,
            msg.match.get("in_port"),
            data_hash
        )

    # ============================================================
    # CLFF Root Selection
    # ============================================================

    def _get_clff_root(self, ingress_dpid, msg):

        try:
            pkt = packet.Packet(msg.data)
        except Exception:
            return ingress_dpid

        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        if eth_pkt is not None:

            src_mac = eth_pkt.src
            source_location = self.host_location.get(src_mac)

            if source_location is not None:

                source_dpid, source_port = source_location

                if source_dpid in self.graph:
                    return source_dpid

        return ingress_dpid

    # ============================================================
    # CLFF State Cleanup
    # ============================================================

    def _cleanup_clff_packet_state(self):

        now = time.time()
        stale_keys = []

        for packet_key, state in list(self.clff_packet_state.items()):

            created = state.get("created", now)

            if (now - created) > CLFF_PACKET_STATE_TIMEOUT:
                stale_keys.append(packet_key)

        for packet_key in stale_keys:
            self.clff_packet_state.pop(packet_key, None)

    # ============================================================
    # Host-Only Fallback
    # ============================================================

    def _flood_ethernet_host_only(self, datapath, msg, in_port):

        dpid = datapath.id
        ports = set()

        ports.update(self._get_host_ports_from_desc(dpid))

        for mac, location in list(self.host_location.items()):

            host_dpid, host_port = location

            if host_dpid != dpid:
                continue

            if host_port == in_port:
                continue

            if self.is_host_port(dpid, host_port):
                ports.add(host_port)

        ports.discard(in_port)

        final_ports = []

        for port_no in ports:

            if port_no <= 0:
                continue

            if self._is_special_port(port_no):
                continue

            if self.is_inter_switch_port(dpid, port_no):
                continue

            final_ports.append(port_no)

        if not final_ports:
            return

        self._packet_out(
            datapath, msg, sorted(set(final_ports))
        )

        self.logger.debug(
            "Host-only fallback on s%d: ports=%s",
            dpid, sorted(set(final_ports))
        )

    # ============================================================
    # ARP Reply
    # ============================================================

    def _send_arp_reply(
        self, datapath, out_port,
        requester_mac, requester_ip,
        target_mac, target_ip
    ):

        e = ethernet.ethernet(
            dst=requester_mac,
            src=target_mac,
            ethertype=ETH_TYPE_ARP
        )

        a = arp.arp(
            hwtype=1, proto=0x0800, hlen=6, plen=4,
            opcode=arp.ARP_REPLY,
            src_mac=target_mac, src_ip=target_ip,
            dst_mac=requester_mac, dst_ip=requester_ip
        )

        pkt = packet.Packet()
        pkt.add_protocol(e)
        pkt.add_protocol(a)
        pkt.serialize()

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        actions = [parser.OFPActionOutput(out_port)]

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data
        )

        datapath.send_msg(out)

    # ============================================================
    # Inter-Switch Port Check
    # ============================================================

    def is_inter_switch_port(self, dpid, port_no):

        if (dpid, port_no) in self.port_to_link:
            return True

        try:
            port_str = str(port_no)
        except Exception:
            port_str = None

        if port_str is not None and (dpid, port_str) in self.port_to_link:
            return True

        if isinstance(port_no, str):
            try:
                port_int = int(port_no)
                if (dpid, port_int) in self.port_to_link:
                    return True
            except (TypeError, ValueError):
                pass

        return False

    # ============================================================
    # Host Port Check
    # ============================================================

    def is_host_port(self, dpid, port_no):

        try:
            port_no = int(port_no)
        except (TypeError, ValueError):
            return False

        if port_no <= 0:
            return False

        if self._is_special_port(port_no):
            return False

        return not self.is_inter_switch_port(dpid, port_no)

    # ============================================================
    # Special OpenFlow Port Check
    # ============================================================

    def _is_special_port(self, port_no):

        try:
            port_no = int(port_no)

            if port_no >= ofproto_v1_3.OFPP_MAX:
                return True

            if port_no == ofproto_v1_3.OFPP_LOCAL:
                return True

        except Exception:
            pass

        return False

    # ============================================================
    # Shortest Path
    # ============================================================

    def _shortest_path(self, src_dpid, dst_dpid):

        if src_dpid not in self.graph:
            return None

        if dst_dpid not in self.graph:
            return None

        try:
            return nx.shortest_path(self.graph, src_dpid, dst_dpid)
        except nx.NetworkXNoPath:
            return None
        except nx.NodeNotFound:
            return None

    # ============================================================
    # Get Forwarding Port
    # ============================================================

    def get_forwarding_port(self, src_dpid, dst_dpid):

        if src_dpid == dst_dpid:
            return None

        path = self._shortest_path(src_dpid, dst_dpid)

        if not path or len(path) < 2:
            return None

        next_hop = path[1]

        link = self.link_to_port.get((src_dpid, next_hop))

        if link is None:
            return None

        src_port, _ = link
        return src_port

    # ============================================================
    # Install Path
    # ============================================================

    def _install_path(self, path, src_mac, dst_mac):

        if not path:
            return

        for index in range(len(path) - 1):

            current_dpid = path[index]
            next_dpid = path[index + 1]

            datapath = self.datapaths.get(current_dpid)

            if datapath is None:
                continue

            link = self.link_to_port.get((current_dpid, next_dpid))

            if link is None:
                continue

            out_port, _ = link

            parser = datapath.ofproto_parser

            match = parser.OFPMatch(
                eth_src=src_mac,
                eth_dst=dst_mac
            )

            actions = [parser.OFPActionOutput(out_port)]

            self._add_flow(
                datapath,
                REROUTE_PRIORITY,
                match,
                actions,
                idle_timeout=HOST_FLOW_IDLE_TIMEOUT,
                hard_timeout=HOST_FLOW_HARD_TIMEOUT
            )

        reverse_path = list(reversed(path))

        for index in range(len(reverse_path) - 1):

            current_dpid = reverse_path[index]
            next_dpid = reverse_path[index + 1]

            datapath = self.datapaths.get(current_dpid)

            if datapath is None:
                continue

            link = self.link_to_port.get((current_dpid, next_dpid))

            if link is None:
                continue

            out_port, _ = link

            parser = datapath.ofproto_parser

            match = parser.OFPMatch(
                eth_src=dst_mac,
                eth_dst=src_mac
            )

            actions = [parser.OFPActionOutput(out_port)]

            self._add_flow(
                datapath,
                REROUTE_PRIORITY,
                match,
                actions,
                idle_timeout=HOST_FLOW_IDLE_TIMEOUT,
                hard_timeout=HOST_FLOW_HARD_TIMEOUT
            )

    # ============================================================
    # Install Direct Output Flow
    # ============================================================

    def _install_output_flow(self, datapath, in_port, dst_mac, out_port):

        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            in_port=in_port,
            eth_dst=dst_mac
        )

        actions = [parser.OFPActionOutput(out_port)]

        self._add_flow(
            datapath,
            NORMAL_PRIORITY,
            match,
            actions,
            idle_timeout=HOST_FLOW_IDLE_TIMEOUT,
            hard_timeout=HOST_FLOW_HARD_TIMEOUT
        )

    # ============================================================
    # Generic Flow Installation
    # ============================================================

    def _add_flow(
        self, datapath, priority, match, actions,
        idle_timeout=0, hard_timeout=0
    ):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )

        datapath.send_msg(mod)

    # ============================================================
    # Packet-Out
    # ============================================================

    def _packet_out(self, datapath, msg, out_port):

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        if isinstance(out_port, (list, tuple, set)):
            actions = [
                parser.OFPActionOutput(port) for port in out_port
            ]
        else:
            actions = [parser.OFPActionOutput(out_port)]

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=msg.match["in_port"],
            actions=actions,
            data=msg.data
        )

        datapath.send_msg(out)

    # ============================================================
    # Raw Packet-Out
    # ============================================================

    def _packet_out_raw(self, datapath, data, out_port, in_port):

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        actions = [parser.OFPActionOutput(out_port)]

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)

    # ============================================================
    # Broadcast / Multicast Check
    # ============================================================

    def _is_broadcast_or_multicast(self, mac):

        mac = str(mac).lower()

        if mac == "ff:ff:ff:ff:ff:ff":
            return True

        try:
            first_octet = int(mac.split(":")[0], 16)
            return bool(first_octet & 1)
        except Exception:
            return False

    # ============================================================
    # LLDP Sender Loop
    # ============================================================

    def _lldp_loop(self):

        while True:

            try:
                self._send_lldp_once()
            except Exception as exc:
                self.logger.exception("LLDP loop error: %s", exc)

            hub.sleep(LLDP_INTERVAL)

    # ============================================================
    # Send LLDP
    # ============================================================

    def _send_lldp_once(self):

        if lldp is None:
            return

        for dpid, datapath in list(self.datapaths.items()):

            ports = self._get_valid_physical_ports(dpid)

            if not ports:
                continue

            for port_no in ports:

                try:
                    self._send_lldp(datapath, port_no)
                except Exception as exc:
                    self.logger.debug(
                        "Could not send LLDP s%d:%d: %s",
                        dpid, port_no, exc
                    )

    # ============================================================
    # Valid Physical Ports
    # ============================================================

    def _get_valid_physical_ports(self, dpid):

        ports = set()

        for (port_dpid, port_no), port_name in list(self.port_desc.items()):

            if port_dpid != dpid:
                continue

            if port_no <= 0:
                continue

            if self._is_special_port(port_no):
                continue

            ports.add(port_no)

        return ports

    # ============================================================
    # Construct + Send LLDP
    # ============================================================

    def _send_lldp(self, datapath, port_no):

        if lldp is None:
            return

        dpid = datapath.id

        chassis_id = lldp.ChassisID(
            subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
            chassis_id=str(dpid).encode()
        )

        port_id = lldp.PortID(
            subtype=lldp.PortID.SUB_PORT_COMPONENT,
            port_id=str(port_no).encode()
        )

        ttl = lldp.TTL(ttl=LLDP_INTERVAL * 2)
        end = lldp.End()

        lldp_pkt = lldp.lldp(
            tlvs=[chassis_id, port_id, ttl, end]
        )

        eth = ethernet.ethernet(
            dst=LLDP_MAC,
            src=self._get_switch_mac(dpid),
            ethertype=ETH_TYPE_LLDP
        )

        pkt = packet.Packet()
        pkt.add_protocol(eth)
        pkt.add_protocol(lldp_pkt)
        pkt.serialize()

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        actions = [parser.OFPActionOutput(port_no)]

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data
        )

        datapath.send_msg(out)

    # ============================================================
    # Switch Source MAC
    # ============================================================

    def _get_switch_mac(self, dpid):

        return (
            "02:%02x:%02x:%02x:%02x:%02x"
            % (
                (dpid >> 32) & 0xff,
                (dpid >> 24) & 0xff,
                (dpid >> 16) & 0xff,
                (dpid >> 8) & 0xff,
                dpid & 0xff
            )
        )

    # ============================================================
    # CLFF Rebuild
    # ============================================================

    def _rebuild_clff(self):

        if self.clff is None:
            return False

        if not self.topology_ready:
            return False

        try:

            success = self.clff.build_trees(
                self.graph,
                self.link_to_port
            )

            if success:
                self.logger.info("CLFF trees rebuilt successfully.")
                summary = self.clff.summary()
                self.logger.info("CLFF summary: %s", summary)
            else:
                self.logger.warning("CLFF tree rebuild failed.")

            return success

        except Exception as exc:
            self.logger.exception("Failed to rebuild CLFF: %s", exc)
            return False

    # ============================================================
    # Reroute Host Event
    # ============================================================

    @set_ev_cls(EventRerouteHost)
    def handle_reroute_host(self, ev):

        host_ip = ev.host_ip
        request_id = ev.request_id

        mac = self.ip_to_mac.get(host_ip)

        if mac is None:
            self.logger.warning(
                "Reroute requested for unknown host %s (request_id=%s)",
                host_ip, request_id
            )
            return

        location = self.host_location.get(mac)

        if location is None:
            self.logger.warning(
                "No location known for host %s (request_id=%s)",
                host_ip, request_id
            )
            return

        dst_dpid, dst_port = location

        self.logger.info(
            "Reroute requested for host %s at s%d:%d (request_id=%s)",
            host_ip, dst_dpid, dst_port, request_id
        )

        for flow_id, flow in list(self.active_flows.items()):

            if not isinstance(flow, dict):
                continue

            src_ip = flow.get("src_ip")
            flow_dst_ip = flow.get("dst_ip")

            if src_ip != host_ip and flow_dst_ip != host_ip:
                continue

            src_mac = flow.get("src_mac")
            dst_mac = flow.get("dst_mac")

            if not src_mac or not dst_mac:
                continue

            src_location = self.host_location.get(src_mac)
            dst_location = self.host_location.get(dst_mac)

            if src_location is None or dst_location is None:
                continue

            src_dpid = src_location[0]
            dst_dpid = dst_location[0]

            path = self._shortest_path(src_dpid, dst_dpid)

            if path:
                self._install_path(path, src_mac, dst_mac)

        self.logger.info(
            "Reroute processing completed for %s (request_id=%s)",
            host_ip, request_id
        )

    # ============================================================
    # Active Flow Registration
    # ============================================================

    def register_active_flow(self, flow_id, flow_data):
        self.active_flows[flow_id] = flow_data

    def remove_active_flow(self, flow_id):
        self.active_flows.pop(flow_id, None)

    # ============================================================
    # Clear Reroute Flows
    # ============================================================

    def clear_all_flows(self):

        for dpid, datapath in list(self.datapaths.items()):

            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=REROUTE_PRIORITY,
                match=parser.OFPMatch()
            )

            datapath.send_msg(mod)

        self.logger.info("Reroute flows cleared.")

    # ============================================================
    # Topology Status
    # ============================================================

    def get_topology_status(self):

        return {
            "topology_ready": self.topology_ready,
            "full_topology_discovered": self.full_topology_discovered,
            "switch_count": len(self.graph.nodes()),
            "link_count": len(self.graph.edges()),
            "host_count": len(self.host_location),
            "switches": sorted(self.graph.nodes()),
            "links": [list(edge) for edge in self.graph.edges()],
            "clff_ready": (
                self.clff is not None and self.clff.is_ready()
            ),
            "clff_trees": (
                len(self.clff.trees) if self.clff is not None else 0
            ),
        }

    # ============================================================
    # Host Status
    # ============================================================

    def get_host_status(self):

        result = {}

        for mac, location in list(self.host_location.items()):

            dpid, port_no = location
            ip = None

            for host_ip, host_mac in list(self.ip_to_mac.items()):
                if host_mac == mac:
                    ip = host_ip
                    break

            result[mac] = {
                "ip": ip, "dpid": dpid, "port": port_no
            }

        return result

    # ============================================================
    # Graph / Links
    # ============================================================

    def get_graph(self):
        return self.graph.copy()

    def get_links(self):

        result = []

        for src_dpid, dst_dpid in self.graph.edges():

            ports = self.link_to_port.get((src_dpid, dst_dpid))

            result.append({
                "src_dpid": src_dpid,
                "dst_dpid": dst_dpid,
                "src_port": ports[0] if ports else None,
                "dst_port": ports[1] if ports else None
            })

        return result

    # ============================================================
    # Topology Summary
    # ============================================================

    def print_topology_summary(self):

        self.logger.info("========== TOPOLOGY SUMMARY ==========")
        self.logger.info("Switches: %s", sorted(self.graph.nodes()))
        self.logger.info("Links: %s", list(self.graph.edges()))
        self.logger.info("Hosts: %s", self.host_location)
        self.logger.info("IP -> MAC: %s", self.ip_to_mac)
        self.logger.info("Port mappings: %s", self.port_to_link)

        if self.clff is not None:
            self.logger.info("CLFF ready: %s", self.clff.is_ready())
            self.logger.info("CLFF summary: %s", self.clff.summary())

        self.logger.info("=======================================")
