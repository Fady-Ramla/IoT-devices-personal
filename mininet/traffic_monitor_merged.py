# traffic_monitor_merged.py
# =============================================================
# Ryu Traffic Monitor - Merged Network Monitor
#
# Responsibilities:
#   1. PacketIn monitoring
#   2. Packet-level feature extraction
#   3. FlowStats monitoring
#   4. Flow-level feature extraction
#   5. CSV dataset collection
#   6. Normal forwarding
#   7. Host learning for forwarding
#   8. Zero-Trust state enforcement
#   9. Quarantine / Restore
#  10. Security -> Network action execution
#  11. Reroute request delegation to TopologyMonitor
#  12. Controller-based loop-free forwarding
#
# IMPORTANT ARCHITECTURE:
#
# TrafficMonitorMerged DOES NOT:
#   - calculate Trust Score
#   - run AI prediction
#   - calculate Dijkstra
#   - discover switch topology
#   - maintain switch-to-switch links
#   - build NetworkX graph
#   - build/maintain the loop-free spanning tree
#   - install dynamic priority-100 rerouting paths
#
# TopologyMonitor owns:
#   - topology discovery
#   - switch-to-switch links
#   - NetworkX graph
#   - Dijkstra
#   - next-hop calculation
#   - loop-free spanning tree (broadcast/unknown unicast)
#   - dynamic rerouting
#
# Forwarding architecture:
#
#             Physical topology
#                    |
#                    v
#             TopologyMonitor
#                    |
#          +---------+---------+
#          |                   |
#       Dijkstra          Spanning Tree
#          |                   |
#     Known Unicast      Unknown/Broadcast
#          |                   |
#          +---------+---------+
#                    |
#                    v
#           TrafficMonitorMerged
#                    |
#                OpenFlow
#                    |
#                    v
#                   OVS
#
# IMPORTANT:
# The physical 7 switch-to-switch links remain active.
# STP is NOT used by this application.
#
# OFPP_FLOOD is intentionally disabled because the physical
# topology contains cycles. Broadcast/unknown-unicast traffic
# is instead forwarded only along the controller-maintained
# loop-free spanning tree (see TopologyMonitor.
# get_loop_free_output_ports).
#
# OpenFlow version: 1.3
# =============================================================


# =============================================================
# IMPORTS
# =============================================================

import csv
import json
import os
import threading
import time


from ryu.base import app_manager

from ryu.controller import ofp_event
from ryu.controller import handler

from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    DEAD_DISPATCHER
)

from ryu.lib import hub

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from ryu.lib.packet import arp

from ryu.ofproto import ofproto_v1_3

from ryu.app.wsgi import (
    ControllerBase,
    WSGIApplication,
    route
)

from webob import Response


# =============================================================
# ZERO-TRUST POLICY
# =============================================================

from zero_trust.zero_trust_policy import (
    TRUSTED,
    UNTRUSTED,
    QUARANTINED,

    ACTION_ALLOW,
    ACTION_KEEP_UNTRUSTED,
    ACTION_QUARANTINE,
    ACTION_RESTORE,
    ACTION_REROUTE,

    MIN_SCORE,
    MAX_SCORE
)


# =============================================================
# ZERO-TRUST DECISION VALIDATOR
# =============================================================

from zero_trust.zero_trust_decision import ZeroTrustDecision


# =============================================================
# REROUTE EVENT
# =============================================================

from topology_monitor import EventRerouteHost


# =============================================================
# CONSTANTS
# =============================================================

PACKET_CSV = "packet_features.csv"
FLOW_CSV = "traffic_features.csv"

FLOW_POLL_INTERVAL = 2.0

FLOW_IDLE_TIMEOUT = 15
STALE_FLOW_MAX_AGE = 60

CSV_FLUSH_EVERY = 50

NORMAL_PRIORITY = 10
QUARANTINE_PRIORITY = 200
TABLE_MISS_PRIORITY = 0

OPENFLOW_VERSION = "1.3"


# =============================================================
# CONTROLLER-BASED LOOP-FREE FORWARDING
# =============================================================

LOOP_FREE_FORWARDING_ENABLED = True


# =============================================================
# NETWORK TEST
# =============================================================

NETWORK_TEST_ENABLED = False

NETWORK_TEST_HOST = "10.0.0.2"

NETWORK_TEST_REQUEST_ID = "NETWORK-TEST-001"


# =============================================================
# REST CONTROLLER
# =============================================================

class NetworkActionController(ControllerBase):
    """
    REST interface used by the Security / Integration layer.

    Endpoint:
        POST /network/action

    TrafficMonitorMerged does not calculate:
        - Trust Score
        - AI prediction
        - Trust State
        - Severity

    It receives the validated decision and executes
    the corresponding network action.
    """

    def __init__(
        self,
        req,
        link,
        data,
        **config
    ):

        super(
            NetworkActionController,
            self
        ).__init__(
            req,
            link,
            data,
            **config
        )

        self.monitor = data[
            "traffic_monitor"
        ]

    # ---------------------------------------------------------
    # POST /network/action
    # ---------------------------------------------------------

    @route(
        "network_action",
        "/network/action",
        methods=["POST"]
    )
    def network_action(
        self,
        req,
        **kwargs
    ):

        # -----------------------------------------------------
        # Parse JSON
        # -----------------------------------------------------

        try:

            body = req.body.decode(
                "utf-8"
            )

            data = json.loads(
                body
            )

        except Exception as e:

            return Response(
                status=400,
                content_type="application/json",
                body=json.dumps({
                    "success": False,
                    "status": "error",
                    "message": "Invalid JSON",
                    "error": str(e)
                })
            )

        # -----------------------------------------------------
        # Extract decision information
        # -----------------------------------------------------

        host_ip = data.get(
            "host_ip"
        )

        action = data.get(
            "action"
        )

        request_id = data.get(
            "request_id"
        )

        trust_state = data.get(
            "trust_state"
        )

        trust_score = data.get(
            "trust_score"
        )

        reason = data.get(
            "reason"
        )

        # -----------------------------------------------------
        # Required fields
        # -----------------------------------------------------

        if not host_ip:

            return Response(
                status=400,
                content_type="application/json",
                body=json.dumps({
                    "success": False,
                    "status": "error",
                    "message": "host_ip is required"
                })
            )

        if not action:

            return Response(
                status=400,
                content_type="application/json",
                body=json.dumps({
                    "success": False,
                    "status": "error",
                    "message": "action is required"
                })
            )

        # -----------------------------------------------------
        # Execute network action
        # -----------------------------------------------------

        try:

            result = self.monitor.execute_security_action(
                host_ip=host_ip,
                action=action,
                request_id=request_id,
                trust_state=trust_state,
                trust_score=trust_score,
                reason=reason
            )

            status_code = 200

            if not result.get(
                "success",
                False
            ):

                status_code = 400

            return Response(
                status=status_code,
                content_type="application/json",
                body=json.dumps(
                    result
                )
            )

        except Exception as e:

            self.monitor.logger.exception(
                "REST network action failed"
            )

            return Response(
                status=500,
                content_type="application/json",
                body=json.dumps({
                    "success": False,
                    "status": "error",
                    "message": str(e)
                })
            )


# =============================================================
# TRAFFIC MONITOR MERGED
# =============================================================

class TrafficMonitorMerged(
    app_manager.RyuApp
):

    # ---------------------------------------------------------
    # OpenFlow 1.3
    # ---------------------------------------------------------

    OFP_VERSIONS = [
        ofproto_v1_3.OFP_VERSION
    ]

    # ---------------------------------------------------------
    # WSGI
    # ---------------------------------------------------------

    _CONTEXTS = {
        "wsgi": WSGIApplication
    }

    # ---------------------------------------------------------
    # Custom Ryu event
    # ---------------------------------------------------------

    _EVENTS = [
        EventRerouteHost
    ]

    # =========================================================
    # INITIALIZATION
    # =========================================================

    def __init__(
        self,
        *args,
        **kwargs
    ):

        super(
            TrafficMonitorMerged,
            self
        ).__init__(
            *args,
            **kwargs
        )

        # -----------------------------------------------------
        # Datapaths
        # -----------------------------------------------------

        self.datapaths = {}

        # -----------------------------------------------------
        # TopologyMonitor
        #
        # TrafficMonitorMerged does not calculate paths.
        # It delegates all topology/loop-free decisions to
        # TopologyMonitor.
        # -----------------------------------------------------

        self.topology_monitor = None

        # -----------------------------------------------------
        # Host learning
        #
        # MAC -> {
        #     "dpid": switch DPID,
        #     "port": host port
        # }
        # -----------------------------------------------------

        self.hosts = {}

        # -----------------------------------------------------
        # IP <-> MAC
        # -----------------------------------------------------

        self.ip_to_mac = {}

        self.mac_to_ip = {}

        # -----------------------------------------------------
        # Trust information
        # -----------------------------------------------------

        self.trust_state = {}

        self.trust_scores = {}

        # -----------------------------------------------------
        # Decision validator
        # -----------------------------------------------------

        self.decision_validator = (
            ZeroTrustDecision()
        )

        # -----------------------------------------------------
        # Quarantine
        # -----------------------------------------------------

        self.quarantined_hosts = set()

        self.quarantine_rules_installed = {}

        # -----------------------------------------------------
        # Flow monitoring
        # -----------------------------------------------------

        self.flow_baselines = {}

        self.flow_last_seen = {}

        # -----------------------------------------------------
        # Action history
        # -----------------------------------------------------

        self.action_history = {}

        # -----------------------------------------------------
        # Network test
        # -----------------------------------------------------

        self.network_test_done = False

        # -----------------------------------------------------
        # CSV state
        # -----------------------------------------------------

        self.packet_file = None
        self.flow_file = None

        self.packet_writer = None
        self.flow_writer = None

        self.packet_rows_since_flush = 0
        self.flow_rows_since_flush = 0

        self.csv_lock = threading.Lock()

        # -----------------------------------------------------
        # WSGI registration
        # -----------------------------------------------------

        wsgi = kwargs[
            "wsgi"
        ]

        wsgi.register(
            NetworkActionController,
            {
                "traffic_monitor": self
            }
        )

        # -----------------------------------------------------
        # Initialize CSV files
        # -----------------------------------------------------

        self._initialize_csv_files()

        # -----------------------------------------------------
        # Start FlowStats monitoring
        # -----------------------------------------------------

        self.monitor_thread = hub.spawn(
            self._flow_stats_loop
        )

        # -----------------------------------------------------
        # Startup logs
        # -----------------------------------------------------

        self.logger.info(
            "================================================="
        )

        self.logger.info(
            "TrafficMonitorMerged initialized"
        )

        self.logger.info(
            "OpenFlow version: %s",
            OPENFLOW_VERSION
        )

        self.logger.info(
            "Packet CSV: %s",
            PACKET_CSV
        )

        self.logger.info(
            "Flow CSV: %s",
            FLOW_CSV
        )

        self.logger.info(
            "Trust Score owner: AI"
        )

        self.logger.info(
            "Trust decision owner: ZeroTrustEngine"
        )

        self.logger.info(
            "Decision validation: ZeroTrustDecision"
        )

        self.logger.info(
            "Network execution owner: TrafficMonitorMerged"
        )

        self.logger.info(
            "Topology/Dijkstra owner: TopologyMonitor"
        )

        self.logger.info(
            "Reroute: delegated to TopologyMonitor"
        )

        self.logger.info(
            "Loop-free forwarding: delegated to TopologyMonitor"
        )

        self.logger.info(
            "Inter-switch OFPP_FLOOD: DISABLED"
        )

        self.logger.info(
            "STP: DISABLED"
        )

        self.logger.info(
            "================================================="
        )

    # =========================================================
    # TOPOLOGY MONITOR ACCESS
    # =========================================================

    def _get_topology_monitor(
        self
    ):
        """
        Get the running TopologyMonitor Ryu application.

        TrafficMonitorMerged does not create a second topology
        database and does not calculate paths or the spanning
        tree itself.
        """

        if self.topology_monitor is not None:

            return self.topology_monitor

        try:

            # -------------------------------------------------
            # Normal Ryu service-brick name
            # -------------------------------------------------

            self.topology_monitor = (
                app_manager.lookup_service_brick(
                    "topology_monitor"
                )
            )

            # -------------------------------------------------
            # Fallback
            # -------------------------------------------------

            if self.topology_monitor is None:

                self.topology_monitor = (
                    app_manager.lookup_service_brick(
                        "TopologyMonitor"
                    )
                )

            if self.topology_monitor is None:

                self.logger.warning(
                    "TopologyMonitor service is not available yet"
                )

            else:

                self.logger.info(
                    "TopologyMonitor service connected"
                )

        except Exception as e:

            self.logger.exception(
                "Failed to get TopologyMonitor: %s",
                e
            )

            self.topology_monitor = None

        return self.topology_monitor

    # =========================================================
    # LOOP-FREE UNICAST NEXT HOP
    # =========================================================

    def _get_loop_free_output_port(
        self,
        dpid,
        dst_mac
    ):
        """
        Ask TopologyMonitor for the next-hop port.

        Used for known unicast traffic.

        TrafficMonitorMerged does NOT calculate Dijkstra.

        TopologyMonitor owns:
            - physical topology
            - NetworkX graph
            - Dijkstra
            - next-hop calculation
        """

        if not LOOP_FREE_FORWARDING_ENABLED:

            return None

        topology = (
            self._get_topology_monitor()
        )

        if topology is None:

            self.logger.warning(
                "Cannot perform loop-free forwarding: "
                "TopologyMonitor unavailable"
            )

            return None

        try:

            output_port = (
                topology.get_forwarding_port(
                    dpid=dpid,
                    dst_mac=dst_mac
                )
            )

            if output_port is None:

                self.logger.warning(
                    "No path available: "
                    "s%d -> %s",
                    dpid,
                    dst_mac
                )

                return None

            self.logger.debug(
                "Dijkstra forwarding: "
                "s%d -> %s via port %s",
                dpid,
                dst_mac,
                output_port
            )

            return output_port

        except AttributeError:

            self.logger.error(
                "TopologyMonitor does not provide "
                "get_forwarding_port(dpid, dst_mac)"
            )

            return None

        except Exception as e:

            self.logger.exception(
                "TopologyMonitor forwarding request failed: "
                "s%d -> %s : %s",
                dpid,
                dst_mac,
                e
            )

            return None

    # =========================================================
    # LOOP-FREE TREE FORWARDING (BROADCAST / UNKNOWN UNICAST)
    # =========================================================

    def _forward_on_loop_free_tree(
        self,
        datapath,
        msg,
        in_port
    ):
        """
        Forward unknown/broadcast traffic using the
        controller-built loop-free spanning tree.

        IMPORTANT:
            OFPP_FLOOD is NEVER used.

        TopologyMonitor decides which ports are safe
        (tree ports + host ports on this switch, minus the
        ingress port). TrafficMonitorMerged only builds the
        OpenFlow PacketOut/actions from that port list.

        Returns:
            True  -> forwarding was performed
            False -> forwarding could not be performed
        """

        if not LOOP_FREE_FORWARDING_ENABLED:

            return False

        topology = (
            self._get_topology_monitor()
        )

        if topology is None:

            self.logger.warning(
                "Cannot use loop-free tree: "
                "TopologyMonitor unavailable"
            )

            return False

        try:

            # -------------------------------------------------
            # Ask TopologyMonitor for safe output ports.
            # -------------------------------------------------

            output_ports = (
                topology.get_loop_free_output_ports(
                    dpid=datapath.id,
                    in_port=in_port
                )
            )

            if not output_ports:

                self.logger.debug(
                    "No loop-free tree output ports on s%d",
                    datapath.id
                )

                return False

            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            actions = []

            for port in output_ports:

                # ---------------------------------------------
                # Never send back through ingress port.
                # (TopologyMonitor already excludes it, this
                # is a defensive second check.)
                # ---------------------------------------------

                if port == in_port:

                    continue

                actions.append(
                    parser.OFPActionOutput(
                        port
                    )
                )

            if not actions:

                return False

            # -------------------------------------------------
            # Packet data.
            # -------------------------------------------------

            data = None

            if msg.buffer_id == ofproto.OFP_NO_BUFFER:

                data = msg.data

            # -------------------------------------------------
            # PacketOut.
            # -------------------------------------------------

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data
            )

            datapath.send_msg(
                out
            )

            self.logger.debug(
                "Loop-free tree forwarding: "
                "s%d in_port=%s output_ports=%s",
                datapath.id,
                in_port,
                output_ports
            )

            return True

        except AttributeError:

            self.logger.error(
                "TopologyMonitor does not provide "
                "get_loop_free_output_ports()"
            )

            return False

        except Exception as e:

            self.logger.exception(
                "Loop-free tree forwarding failed on s%d: %s",
                datapath.id,
                e
            )

            return False

    # =========================================================
    # CSV INITIALIZATION
    # =========================================================

    def _initialize_csv_files(
        self
    ):

        packet_exists = os.path.exists(
            PACKET_CSV
        )

        flow_exists = os.path.exists(
            FLOW_CSV
        )

        self.packet_file = open(
            PACKET_CSV,
            "a",
            newline=""
        )

        self.flow_file = open(
            FLOW_CSV,
            "a",
            newline=""
        )

        self.packet_writer = csv.writer(
            self.packet_file
        )

        self.flow_writer = csv.writer(
            self.flow_file
        )

        # -----------------------------------------------------
        # Packet feature schema
        # -----------------------------------------------------

        if (
            not packet_exists
            or os.path.getsize(PACKET_CSV) == 0
        ):

            self.packet_writer.writerow([
                "timestamp",
                "switch_dpid",
                "in_port",
                "src_mac",
                "dst_mac",
                "src_ip",
                "dst_ip",
                "protocol",
                "src_port",
                "dst_port",
                "packet_length",
                "tcp_flags",
                "icmp_type",
                "arp_operation"
            ])

            self.packet_file.flush()

        # -----------------------------------------------------
        # Flow feature schema
        # -----------------------------------------------------

        if (
            not flow_exists
            or os.path.getsize(FLOW_CSV) == 0
        ):

            self.flow_writer.writerow([
                "timestamp",
                "switch_dpid",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "protocol",
                "priority",
                "packet_count",
                "byte_count",
                "packet_rate",
                "byte_rate",
                "duration_sec"
            ])

            self.flow_file.flush()

    # =========================================================
    # SWITCH FEATURES
    # =========================================================

    @handler.set_ev_cls(
        ofp_event.EventOFPSwitchFeatures,
        CONFIG_DISPATCHER
    )
    def switch_features_handler(
        self,
        ev
    ):

        datapath = ev.msg.datapath

        self.datapaths[
            datapath.id
        ] = datapath

        self.logger.info(
            "Switch connected: s%d",
            datapath.id
        )

        self._install_table_miss(
            datapath
        )

        # -----------------------------------------------------
        # Reinstall quarantine rules after reconnect.
        # -----------------------------------------------------

        for host_ip in list(
            self.quarantined_hosts
        ):

            self._install_drop_rule(
                datapath,
                host_ip
            )

    # =========================================================
    # DATAPATH STATE CHANGE
    # =========================================================

    @handler.set_ev_cls(
        ofp_event.EventOFPStateChange,
        [MAIN_DISPATCHER, DEAD_DISPATCHER]
    )
    def state_change_handler(
        self,
        ev
    ):

        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:

            self.datapaths[
                datapath.id
            ] = datapath

            self.logger.info(
                "Datapath registered: s%d",
                datapath.id
            )

        elif ev.state == DEAD_DISPATCHER:

            if datapath.id in self.datapaths:

                del self.datapaths[
                    datapath.id
                ]

            self.logger.info(
                "Datapath removed: s%d",
                datapath.id
            )

            for host_ip in list(
                self.quarantine_rules_installed
            ):

                switches = (
                    self.quarantine_rules_installed[
                        host_ip
                    ]
                )

                switches.discard(
                    datapath.id
                )

    # =========================================================
    # TABLE MISS
    # =========================================================

    def _install_table_miss(
        self,
        datapath
    ):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=TABLE_MISS_PRIORITY,
            match=match,
            instructions=instructions
        )

        datapath.send_msg(
            mod
        )

        self.logger.info(
            "Table-miss rule installed on s%d",
            datapath.id
        )

    # =========================================================
    # GENERIC FLOW ADD
    # =========================================================

    def _add_flow(
        self,
        datapath,
        priority,
        match,
        actions
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
            instructions=instructions
        )

        datapath.send_msg(
            mod
        )

    # =========================================================
    # PACKET IN
    # =========================================================

    @handler.set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER
    )
    def packet_in_handler(
        self,
        ev
    ):

        msg = ev.msg

        datapath = msg.datapath

        dpid = datapath.id

        in_port = msg.match.get(
            "in_port"
        )

        # -----------------------------------------------------
        # Defensive check: without a valid in_port we cannot
        # safely learn the host or forward the packet.
        # -----------------------------------------------------

        if in_port is None:

            return

        pkt = packet.Packet(
            msg.data
        )

        eth_pkt = pkt.get_protocol(
            ethernet.ethernet
        )

        if eth_pkt is None:

            return

        # -----------------------------------------------------
        # Ignore LLDP.
        # -----------------------------------------------------

        if eth_pkt.ethertype == 0x88CC:

            return

        src_mac = eth_pkt.src
        dst_mac = eth_pkt.dst

        # -----------------------------------------------------
        # Learn source for normal forwarding.
        #
        # TopologyMonitor independently maintains its own
        # host-location database for topology/rerouting.
        #
        # This local table is used by TrafficMonitorMerged
        # to decide the immediate forwarding behavior.
        # -----------------------------------------------------

        self.hosts[
            src_mac
        ] = {
            "dpid": dpid,
            "port": in_port
        }

        # -----------------------------------------------------
        # Extract IP information.
        # -----------------------------------------------------

        src_ip = ""
        dst_ip = ""
        protocol = ""
        src_port = ""
        dst_port = ""

        tcp_flags = ""
        icmp_type = ""
        arp_operation = ""

        # -----------------------------------------------------
        # IPv4
        # -----------------------------------------------------

        ipv4_pkt = pkt.get_protocol(
            ipv4.ipv4
        )

        if ipv4_pkt is not None:

            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst

            protocol = ipv4_pkt.proto

            self.ip_to_mac[
                src_ip
            ] = src_mac

            self.mac_to_ip[
                src_mac
            ] = src_ip

            # -------------------------------------------------
            # TCP
            # -------------------------------------------------

            tcp_pkt = pkt.get_protocol(
                tcp.tcp
            )

            if tcp_pkt is not None:

                src_port = tcp_pkt.src_port
                dst_port = tcp_pkt.dst_port

                tcp_flags = tcp_pkt.bits

            # -------------------------------------------------
            # UDP
            # -------------------------------------------------

            udp_pkt = pkt.get_protocol(
                udp.udp
            )

            if udp_pkt is not None:

                src_port = udp_pkt.src_port
                dst_port = udp_pkt.dst_port

            # -------------------------------------------------
            # ICMP
            # -------------------------------------------------

            icmp_pkt = pkt.get_protocol(
                icmp.icmp
            )

            if icmp_pkt is not None:

                icmp_type = icmp_pkt.type

        # -----------------------------------------------------
        # IPv6
        # -----------------------------------------------------

        ipv6_pkt = pkt.get_protocol(
            ipv6.ipv6
        )

        if ipv6_pkt is not None:

            src_ip = ipv6_pkt.src
            dst_ip = ipv6_pkt.dst

            protocol = ipv6_pkt.nxt

        # -----------------------------------------------------
        # ARP
        # -----------------------------------------------------

        arp_pkt = pkt.get_protocol(
            arp.arp
        )

        if arp_pkt is not None:

            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

            arp_operation = arp_pkt.opcode

            self.ip_to_mac[
                src_ip
            ] = src_mac

            self.mac_to_ip[
                src_mac
            ] = src_ip

        # -----------------------------------------------------
        # Packet length
        # -----------------------------------------------------

        packet_length = len(
            msg.data
        )

        # -----------------------------------------------------
        # Save packet feature
        # -----------------------------------------------------

        self._write_packet_feature([
            time.time(),
            dpid,
            in_port,
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            packet_length,
            tcp_flags,
            icmp_type,
            arp_operation
        ])

        # -----------------------------------------------------
        # New hosts start as UNTRUSTED.
        # -----------------------------------------------------

        if src_ip:

            if src_ip not in self.trust_state:

                self.trust_state[
                    src_ip
                ] = UNTRUSTED

        # -----------------------------------------------------
        # Quarantined source.
        # -----------------------------------------------------

        if (
            src_ip
            and src_ip in self.quarantined_hosts
        ):

            self.logger.warning(
                "Packet blocked from quarantined host: %s",
                src_ip
            )

            return

        # -----------------------------------------------------
        # Normal forwarding.
        # -----------------------------------------------------

        self._forward_packet(
            datapath,
            msg,
            in_port,
            dst_mac
        )

    # =========================================================
    # NORMAL FORWARDING
    # =========================================================

    def _forward_packet(
        self,
        datapath,
        msg,
        in_port,
        dst_mac
    ):
        """
        Controller-based forwarding.

        Forwarding decision hierarchy:

            1. Broadcast / multicast
                    ->
                Loop-Free Spanning Tree

            2. Known destination on same switch
                    ->
                Direct host port

            3. Known destination on another switch
                    ->
                TopologyMonitor
                    ->
                Dijkstra
                    ->
                Next-hop port

            4. Unknown unicast
                    ->
                Loop-Free Spanning Tree

        OFPP_FLOOD is NEVER used.
        """

        dpid = datapath.id

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # =====================================================
        # BROADCAST
        # =====================================================

        is_broadcast = (
            dst_mac.lower()
            == "ff:ff:ff:ff:ff:ff"
        )

        # =====================================================
        # MULTICAST
        # =====================================================

        is_multicast = (
            dst_mac.lower().startswith(
                "01:00:5e:"
            )
            or
            dst_mac.lower().startswith(
                "33:33:"
            )
        )

        # =====================================================
        # BROADCAST / MULTICAST
        # =====================================================

        if (
            is_broadcast
            or is_multicast
        ):

            self.logger.debug(
                "Broadcast/multicast on s%d "
                "-> loop-free spanning tree",
                dpid
            )

            success = (
                self._forward_on_loop_free_tree(
                    datapath,
                    msg,
                    in_port
                )
            )

            if not success:

                self.logger.warning(
                    "Loop-free tree forwarding failed "
                    "for broadcast/multicast on s%d",
                    dpid
                )

            return

        # =====================================================
        # DESTINATION KNOWN
        # =====================================================

        if dst_mac in self.hosts:

            dst_info = self.hosts[
                dst_mac
            ]

            dst_dpid = dst_info[
                "dpid"
            ]

            dst_port = dst_info[
                "port"
            ]

            # -------------------------------------------------
            # SAME SWITCH
            # -------------------------------------------------

            if dst_dpid == dpid:

                output_port = dst_port

                self.logger.debug(
                    "Local forwarding: "
                    "s%d -> port %s -> %s",
                    dpid,
                    output_port,
                    dst_mac
                )

            # -------------------------------------------------
            # DIFFERENT SWITCH
            # -------------------------------------------------

            else:

                self.logger.debug(
                    "Remote forwarding request: "
                    "s%d -> s%d -> %s",
                    dpid,
                    dst_dpid,
                    dst_mac
                )

                # ---------------------------------------------
                # IMPORTANT:
                #
                # TrafficMonitorMerged does NOT calculate
                # Dijkstra.
                #
                # It asks TopologyMonitor for the next-hop.
                # ---------------------------------------------

                output_port = (
                    self._get_loop_free_output_port(
                        dpid=dpid,
                        dst_mac=dst_mac
                    )
                )

                if output_port is None:

                    self.logger.warning(
                        "No Dijkstra path available: "
                        "s%d -> s%d -> %s",
                        dpid,
                        dst_dpid,
                        dst_mac
                    )

                    return

            # -------------------------------------------------
            # Install normal forwarding rule.
            # -------------------------------------------------

            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=dst_mac
            )

            actions = [
                parser.OFPActionOutput(
                    output_port
                )
            ]

            self._add_flow(
                datapath,
                NORMAL_PRIORITY,
                match,
                actions
            )

            # -------------------------------------------------
            # Send current packet.
            # -------------------------------------------------

            data = None

            if msg.buffer_id == ofproto.OFP_NO_BUFFER:

                data = msg.data

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data
            )

            datapath.send_msg(
                out
            )

            return

        # =====================================================
        # UNKNOWN UNICAST
        # =====================================================

        self.logger.debug(
            "Unknown destination %s on s%d "
            "-> loop-free spanning tree",
            dst_mac,
            dpid
        )

        success = (
            self._forward_on_loop_free_tree(
                datapath,
                msg,
                in_port
            )
        )

        if not success:

            self.logger.warning(
                "Unknown destination forwarding failed "
                "on s%d for %s",
                dpid,
                dst_mac
            )

    # =========================================================
    # FLOW STATS LOOP
    # =========================================================

    def _flow_stats_loop(
        self
    ):

        while True:

            try:

                for datapath in list(
                    self.datapaths.values()
                ):

                    self._request_flow_stats(
                        datapath
                    )

                self._cleanup_stale_flows()

            except Exception as e:

                self.logger.exception(
                    "FlowStats loop error: %s",
                    e
                )

            hub.sleep(
                FLOW_POLL_INTERVAL
            )

    # =========================================================
    # REQUEST FLOW STATS
    # =========================================================

    def _request_flow_stats(
        self,
        datapath
    ):

        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(
            datapath
        )

        datapath.send_msg(
            req
        )

    # =========================================================
    # FLOW STATS REPLY
    # =========================================================

    @handler.set_ev_cls(
        ofp_event.EventOFPFlowStatsReply,
        MAIN_DISPATCHER
    )
    def flow_stats_reply_handler(
        self,
        ev
    ):

        datapath = ev.msg.datapath

        dpid = datapath.id

        now = time.time()

        for stat in ev.msg.body:

            # -------------------------------------------------
            # Ignore table-miss.
            # -------------------------------------------------

            if stat.priority == TABLE_MISS_PRIORITY:

                continue

            match = stat.match

            # -------------------------------------------------
            # IPv4 flow fields.
            # -------------------------------------------------

            src_ip = match.get(
                "ipv4_src",
                ""
            )

            dst_ip = match.get(
                "ipv4_dst",
                ""
            )

            protocol = match.get(
                "ip_proto",
                ""
            )

            src_port = ""
            dst_port = ""

            # -------------------------------------------------
            # TCP
            # -------------------------------------------------

            if protocol == 6:

                src_port = match.get(
                    "tcp_src",
                    ""
                )

                dst_port = match.get(
                    "tcp_dst",
                    ""
                )

            # -------------------------------------------------
            # UDP
            # -------------------------------------------------

            elif protocol == 17:

                src_port = match.get(
                    "udp_src",
                    ""
                )

                dst_port = match.get(
                    "udp_dst",
                    ""
                )

            # -------------------------------------------------
            # Ignore non-IPv4 flows.
            # -------------------------------------------------

            if not src_ip and not dst_ip:

                continue

            packet_count = stat.packet_count

            byte_count = stat.byte_count

            duration_sec = (
                stat.duration_sec
                + (
                    stat.duration_nsec
                    / 1_000_000_000.0
                )
            )

            # -------------------------------------------------
            # Unique flow key.
            # -------------------------------------------------

            flow_key = (
                dpid,
                stat.priority,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol
            )

            # -------------------------------------------------
            # First observation = baseline.
            # -------------------------------------------------

            if flow_key not in self.flow_baselines:

                self.flow_baselines[
                    flow_key
                ] = {
                    "timestamp": now,
                    "packet_count": packet_count,
                    "byte_count": byte_count
                }

                self.flow_last_seen[
                    flow_key
                ] = now

                continue

            # -------------------------------------------------
            # Previous counters.
            # -------------------------------------------------

            previous = self.flow_baselines[
                flow_key
            ]

            previous_packets = previous[
                "packet_count"
            ]

            previous_bytes = previous[
                "byte_count"
            ]

            previous_time = previous[
                "timestamp"
            ]

            # -------------------------------------------------
            # Counter deltas.
            # -------------------------------------------------

            packet_delta = (
                packet_count
                - previous_packets
            )

            byte_delta = (
                byte_count
                - previous_bytes
            )

            time_delta = (
                now
                - previous_time
            )

            # -------------------------------------------------
            # Protect against counter reset.
            # -------------------------------------------------

            if packet_delta < 0:

                packet_delta = packet_count

            if byte_delta < 0:

                byte_delta = byte_count

            # -------------------------------------------------
            # Interval rates.
            # -------------------------------------------------

            if time_delta > 0:

                packet_rate = (
                    packet_delta
                    / time_delta
                )

                byte_rate = (
                    byte_delta
                    / time_delta
                )

            else:

                packet_rate = 0.0
                byte_rate = 0.0

            # -------------------------------------------------
            # Update baseline.
            # -------------------------------------------------

            self.flow_baselines[
                flow_key
            ] = {
                "timestamp": now,
                "packet_count": packet_count,
                "byte_count": byte_count
            }

            self.flow_last_seen[
                flow_key
            ] = now

            # -------------------------------------------------
            # Write feature row.
            # -------------------------------------------------

            self._write_flow_feature([
                now,
                dpid,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
                stat.priority,
                packet_count,
                byte_count,
                packet_rate,
                byte_rate,
                duration_sec
            ])

    # =========================================================
    # WRITE PACKET FEATURE
    # =========================================================

    def _write_packet_feature(
        self,
        row
    ):

        with self.csv_lock:

            self.packet_writer.writerow(
                row
            )

            self.packet_rows_since_flush += 1

            if (
                self.packet_rows_since_flush
                >= CSV_FLUSH_EVERY
            ):

                self.packet_file.flush()

                self.packet_rows_since_flush = 0

    # =========================================================
    # WRITE FLOW FEATURE
    # =========================================================

    def _write_flow_feature(
        self,
        row
    ):

        with self.csv_lock:

            self.flow_writer.writerow(
                row
            )

            self.flow_rows_since_flush += 1

            if (
                self.flow_rows_since_flush
                >= CSV_FLUSH_EVERY
            ):

                self.flow_file.flush()

                self.flow_rows_since_flush = 0

    # =========================================================
    # CLEANUP STALE FLOWS
    # =========================================================

    def _cleanup_stale_flows(
        self
    ):

        now = time.time()

        stale_keys = []

        for flow_key, last_seen in list(
            self.flow_last_seen.items()
        ):

            if (
                now - last_seen
                > STALE_FLOW_MAX_AGE
            ):

                stale_keys.append(
                    flow_key
                )

        for flow_key in stale_keys:

            self.flow_last_seen.pop(
                flow_key,
                None
            )

            self.flow_baselines.pop(
                flow_key,
                None
            )

    # =========================================================
    # VALIDATE NETWORK DECISION
    # =========================================================

    def _validate_network_decision(
        self,
        host_ip,
        action,
        trust_state=None,
        trust_score=None,
        reason=None
    ):

        # -----------------------------------------------------
        # Validate action.
        # -----------------------------------------------------

        valid_actions = {
            ACTION_ALLOW,
            ACTION_KEEP_UNTRUSTED,
            ACTION_QUARANTINE,
            ACTION_RESTORE,
            ACTION_REROUTE
        }

        if action not in valid_actions:

            return {
                "valid": False,
                "message": (
                    "Invalid action: %s"
                    % action
                )
            }

        # -----------------------------------------------------
        # Validate trust state.
        # -----------------------------------------------------

        valid_states = {
            TRUSTED,
            UNTRUSTED,
            QUARANTINED
        }

        if (
            trust_state is not None
            and trust_state not in valid_states
        ):

            return {
                "valid": False,
                "message": (
                    "Invalid trust state: %s"
                    % trust_state
                )
            }

        # -----------------------------------------------------
        # Validate trust score.
        # -----------------------------------------------------

        if trust_score is not None:

            try:

                trust_score = float(
                    trust_score
                )

            except (
                TypeError,
                ValueError
            ):

                return {
                    "valid": False,
                    "message": "Invalid trust score"
                }

            if not (
                MIN_SCORE
                <= trust_score
                <= MAX_SCORE
            ):

                return {
                    "valid": False,
                    "message": (
                        "Trust score must be between "
                        "%s and %s"
                        % (
                            MIN_SCORE,
                            MAX_SCORE
                        )
                    )
                }

        # -----------------------------------------------------
        # Validate state/action relationship.
        # -----------------------------------------------------

        if trust_state is not None:

            if not self.decision_validator.is_action_allowed(
                trust_state,
                action
            ):

                return {
                    "valid": False,
                    "message": (
                        "Action %s is not allowed "
                        "for trust state %s"
                        % (
                            action,
                            trust_state
                        )
                    )
                }

        return {
            "valid": True,
            "host_ip": host_ip,
            "action": action,
            "trust_state": trust_state,
            "trust_score": trust_score,
            "reason": reason
        }

    # =========================================================
    # INSTALL DROP RULE
    # =========================================================

    def _install_drop_rule(
        self,
        datapath,
        host_ip
    ):

        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=host_ip
        )

        # -----------------------------------------------------
        # Empty actions = DROP.
        # -----------------------------------------------------

        actions = []

        self._add_flow(
            datapath,
            QUARANTINE_PRIORITY,
            match,
            actions
        )

        # -----------------------------------------------------
        # Track installed quarantine rules.
        # -----------------------------------------------------

        if host_ip not in (
            self.quarantine_rules_installed
        ):

            self.quarantine_rules_installed[
                host_ip
            ] = set()

        self.quarantine_rules_installed[
            host_ip
        ].add(
            datapath.id
        )

        self.logger.warning(
            "QUARANTINE rule installed on s%d for %s",
            datapath.id,
            host_ip
        )

    # =========================================================
    # QUARANTINE HOST
    # =========================================================

    def quarantine_host(
        self,
        host_ip,
        request_id=None,
        reason=None
    ):

        self.quarantined_hosts.add(
            host_ip
        )

        self.trust_state[
            host_ip
        ] = QUARANTINED

        # -----------------------------------------------------
        # Install DROP on every connected switch.
        # -----------------------------------------------------

        for datapath in list(
            self.datapaths.values()
        ):

            self._install_drop_rule(
                datapath,
                host_ip
            )

        self._record_action(
            request_id=request_id,
            host_ip=host_ip,
            action=ACTION_QUARANTINE,
            status="executed",
            reason=reason
        )

        self.logger.warning(
            "Host quarantined: %s",
            host_ip
        )

        return True

    # =========================================================
    # DELETE QUARANTINE RULES
    # =========================================================

    def _delete_quarantine_rules(
        self,
        datapath,
        host_ip
    ):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=host_ip
        )

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=QUARANTINE_PRIORITY,
            match=match
        )

        datapath.send_msg(
            mod
        )

    # =========================================================
    # RESTORE HOST
    # =========================================================

    def restore_host(
        self,
        host_ip,
        request_id=None,
        reason=None
    ):

        self.quarantined_hosts.discard(
            host_ip
        )

        self.trust_state[
            host_ip
        ] = TRUSTED

        # -----------------------------------------------------
        # Delete quarantine rules.
        # -----------------------------------------------------

        for datapath in list(
            self.datapaths.values()
        ):

            self._delete_quarantine_rules(
                datapath,
                host_ip
            )

        # -----------------------------------------------------
        # Clean rule tracking.
        # -----------------------------------------------------

        self.quarantine_rules_installed.pop(
            host_ip,
            None
        )

        self._record_action(
            request_id=request_id,
            host_ip=host_ip,
            action=ACTION_RESTORE,
            status="executed",
            reason=reason
        )

        self.logger.info(
            "Host restored: %s",
            host_ip
        )

        return True

    # =========================================================
    # UPDATE TRUST STATE
    # =========================================================

    def update_trust_state(
        self,
        host_ip,
        state,
        trust_score=None
    ):

        valid_states = {
            TRUSTED,
            UNTRUSTED,
            QUARANTINED
        }

        if state not in valid_states:

            return {
                "success": False,
                "message": (
                    "Invalid trust state: %s"
                    % state
                )
            }

        self.trust_state[
            host_ip
        ] = state

        if trust_score is not None:

            self.trust_scores[
                host_ip
            ] = trust_score

        # -----------------------------------------------------
        # Synchronize quarantine set.
        # -----------------------------------------------------

        if state == QUARANTINED:

            self.quarantined_hosts.add(
                host_ip
            )

        else:

            self.quarantined_hosts.discard(
                host_ip
            )

        return {
            "success": True,
            "host_ip": host_ip,
            "trust_state": state,
            "trust_score": trust_score
        }

    # =========================================================
    # EXECUTE SECURITY ACTION
    # =========================================================

    def execute_security_action(
        self,
        host_ip,
        action,
        request_id=None,
        trust_state=None,
        trust_score=None,
        reason=None
    ):

        # -----------------------------------------------------
        # Normalize action.
        # -----------------------------------------------------

        action = str(
            action
        ).upper()

        # -----------------------------------------------------
        # Validate decision.
        # -----------------------------------------------------

        validation = self._validate_network_decision(
            host_ip=host_ip,
            action=action,
            trust_state=trust_state,
            trust_score=trust_score,
            reason=reason
        )

        if not validation["valid"]:

            self.logger.warning(
                "Security decision rejected: %s",
                validation["message"]
            )

            return {
                "success": False,
                "status": "rejected",
                "message": validation["message"],
                "host_ip": host_ip,
                "action": action
            }

        # -----------------------------------------------------
        # Store Trust Score.
        # -----------------------------------------------------

        if trust_score is not None:

            self.trust_scores[
                host_ip
            ] = trust_score

        # -----------------------------------------------------
        # Store Trust State.
        # -----------------------------------------------------

        if trust_state is not None:

            state_result = self.update_trust_state(
                host_ip,
                trust_state,
                trust_score
            )

            if not state_result[
                "success"
            ]:

                return state_result

        # =====================================================
        # KEEP UNTRUSTED
        # =====================================================

        if action == ACTION_KEEP_UNTRUSTED:

            if host_ip not in self.trust_state:

                self.trust_state[
                    host_ip
                ] = UNTRUSTED

            self._record_action(
                request_id=request_id,
                host_ip=host_ip,
                action=action,
                status="executed",
                reason=reason
            )

            return {
                "success": True,
                "status": "executed",
                "action": action,
                "host_ip": host_ip
            }

        # =====================================================
        # ALLOW
        # =====================================================

        if action == ACTION_ALLOW:

            if trust_state is not None:

                self.trust_state[
                    host_ip
                ] = trust_state

            else:

                self.trust_state[
                    host_ip
                ] = TRUSTED

            self._record_action(
                request_id=request_id,
                host_ip=host_ip,
                action=action,
                status="executed",
                reason=reason
            )

            return {
                "success": True,
                "status": "executed",
                "action": action,
                "host_ip": host_ip
            }

        # =====================================================
        # QUARANTINE
        # =====================================================

        if action == ACTION_QUARANTINE:

            success = self.quarantine_host(
                host_ip=host_ip,
                request_id=request_id,
                reason=reason
            )

            return {
                "success": success,
                "status": (
                    "executed"
                    if success
                    else "failed"
                ),
                "action": action,
                "host_ip": host_ip
            }

        # =====================================================
        # RESTORE
        # =====================================================

        if action == ACTION_RESTORE:

            success = self.restore_host(
                host_ip=host_ip,
                request_id=request_id,
                reason=reason
            )

            return {
                "success": success,
                "status": (
                    "executed"
                    if success
                    else "failed"
                ),
                "action": action,
                "host_ip": host_ip
            }

        # =====================================================
        # REROUTE
        # =====================================================

        if action == ACTION_REROUTE:

            success = self.reroute_host(
                host_ip=host_ip,
                request_id=request_id,
                reason=reason
            )

            status = (
                "requested"
                if success
                else "failed"
            )

            self._record_action(
                request_id=request_id,
                host_ip=host_ip,
                action=action,
                status=status,
                reason=reason
            )

            return {
                "success": success,
                "status": status,
                "action": action,
                "host_ip": host_ip,
                "request_id": request_id
            }

        # -----------------------------------------------------
        # Should never reach here.
        # -----------------------------------------------------

        return {
            "success": False,
            "status": "failed",
            "message": "Unhandled action"
        }

    # =========================================================
    # REROUTE REQUEST
    # =========================================================

    def reroute_host(
        self,
        host_ip,
        request_id=None,
        reason=None
    ):
        """
        Delegate rerouting to TopologyMonitor.

        TrafficMonitorMerged does not perform:
            - topology discovery
            - NetworkX graph construction
            - Dijkstra
            - priority-100 path calculation
        """

        self.logger.info(
            "REROUTE request received: "
            "host=%s request_id=%s reason=%s",
            host_ip,
            request_id,
            reason
        )

        try:

            reroute_event = EventRerouteHost(
                host_ip=host_ip,
                request_id=request_id
            )

            self.send_event_to_observers(
                reroute_event
            )

            self.logger.info(
                "REROUTE request delegated to TopologyMonitor: "
                "host=%s request_id=%s",
                host_ip,
                request_id
            )

            return True

        except Exception as e:

            self.logger.exception(
                "Failed to delegate REROUTE request: %s",
                e
            )

            return False

    # =========================================================
    # RECORD ACTION
    # =========================================================

    def _record_action(
        self,
        request_id,
        host_ip,
        action,
        status,
        reason=None
    ):

        if request_id is None:

            request_id = (
                "AUTO-%d"
                % int(time.time() * 1000)
            )

        self.action_history[
            request_id
        ] = {
            "request_id": request_id,
            "host_ip": host_ip,
            "action": action,
            "status": status,
            "reason": reason,
            "timestamp": time.time()
        }

    # =========================================================
    # PUBLIC HELPERS
    # =========================================================

    def get_switches(self):

        return list(
            self.datapaths.keys()
        )

    # ---------------------------------------------------------

    def get_hosts(self):

        return self.hosts.copy()

    # ---------------------------------------------------------

    def get_action(
        self,
        request_id
    ):

        return self.action_history.get(
            request_id
        )

    # =========================================================
    # CLOSE
    # =========================================================

    def close(self):

        try:

            self.packet_file.flush()
            self.flow_file.flush()

        except Exception:

            pass

        try:

            self.packet_file.close()
            self.flow_file.close()

        except Exception:

            pass

        self.logger.info(
            "TrafficMonitorMerged closed"
        )

        super(
            TrafficMonitorMerged,
            self
        ).close()
