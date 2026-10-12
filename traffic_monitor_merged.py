#!/usr/bin/env python3

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
#   6. Zero-Trust state enforcement
#   7. Explicit Security device block / unblock delegation
#   8. Security -> Network action execution
#   9. Reroute request delegation to TopologyMonitor
#
# IMPORTANT ARCHITECTURE:
#
#   TopologyMonitor OWNS ALL FORWARDING:
#       - LLDP
#       - topology discovery
#       - host learning
#       - ARP handling
#       - ARP flooding
#       - known unicast forwarding
#       - unknown unicast forwarding
#       - broadcast / multicast forwarding
#       - CLFF
#       - PathEngine integration (path decisions are owned by PathEngine)
#       - rerouting
#
#   TrafficMonitorMerged OWNS:
#       - packet observation
#       - packet feature extraction
#       - flow statistics
#       - CSV dataset collection
#       - Zero-Trust state
#       - Security device block / unblock requests (delegated)
#       - Security -> Network actions
#       - reroute delegation
#
# IMPORTANT:
#
#   TrafficMonitorMerged MUST NOT send PacketOut for normal
#   network forwarding.
#
#   TrafficMonitorMerged MUST NOT install normal forwarding
#   flows.
#
#   TrafficMonitorMerged MUST NOT install CLFF forwarding
#   flows.
#
#   This prevents duplicate forwarding because both Ryu apps
#   receive the same PacketIn event.
#
# =============================================================


import csv
import json
import ipaddress
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

    ACTION_ALLOW,
    ACTION_KEEP_UNTRUSTED,
    ACTION_BLOCK_DEVICE,
    ACTION_UNBLOCK_DEVICE,
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

# -------------------------------------------------------------
# These priorities are kept for compatibility with the
# existing Zero-Trust implementation.
#
# TrafficMonitorMerged does NOT use NORMAL_PRIORITY for
# forwarding anymore.
#
# TrafficMonitorMerged does NOT install CLFF_PRIORITY rules.
# -------------------------------------------------------------

NORMAL_PRIORITY = 10
CLFF_PRIORITY = 20
TABLE_MISS_PRIORITY = 0

OPENFLOW_VERSION = "1.3"


# =============================================================
# LOOP-FREE FORWARDING
#
# Kept only for compatibility with existing code/status.
#
# Actual forwarding belongs to TopologyMonitor.
# =============================================================

LOOP_FREE_FORWARDING_ENABLED = True


# =============================================================
# CLFF CONFIGURATION
#
# CLFF is owned by TopologyMonitor.
# =============================================================

CLFF_ENABLED = True

CLFF_BROADCAST_STATE_TIMEOUT = 5.0


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
                charset="utf-8",
                body=json.dumps({
                    "success": False,
                    "status": "error",
                    "message": "Invalid JSON",
                    "error": str(e)
                }).encode("utf-8")
            )

        host_ip = data.get("ip") or data.get("host_ip")
        mac = data.get("mac")

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

        if not action:

            return Response(
                status=400,
                content_type="application/json",
                charset="utf-8",
                body=json.dumps({
                    "success": False,
                    "status": "error",
                    "message": "action is required"
                }).encode("utf-8")
            )

        try:

            action = str(action).strip().upper()
            if action in (ACTION_BLOCK_DEVICE, ACTION_UNBLOCK_DEVICE):
                if not mac:
                    return Response(
                        status=400, content_type="application/json",
                        charset="utf-8",
                        body=json.dumps({
                            "success": False, "status": "error",
                            "message": "mac is required for device block actions"
                        }).encode("utf-8"))
            elif not host_ip:
                return Response(
                    status=400, content_type="application/json",
                    charset="utf-8",
                    body=json.dumps({
                        "success": False, "status": "error",
                        "message": "ip (or host_ip) is required for this action"
                    }).encode("utf-8"))

            result = self.monitor.execute_security_action(
                host_ip=host_ip,
                mac=mac,
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
                charset="utf-8",
                body=json.dumps(
                    result
                ).encode("utf-8")
            )

        except Exception as e:

            self.monitor.logger.exception(
                "REST network action failed"
            )

            return Response(
                status=500,
                content_type="application/json",
                charset="utf-8",
                body=json.dumps({
                    "success": False,
                    "status": "error",
                    "message": str(e)
                }).encode("utf-8")
            )

    def _link_action(self, req, action):
        try:
            data = json.loads(req.body.decode("utf-8"))
            src_dpid = int(data["src_dpid"])
            dst_dpid = int(data["dst_dpid"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return Response(
                status=400,
                content_type="application/json",
                charset="utf-8",
                body=json.dumps({
                    "success": False,
                    "status": "error",
                    "message": "src_dpid and dst_dpid are required",
                    "details": str(exc)
                }).encode("utf-8")
            )

        topology = self.monitor._get_topology_monitor()
        if topology is None:
            return Response(
                status=503,
                content_type="application/json",
                charset="utf-8",
                body=json.dumps({
                    "success": False,
                    "status": "unavailable",
                    "message": "TopologyMonitor is not available"
                }).encode("utf-8")
            )

        reason = data.get("reason", "REST link action")
        if action == "isolate":
            success = topology.isolate_link(src_dpid, dst_dpid)
        else:
            success = topology.restore_link(src_dpid, dst_dpid)

        result = {
            "success": bool(success),
            "status": "executed" if success else "rejected",
            "action": action.upper(),
            "src_dpid": src_dpid,
            "dst_dpid": dst_dpid,
            "reason": reason,
            "topology_status": topology.get_topology_status()
        }
        return Response(
            status=200 if success else 400,
            content_type="application/json",
            charset="utf-8",
            body=json.dumps(result).encode("utf-8")
        )

    @route(
        "network_link_isolate",
        "/network/link/isolate",
        methods=["POST"]
    )
    def network_link_isolate(self, req, **kwargs):
        return self._link_action(req, "isolate")

    @route(
        "network_link_restore",
        "/network/link/restore",
        methods=["POST"]
    )
    def network_link_restore(self, req, **kwargs):
        return self._link_action(req, "restore")

    @route(
        "network_link_metric",
        "/network/link/metric",
        methods=["POST"]
    )
    def network_link_metric(self, req, **kwargs):
        try:
            data = json.loads(req.body.decode("utf-8"))
            src_dpid = int(data["src_dpid"])
            dst_dpid = int(data["dst_dpid"])
            utilization = float(data["utilization"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return Response(
                status=400,
                content_type="application/json",
                charset="utf-8",
                body=json.dumps({
                    "success": False,
                    "status": "error",
                    "message": (
                        "src_dpid, dst_dpid and utilization are required"
                    ),
                    "details": str(exc)
                }).encode("utf-8")
            )

        topology = self.monitor._get_topology_monitor()
        if topology is None:
            return Response(
                status=503,
                content_type="application/json",
                charset="utf-8",
                body=json.dumps({
                    "success": False,
                    "status": "unavailable",
                    "message": "TopologyMonitor is not available"
                }).encode("utf-8")
            )

        topology.update_link_metric(
            src_dpid,
            dst_dpid,
            utilization=utilization,
            rate_bps=data.get("rate_bps"),
            capacity_bps=data.get("capacity_bps")
        )

        return Response(
            status=200,
            content_type="application/json",
            charset="utf-8",
            body=json.dumps({
                "success": True,
                "status": "updated",
                "path_engine": topology.get_path_engine_status()
            }).encode("utf-8")
        )


# =============================================================
# TRAFFIC MONITOR MERGED
# =============================================================

class TrafficMonitorMerged(
    app_manager.RyuApp
):

    OFP_VERSIONS = [
        ofproto_v1_3.OFP_VERSION
    ]

    _CONTEXTS = {
        "wsgi": WSGIApplication
    }

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
        # -----------------------------------------------------

        self.topology_monitor = None

        # -----------------------------------------------------
        # Local host cache
        #
        # This is observation/cache information only.
        #
        # TopologyMonitor remains the source of truth.
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
        # Flow monitoring
        # -----------------------------------------------------

        self.flow_baselines = {}
        self.flow_last_seen = {}

        # -----------------------------------------------------
        # Action history
        # -----------------------------------------------------

        self.action_history = {}

        # -----------------------------------------------------
        # Legacy CLFF state
        #
        # Kept only for compatibility/cleanup.
        #
        # TrafficMonitorMerged no longer forwards using CLFF.
        # -----------------------------------------------------

        self.broadcast_state = {}
        self.processed_broadcasts = {}

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

        wsgi = kwargs["wsgi"]

        wsgi.register(
            NetworkActionController,
            {
                "traffic_monitor": self
            }
        )

        # -----------------------------------------------------
        # CSV
        # -----------------------------------------------------

        self._initialize_csv_files()

        # -----------------------------------------------------
        # FlowStats
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
            "Security action execution owner: TrafficMonitorMerged"
        )

        # -----------------------------------------------------
        # FORWARDING OWNERSHIP
        # -----------------------------------------------------

        self.logger.info(
            "Forwarding owner: TopologyMonitor"
        )

        self.logger.info(
            "Topology/forwarding owner: TopologyMonitor; "
            "path decisions: PathEngine"
        )

        self.logger.info(
            "ARP owner: TopologyMonitor"
        )

        self.logger.info(
            "Host learning owner: TopologyMonitor"
        )

        self.logger.info(
            "Known unicast owner: TopologyMonitor"
        )

        self.logger.info(
            "Unknown unicast owner: TopologyMonitor"
        )

        self.logger.info(
            "Broadcast/Multicast owner: TopologyMonitor + CLFF"
        )

        self.logger.info(
            "Reroute: delegated to TopologyMonitor"
        )

        self.logger.info(
            "TrafficMonitor forwarding: OBSERVATION ONLY"
        )

        self.logger.info(
            "TrafficMonitor PacketOut forwarding: DISABLED"
        )

        self.logger.info(
            "TrafficMonitor CLFF forwarding: DISABLED"
        )

        self.logger.info(
            "TopologyMonitor CLFF: %s",
            "ENABLED" if CLFF_ENABLED else "DISABLED"
        )

        self.logger.info(
            "Inter-switch OFPP_FLOOD: DISABLED"
        )

        self.logger.info(
            "================================================="
        )

    # =========================================================
    # TOPOLOGY MONITOR ACCESS
    # =========================================================

    def _get_topology_monitor(self):

        if self.topology_monitor is not None:
            return self.topology_monitor

        try:

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
    # CLFF ENGINE ACCESS
    #
    # Compatibility/status only.
    #
    # TrafficMonitorMerged does NOT use CLFF for forwarding.
    # =========================================================

    def _get_clff_engine(self):

        topology = self._get_topology_monitor()

        if topology is None:
            return None

        clff = getattr(
            topology,
            "clff",
            None
        )

        if clff is None:

            self.logger.debug(
                "TopologyMonitor has no CLFF engine"
            )

            return None

        try:

            if not clff.is_ready():

                self.logger.debug(
                    "CLFF engine is not ready"
                )

                return None

        except Exception:

            return None

        return clff

    # =========================================================
    # INTER-SWITCH PORT CHECK
    # =========================================================

    def _is_inter_switch_port(
        self,
        dpid,
        port
    ):

        topology = self._get_topology_monitor()

        if topology is None:
            return False

        try:

            port_to_link = getattr(
                topology,
                "port_to_link",
                {}
            )

            return (dpid, port) in port_to_link

        except Exception:

            return False

    # =========================================================
    # GET HOST PORTS
    #
    # TopologyMonitor is the source of truth.
    #
    # This method is retained for compatibility/status only.
    # It is NOT used for packet forwarding here.
    # =========================================================

    def _get_host_ports(self, dpid):

        topology = self._get_topology_monitor()

        if topology is None:
            return []

        host_ports = set()

        try:

            host_location = getattr(
                topology,
                "host_location",
                {}
            )

            for location in host_location.values():

                host_dpid = None
                host_port = None

                if isinstance(location, dict):

                    host_dpid = location.get(
                        "dpid"
                    )

                    host_port = location.get(
                        "port"
                    )

                elif isinstance(
                    location,
                    (tuple, list)
                ):

                    if len(location) >= 2:

                        host_dpid = location[0]
                        host_port = location[1]

                if (
                    host_dpid == dpid
                    and host_port is not None
                ):

                    if not self._is_inter_switch_port(
                        dpid,
                        host_port
                    ):

                        host_ports.add(
                            host_port
                        )

        except Exception as e:

            self.logger.debug(
                "Unable to get host ports on s%d: %s",
                dpid,
                e
            )

        if not host_ports:

            for host_info in self.hosts.values():

                if not isinstance(
                    host_info,
                    dict
                ):
                    continue

                if host_info.get(
                    "dpid"
                ) != dpid:
                    continue

                port = host_info.get(
                    "port"
                )

                if port is None:
                    continue

                if self._is_inter_switch_port(
                    dpid,
                    port
                ):
                    continue

                host_ports.add(
                    port
                )

        return sorted(
            host_ports
        )

    # =========================================================
    # GET KNOWN HOST INFORMATION
    #
    # TopologyMonitor is the primary source.
    #
    # This is observation/status lookup only.
    # =========================================================

    def _get_known_host(
        self,
        dst_mac
    ):

        topology = self._get_topology_monitor()

        if topology is not None:

            try:

                host_location = getattr(
                    topology,
                    "host_location",
                    {}
                )

                location = host_location.get(
                    dst_mac
                )

                if location is not None:

                    if isinstance(
                        location,
                        dict
                    ):

                        dpid = location.get(
                            "dpid"
                        )

                        port = location.get(
                            "port"
                        )

                    elif isinstance(
                        location,
                        (tuple, list)
                    ):

                        if len(location) >= 2:

                            dpid = location[0]
                            port = location[1]

                        else:

                            dpid = None
                            port = None

                    else:

                        dpid = None
                        port = None

                    if (
                        dpid is not None
                        and port is not None
                    ):

                        return {
                            "dpid": dpid,
                            "port": port
                        }

            except Exception as e:

                self.logger.debug(
                    "Unable to read host %s "
                    "from TopologyMonitor: %s",
                    dst_mac,
                    e
                )

        host_info = self.hosts.get(
            dst_mac
        )

        if isinstance(
            host_info,
            dict
        ):

            if (
                "dpid" in host_info
                and "port" in host_info
            ):

                return host_info

        return None

    # =========================================================
    # LOOP-FREE UNICAST OUTPUT PORT
    #
    # Compatibility helper only.
    #
    # IMPORTANT:
    # TrafficMonitorMerged no longer calls this from PacketIn.
    #
    # Actual forwarding is performed by TopologyMonitor.
    # =========================================================

    def _get_loop_free_output_port(
        self,
        dpid,
        dst_mac
    ):

        if not LOOP_FREE_FORWARDING_ENABLED:
            return None

        topology = self._get_topology_monitor()

        if topology is None:

            self.logger.warning(
                "Cannot query forwarding path: "
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

            return output_port

        except AttributeError:

            self.logger.error(
                "TopologyMonitor does not provide "
                "get_forwarding_port(dpid, dst_mac)"
            )

            return None

        except Exception as e:

            self.logger.exception(
                "TopologyMonitor forwarding lookup failed: "
                "s%d -> %s : %s",
                dpid,
                dst_mac,
                e
            )

            return None

    # =========================================================
    # LEGACY CLFF HELPERS
    #
    # These are intentionally retained so the file remains
    # compatible with the existing project structure.
    #
    # They are NOT called from PacketIn forwarding anymore.
    #
    # CLFF forwarding belongs exclusively to TopologyMonitor.
    # =========================================================

    def _get_clff_packet_key(
        self,
        msg,
        eth_pkt
    ):

        try:

            import hashlib

            frame_hash = hashlib.sha256(
                msg.data
            ).hexdigest()

        except Exception:

            frame_hash = (
                "%s-%s-%s"
                % (
                    eth_pkt.src,
                    eth_pkt.dst,
                    eth_pkt.ethertype
                )
            )

        return (
            eth_pkt.src,
            eth_pkt.dst,
            eth_pkt.ethertype,
            frame_hash
        )

    def _get_or_create_clff_root(
        self,
        packet_key,
        ingress_dpid
    ):

        now = time.time()

        state = self.broadcast_state.get(
            packet_key
        )

        if state is not None:

            if (
                now - state["timestamp"]
                <= CLFF_BROADCAST_STATE_TIMEOUT
            ):

                state["timestamp"] = now

                return state[
                    "root_dpid"
                ]

            self.broadcast_state.pop(
                packet_key,
                None
            )

        self.broadcast_state[
            packet_key
        ] = {
            "root_dpid": ingress_dpid,
            "timestamp": now
        }

        return ingress_dpid

    def _cleanup_clff_state(self):

        now = time.time()

        expired_keys = []

        for (
            key,
            state
        ) in list(
            self.broadcast_state.items()
        ):

            if (
                now - state["timestamp"]
                > CLFF_BROADCAST_STATE_TIMEOUT
            ):

                expired_keys.append(
                    key
                )

        for key in expired_keys:

            self.broadcast_state.pop(
                key,
                None
            )

        expired_processed = []

        for (
            key,
            timestamp
        ) in list(
            self.processed_broadcasts.items()
        ):

            if (
                now - timestamp
                > CLFF_BROADCAST_STATE_TIMEOUT
            ):

                expired_processed.append(
                    key
                )

        for key in expired_processed:

            self.processed_broadcasts.pop(
                key,
                None
            )

    # =========================================================
    # DISABLED LEGACY CLFF INSTALLATION
    #
    # Kept as a safety guard.
    #
    # It deliberately does NOTHING.
    # =========================================================

    def _install_clff_tree_rules(
        self,
        root_dpid,
        packet_key,
        eth_pkt,
        source_in_port
    ):

        self.logger.debug(
            "TrafficMonitor CLFF rule installation skipped; "
            "TopologyMonitor owns CLFF"
        )

        return False

    # =========================================================
    # DISABLED LEGACY CLFF FORWARDING
    #
    # IMPORTANT:
    # Never send PacketOut from this application for
    # broadcast/unknown forwarding.
    # =========================================================

    def _forward_clff_packet(
        self,
        datapath,
        msg,
        in_port,
        eth_pkt
    ):

        self.logger.debug(
            "TrafficMonitor CLFF forwarding skipped on s%d; "
            "TopologyMonitor owns CLFF forwarding",
            datapath.id
        )

        return False

    # =========================================================
    # CSV INITIALIZATION
    # =========================================================

    def _initialize_csv_files(self):

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

        if (
            not packet_exists
            or os.path.getsize(
                PACKET_CSV
            ) == 0
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

        if (
            not flow_exists
            or os.path.getsize(
                FLOW_CSV
            ) == 0
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

    # =========================================================
    # DATAPATH STATE CHANGE
    # =========================================================

    @handler.set_ev_cls(
        ofp_event.EventOFPStateChange,
        [
            MAIN_DISPATCHER,
            DEAD_DISPATCHER
        ]
    )
    def state_change_handler(
        self,
        ev
    ):

        datapath = ev.datapath

        dpid = getattr(datapath, "id", None)

        if dpid is None:
            self.logger.warning(
                "Datapath state change without a valid DPID: state=%s",
                ev.state
            )
            return

        if ev.state == MAIN_DISPATCHER:

            self.datapaths[
                dpid
            ] = datapath

            self.logger.info(
                "Datapath registered: s%d",
                dpid
            )

        elif ev.state == DEAD_DISPATCHER:

            if dpid in self.datapaths:

                del self.datapaths[
                    dpid
                ]

            self.logger.info(
                "Datapath removed: s%d",
                dpid
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
    #
    #
    # It is NOT used for normal forwarding anymore.
    # =========================================================

    def _add_flow(
        self,
        datapath,
        priority,
        match,
        actions,
        idle_timeout=0,
        hard_timeout=0
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

        pkt = packet.Packet(
            msg.data
        )

        eth_pkt = pkt.get_protocol(
            ethernet.ethernet
        )

        if eth_pkt is None:
            return

        # =====================================================
        # LLDP
        #
        # TopologyMonitor owns LLDP completely.
        # =====================================================

        if eth_pkt.ethertype == 0x88CC:

            return

        src_mac = eth_pkt.src
        dst_mac = eth_pkt.dst

        # =====================================================
        # INTER-SWITCH CHECK
        # =====================================================

        inter_switch_port = (
            self._is_inter_switch_port(
                dpid,
                in_port
            )
        )

        # =====================================================
        # LOCAL OBSERVATION CACHE
        #
        # TopologyMonitor owns actual host learning.
        # =====================================================

        if not inter_switch_port:

            self.hosts[src_mac] = {
                "dpid": dpid,
                "port": in_port
            }

        # =====================================================
        # DEFAULT FEATURE VALUES
        # =====================================================

        src_ip = ""
        dst_ip = ""
        protocol = ""
        src_port = ""
        dst_port = ""

        tcp_flags = ""
        icmp_type = ""
        arp_operation = ""

        # =====================================================
        # IPv4
        # =====================================================

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

            tcp_pkt = pkt.get_protocol(
                tcp.tcp
            )

            if tcp_pkt is not None:

                src_port = (
                    tcp_pkt.src_port
                )

                dst_port = (
                    tcp_pkt.dst_port
                )

                tcp_flags = (
                    tcp_pkt.bits
                )

            udp_pkt = pkt.get_protocol(
                udp.udp
            )

            if udp_pkt is not None:

                src_port = (
                    udp_pkt.src_port
                )

                dst_port = (
                    udp_pkt.dst_port
                )

            icmp_pkt = pkt.get_protocol(
                icmp.icmp
            )

            if icmp_pkt is not None:

                icmp_type = (
                    icmp_pkt.type
                )

        # =====================================================
        # IPv6
        # =====================================================

        ipv6_pkt = pkt.get_protocol(
            ipv6.ipv6
        )

        if ipv6_pkt is not None:

            src_ip = ipv6_pkt.src
            dst_ip = ipv6_pkt.dst
            protocol = ipv6_pkt.nxt

            self.ip_to_mac[
                src_ip
            ] = src_mac

            self.mac_to_ip[
                src_mac
            ] = src_ip

        # =====================================================
        # ARP
        #
        # TrafficMonitor ONLY observes ARP.
        #
        # It does NOT:
        #   - reply to ARP
        #   - flood ARP
        #   - forward ARP
        #
        # TopologyMonitor handles all of that.
        # =====================================================

        arp_pkt = pkt.get_protocol(
            arp.arp
        )

        if arp_pkt is not None:

            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

            arp_operation = (
                arp_pkt.opcode
            )

            self.ip_to_mac[
                src_ip
            ] = src_mac

            self.mac_to_ip[
                src_mac
            ] = src_ip

        # =====================================================
        # PACKET FEATURE COLLECTION
        # =====================================================

        packet_length = len(
            msg.data
        )

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

        # =====================================================
        # TRUST STATE
        # =====================================================

        if src_ip:

            if src_ip not in self.trust_state:

                self.trust_state[
                    src_ip
                ] = UNTRUSTED

        # =====================================================
        # SECURITY BLOCK CHECK (observation-side fallback)
        # TopologyMonitor owns the actual OpenFlow enforcement.
        # =====================================================

        topology = self._get_topology_monitor()
        if topology is not None:
            blocked = getattr(topology, "blocked_devices", {})
            if str(src_mac).lower() in blocked:
                self.logger.warning(
                    "Packet observed from blocked MAC %s (IP=%s); "
                    "TopologyMonitor owns the drop rule", src_mac, src_ip)
                return

        # =====================================================
        # ARP
        #
        # TrafficMonitor stops observing here.
        #
        # TopologyMonitor receives the same PacketIn event and
        # handles ARP forwarding.
        # =====================================================

        if eth_pkt.ethertype == 0x0806:

            self.logger.debug(
                "ARP observed by TrafficMonitor on s%d; "
                "forwarding delegated to TopologyMonitor",
                dpid
            )

            self._cleanup_clff_state()

            return

        # =====================================================
        # NON-ARP PACKET
        #
        # IMPORTANT:
        #
        # We DO NOT call a forwarding function here.
        #
        # TopologyMonitor independently receives the same
        # PacketIn event and performs forwarding.
        #
        # TrafficMonitor only observes this packet.
        # =====================================================

        self._observe_forwarding_event(
            datapath=datapath,
            msg=msg,
            in_port=in_port,
            dst_mac=dst_mac
        )

        self._cleanup_clff_state()

    # =========================================================
    # FORWARDING OBSERVATION ONLY
    #
    # This function MUST NOT:
    #   - send PacketOut
    #   - install forwarding FlowMod
    #   - run Dijkstra
    #   - run CLFF
    #   - flood
    #
    # TopologyMonitor is the forwarding owner.
    # =========================================================

    def _observe_forwarding_event(
        self,
        datapath,
        msg,
        in_port,
        dst_mac
    ):

        dpid = datapath.id

        if self._is_broadcast_or_multicast(
            dst_mac
        ):

            self.logger.debug(
                "Observed broadcast/multicast on s%d -> %s; "
                "TopologyMonitor owns forwarding",
                dpid,
                dst_mac
            )

            return

        dst_info = self._get_known_host(
            dst_mac
        )

        if dst_info is not None:

            self.logger.debug(
                "Observed known unicast on s%d -> %s; "
                "TopologyMonitor owns forwarding",
                dpid,
                dst_mac
            )

            return

        self.logger.debug(
            "Observed unknown unicast on s%d -> %s; "
            "TopologyMonitor owns forwarding",
            dpid,
            dst_mac
        )

    # =========================================================
    # BACKWARD-COMPATIBILITY ALIAS
    #
    # Existing code that calls _forward_packet() will still
    # work, but this method NEVER forwards.
    # =========================================================

    def _forward_packet(
        self,
        datapath,
        msg,
        in_port,
        dst_mac
    ):

        self._observe_forwarding_event(
            datapath=datapath,
            msg=msg,
            in_port=in_port,
            dst_mac=dst_mac
        )

    # =========================================================
    # BROADCAST / MULTICAST CHECK
    # =========================================================

    def _is_broadcast_or_multicast(
        self,
        dst_mac
    ):

        if not dst_mac:
            return False

        normalized = dst_mac.lower()

        if normalized == (
            "ff:ff:ff:ff:ff:ff"
        ):

            return True

        try:

            first_octet = int(
                normalized.split(":")[0],
                16
            )

            return bool(
                first_octet & 1
            )

        except Exception:

            return False

    # =========================================================
    # FLOW STATS LOOP
    # =========================================================

    def _flow_stats_loop(self):

        while True:

            try:

                for datapath in list(
                    self.datapaths.values()
                ):

                    self._request_flow_stats(
                        datapath
                    )

                self._cleanup_stale_flows()
                self._cleanup_clff_state()

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

        parser = (
            datapath.ofproto_parser
        )

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
            # Ignore table-miss
            # -------------------------------------------------

            if (
                stat.priority
                == TABLE_MISS_PRIORITY
            ):

                continue

            # -------------------------------------------------
            # Ignore legacy CLFF priority.
            #
            # Current CLFF rules belong to TopologyMonitor.
            # -------------------------------------------------

            if (
                stat.priority
                == CLFF_PRIORITY
            ):

                continue

            match = stat.match

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

            if protocol == 6:

                src_port = match.get(
                    "tcp_src",
                    ""
                )

                dst_port = match.get(
                    "tcp_dst",
                    ""
                )

            elif protocol == 17:

                src_port = match.get(
                    "udp_src",
                    ""
                )

                dst_port = match.get(
                    "udp_dst",
                    ""
                )

            if not src_ip and not dst_ip:
                continue

            packet_count = (
                stat.packet_count
            )

            byte_count = (
                stat.byte_count
            )

            duration_sec = (
                stat.duration_sec
                + (
                    stat.duration_nsec
                    / 1_000_000_000.0
                )
            )

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
            # First observation = baseline
            # -------------------------------------------------

            if (
                flow_key
                not in self.flow_baselines
            ):

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

            previous = (
                self.flow_baselines[
                    flow_key
                ]
            )

            previous_packets = (
                previous[
                    "packet_count"
                ]
            )

            previous_bytes = (
                previous[
                    "byte_count"
                ]
            )

            previous_time = (
                previous[
                    "timestamp"
                ]
            )

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
            # Counter reset handling
            # -------------------------------------------------

            if packet_delta < 0:

                packet_delta = (
                    packet_count
                )

            if byte_delta < 0:

                byte_delta = (
                    byte_count
                )

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
            # Update baseline
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
            # Write flow feature
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

        for (
            flow_key,
            last_seen
        ) in list(
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
        self, host_ip, action, trust_state=None, trust_score=None,
        reason=None, mac=None
    ):
        action = str(action).strip().upper()
        valid_actions = {
            ACTION_ALLOW, ACTION_KEEP_UNTRUSTED, ACTION_BLOCK_DEVICE,
            ACTION_UNBLOCK_DEVICE, ACTION_REROUTE
        }
        if action not in valid_actions:
            return {"valid": False, "message": "Invalid action: %s" % action}

        if trust_state is not None and trust_state not in {TRUSTED, UNTRUSTED}:
            return {"valid": False, "message": "Invalid trust state: %s" % trust_state}

        if trust_score is not None:
            if isinstance(trust_score, bool):
                return {"valid": False, "message": "Invalid trust score"}
            try:
                trust_score = float(trust_score)
            except (TypeError, ValueError):
                return {"valid": False, "message": "Invalid trust score"}
            if not MIN_SCORE <= trust_score <= MAX_SCORE:
                return {"valid": False,
                        "message": "Trust score must be between %s and %s"
                                   % (MIN_SCORE, MAX_SCORE)}

        if action in (ACTION_BLOCK_DEVICE, ACTION_UNBLOCK_DEVICE):
            try:
                fields = self.decision_validator.validate_device_action(
                    action, mac, host_ip)
            except ValueError as exc:
                return {"valid": False, "message": str(exc)}
            return {"valid": True, "host_ip": fields["ip"],
                    "mac": fields["mac"], "action": action,
                    "trust_state": trust_state, "trust_score": trust_score,
                    "reason": reason}

        if not isinstance(host_ip, str) or not host_ip.strip():
            return {"valid": False, "message": "ip (or host_ip) is required"}
        try:
            host_ip = str(ipaddress.ip_address(host_ip.strip()))
        except ValueError:
            return {"valid": False, "message": "ip must be a valid IPv4 or IPv6 address"}

        if trust_state is not None:
            try:
                self.decision_validator.validate_decision(
                    trust_score=trust_score if trust_score is not None else 0,
                    trust_state=trust_state, action=action)
            except ValueError as exc:
                return {"valid": False, "message": str(exc)}

        return {"valid": True, "host_ip": host_ip, "mac": None,
                "action": action, "trust_state": trust_state,
                "trust_score": trust_score, "reason": reason}

    # =========================================================
    # UPDATE TRUST STATE
    # =========================================================

    def update_trust_state(self, host_ip, state, trust_score=None):
        if state not in {TRUSTED, UNTRUSTED}:
            return {"success": False, "message": "Invalid trust state: %s" % state}
        self.trust_state[host_ip] = state
        if trust_score is not None:
            self.trust_scores[host_ip] = trust_score
        return {"success": True, "host_ip": host_ip,
                "trust_state": state, "trust_score": trust_score}

    # =========================================================
    # EXECUTE SECURITY ACTION
    # =========================================================

    def execute_security_action(
        self, host_ip=None, action=None, request_id=None, trust_state=None,
        trust_score=None, reason=None, mac=None
    ):
        action = str(action or "").strip().upper()
        validation = self._validate_network_decision(
            host_ip=host_ip, mac=mac, action=action,
            trust_state=trust_state, trust_score=trust_score, reason=reason)
        if not validation["valid"]:
            self.logger.warning("Security decision rejected: %s", validation["message"])
            return {"success": False, "status": "rejected",
                    "message": validation["message"], "host_ip": host_ip,
                    "mac": mac, "action": action}

        host_ip = validation["host_ip"]
        mac = validation["mac"]

        # Explicit enforcement actions do not alter Trust Score or state.
        if action in (ACTION_BLOCK_DEVICE, ACTION_UNBLOCK_DEVICE):
            topology = self._get_topology_monitor()
            if topology is None:
                return {"success": False, "status": "unavailable",
                        "message": "TopologyMonitor is not available",
                        "action": action, "mac": mac, "ip": host_ip}
            method = (topology.block_device if action == ACTION_BLOCK_DEVICE
                      else topology.unblock_device)
            result = method(mac=mac, ip=host_ip, request_id=request_id,
                            reason=reason)
            self._record_action(
                request_id=request_id, host_ip=host_ip, mac=mac, action=action,
                status=result.get("status", "failed"), reason=reason)
            result.update({"action": action, "mac": mac, "ip": host_ip,
                           "request_id": request_id,
                           "trust_state_unchanged": True,
                           "trust_score_unchanged": True})
            return result

        if trust_score is not None:
            self.trust_scores[host_ip] = trust_score
        if trust_state is not None:
            state_result = self.update_trust_state(host_ip, trust_state, trust_score)
            if not state_result["success"]:
                return state_result

        if action == ACTION_KEEP_UNTRUSTED:
            if host_ip not in self.trust_state:
                self.trust_state[host_ip] = UNTRUSTED
            self._record_action(request_id, host_ip, action, "executed", reason)
            return {"success": True, "status": "executed", "action": action,
                    "host_ip": host_ip, "request_id": request_id}

        if action == ACTION_ALLOW:
            self.trust_state[host_ip] = trust_state or TRUSTED
            self._record_action(request_id, host_ip, action, "executed", reason)
            return {"success": True, "status": "executed", "action": action,
                    "host_ip": host_ip, "request_id": request_id}

        if action == ACTION_REROUTE:
            success = self.reroute_host(host_ip, request_id, reason)
            status = "requested" if success else "failed"
            self._record_action(request_id, host_ip, action, status, reason)
            return {"success": success, "status": status, "action": action,
                    "host_ip": host_ip, "request_id": request_id}

        return {"success": False, "status": "failed",
                "message": "Unhandled action", "host_ip": host_ip,
                "mac": mac, "action": action, "request_id": request_id}

    # =========================================================
    # REROUTE REQUEST
    # =========================================================

    def reroute_host(
        self,
        host_ip,
        request_id=None,
        reason=None
    ):

        self.logger.info(
            "REROUTE request received: "
            "host=%s request_id=%s reason=%s",
            host_ip,
            request_id,
            reason
        )

        try:

            reroute_event = (
                EventRerouteHost(
                    host_ip=host_ip,
                    request_id=request_id
                )
            )

            self.send_event_to_observers(
                reroute_event
            )

            self.logger.info(
                "REROUTE request delegated to "
                "TopologyMonitor: host=%s request_id=%s",
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
        reason=None,
        mac=None
    ):

        if request_id is None:

            request_id = (
                "AUTO-%d"
                % int(
                    time.time() * 1000
                )
            )

        self.action_history[
            request_id
        ] = {
            "request_id": request_id,
            "host_ip": host_ip,
            "mac": mac,
            "action": action,
            "status": status,
            "reason": reason,
            "timestamp": time.time()
        }

    # =========================================================
    # PUBLIC HELPERS
    # =========================================================

    def get_switches(
        self
    ):

        return list(
            self.datapaths.keys()
        )

    def get_hosts(
        self
    ):

        topology = (
            self._get_topology_monitor()
        )

        if topology is not None:

            try:

                host_location = getattr(
                    topology,
                    "host_location",
                    {}
                )

                if host_location:

                    return host_location.copy()

            except Exception:
                pass

        return self.hosts.copy()

    def get_action(
        self,
        request_id
    ):

        return self.action_history.get(
            request_id
        )

    def get_network_status(
        self
    ):

        topology = (
            self._get_topology_monitor()
        )

        topology_status = None

        if topology is not None:

            try:

                topology_status = (
                    topology.get_topology_status()
                )

            except Exception:

                topology_status = None

        clff = None

        if topology is not None:

            clff = getattr(
                topology,
                "clff",
                None
            )

        clff_ready = False

        if clff is not None:

            try:

                clff_ready = clff.is_ready()

            except Exception:

                clff_ready = False

        return {
            "switches": self.get_switches(),
            "hosts": self.get_hosts(),
            "blocked_devices": (
                dict(getattr(topology, "blocked_devices", {}))
                if topology is not None else {}
            ),
            "trust_state": (
                self.trust_state.copy()
            ),
            "trust_scores": (
                self.trust_scores.copy()
            ),
            "topology": topology_status,
            "clff_enabled": CLFF_ENABLED,
            "clff_ready": clff_ready,
            "forwarding_owner": "TopologyMonitor",
            "traffic_monitor_forwarding": False
        }

    # =========================================================
    # CLOSE
    # =========================================================

    def close(
        self
    ):

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