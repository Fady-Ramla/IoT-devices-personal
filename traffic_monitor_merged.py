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
import hmac
import ipaddress
import os
from pathlib import Path
import threading
import time
import uuid


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

try:
    from zero_trust.zero_trust_policy import (
        TRUSTED,
        UNTRUSTED,
        ACTION_ALLOW,
        ACTION_KEEP_UNTRUSTED,
        ACTION_REROUTE,
        MIN_SCORE,
        MAX_SCORE,
    )
except ImportError:
    from zero_trust.zero_trust_policy import (
        TRUSTED,
        UNTRUSTED,
        ACTION_ALLOW,
        ACTION_KEEP_UNTRUSTED,
        ACTION_REROUTE,
        MIN_SCORE,
        MAX_SCORE,
    )


# Do not accept legacy policy aliases for device isolation actions.
ACTION_BLOCK_DEVICE = "BLOCK_DEVICE"
ACTION_UNBLOCK_DEVICE = "UNBLOCK_DEVICE"

# =============================================================
# ZERO-TRUST DECISION VALIDATOR
# =============================================================

from zero_trust.zero_trust_decision import ZeroTrustDecision


# =============================================================
# REROUTE EVENT
# =============================================================

from topology_monitor import EventRerouteHost

# Shadow-only API client. It must never enforce a returned verdict.
try:
    from shadow_api_client import submit_flow_live
except ImportError:
    submit_flow_live = None


# =============================================================
# CONSTANTS
# =============================================================

PACKET_CSV = "packet_features.csv"
FLOW_CSV = "traffic_features.csv"

FLOW_POLL_INTERVAL = 2.0

# PacketIn fallback window.  The topology app may install MAC-only rules,
# which do not expose IPv4 fields through FlowStats.  In that case we build
# model-safe flow windows from observed packets without touching forwarding.
PACKET_FLOW_WINDOW = 5.0

FLOW_IDLE_TIMEOUT = 15
STALE_FLOW_MAX_AGE = 60

CSV_FLUSH_EVERY = 50

# Dataset run lifecycle and durable run-scoped output.
PROJECT_ROOT = Path(__file__).resolve().parent
ACTIVE_RUN_FILE = Path(os.environ.get("SECUREIOT_ACTIVE_RUN_FILE", str(PROJECT_ROOT / "New_Datasets" / "active_run.json"))).expanduser().resolve()
RAW_DATA_ROOT = Path(os.environ.get("SECUREIOT_RAW_DATA_ROOT", str(PROJECT_ROOT / "New_Datasets" / "raw"))).expanduser().resolve()
PACKET_DATA_DIR = RAW_DATA_ROOT / "packet"
FLOW_DATA_DIR = RAW_DATA_ROOT / "flow"
SHADOW_API_DATA_DIR = RAW_DATA_ROOT / "shadow_api"
DATASET_RUN_LEDGER = RAW_DATA_ROOT / ".dataset_run_ids.jsonl"
PACKET_HEADER = [
    "run_id", "observation_id", "timestamp", "switch_dpid", "in_port",
    "src_mac", "dst_mac", "src_ip", "dst_ip", "protocol", "src_port",
    "dst_port", "packet_length", "tcp_flags", "icmp_type", "arp_operation"
]
FLOW_HEADER = [
    "run_id", "observation_id", "timestamp", "switch_dpid", "src_ip", "dst_ip",
    "src_port", "dst_port", "protocol", "priority", "packet_count", "byte_count",
    "packet_rate", "byte_rate", "duration_sec", "avg_packet_size", "syn_count",
    "ack_count", "rst_count", "fin_count", "syn_ack_ratio", "rst_ratio",
    "unique_dst_ports", "failed_connection_count", "tcp_fraction", "udp_fraction",
    "icmp_fraction", "source", "src_mac", "dst_mac"
]
PACKET_FLOW_WINDOW = 10.0

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

        expected_token = self.monitor.control_token
        supplied_token = req.headers.get("X-SecureIoT-Token", "")
        if not expected_token:
            return Response(
                status=503, content_type="application/json",
                charset="utf-8",
                body=json.dumps({
                    "success": False, "status": "unavailable",
                    "message": "Zero Trust control token is not configured"
                }).encode("utf-8"))
        if not supplied_token or not hmac.compare_digest(
                supplied_token, expected_token):
            return Response(
                status=401, content_type="application/json",
                charset="utf-8",
                body=json.dumps({
                    "success": False, "status": "unauthorized",
                    "message": "Valid Zero Trust control token required"
                }).encode("utf-8"))

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

    @route(
        "security_decision",
        "/security/decision",
        methods=["POST"]
    )
    def security_decision(self, req, **kwargs):
        """Accept Security telemetry and execute only its BLOCK decision."""
        expected_token = self.monitor.control_token
        supplied_token = req.headers.get("X-SecureIoT-Token", "")
        if not expected_token:
            return Response(status=503, content_type="application/json",
                            charset="utf-8", body=json.dumps({
                                "success": False, "status": "unavailable",
                                "message": "Zero Trust control token is not configured"
                            }).encode("utf-8"))
        if not supplied_token or not hmac.compare_digest(
                supplied_token, expected_token):
            return Response(status=401, content_type="application/json",
                            charset="utf-8", body=json.dumps({
                                "success": False, "status": "unauthorized",
                                "message": "Valid Zero Trust control token required"
                            }).encode("utf-8"))
        try:
            payload = json.loads(req.body.decode("utf-8"))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            return Response(status=400, content_type="application/json",
                            charset="utf-8", body=json.dumps({
                                "success": False, "status": "error",
                                "message": "Invalid JSON", "error": str(exc)
                            }).encode("utf-8"))
        try:
            result = self.monitor.handle_security_decision(payload)
            status_code = 200 if result.get("success") else 400
            return Response(status=status_code, content_type="application/json",
                            charset="utf-8", body=json.dumps(result).encode("utf-8"))
        except Exception as exc:
            self.monitor.logger.exception("Security decision failed")
            return Response(status=500, content_type="application/json",
                            charset="utf-8", body=json.dumps({
                                "success": False, "status": "error",
                                "message": str(exc)
                            }).encode("utf-8"))

    def _link_action(self, req, action):
        expected_token = self.monitor.control_token
        supplied_token = req.headers.get("X-SecureIoT-Token", "")
        if not expected_token:
            return Response(
                status=503, content_type="application/json", charset="utf-8",
                body=json.dumps({
                    "success": False, "status": "unavailable",
                    "message": "Zero Trust control token is not configured"
                }).encode("utf-8"))
        if not supplied_token or not hmac.compare_digest(supplied_token, expected_token):
            return Response(
                status=401, content_type="application/json", charset="utf-8",
                body=json.dumps({
                    "success": False, "status": "unauthorized",
                    "message": "Valid Zero Trust control token required"
                }).encode("utf-8"))
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

class DatasetRunController(ControllerBase):
    """Local peer only; never trust forwarding headers for authorization.

    POST /dataset/run:
      {"operation": "start", "run_id": "unique-id", "generation": 1,
       "expected_switches": 6}
      {"operation": "stop", "run_id": "unique-id", "generation": 1}
    GET /dataset/run/status (or POST with operation=status).
    The global WSGI listener is deliberately not changed, preserving ZT REST.
    """

    def __init__(self, req, link, data, **config):
        super(DatasetRunController, self).__init__(req, link, data, **config)
        self.monitor = data["traffic_monitor"]

    @staticmethod
    def _local_peer(req):
        # A localhost reverse proxy must not expose this control surface.
        if any(name in req.headers for name in
               ("Forwarded", "X-Forwarded-For", "X-Real-IP")):
            return False
        try:
            peer = ipaddress.ip_address(req.environ.get("REMOTE_ADDR", ""))
        except (ValueError, TypeError):
            return False
        if isinstance(peer, ipaddress.IPv6Address) and peer.ipv4_mapped:
            peer = peer.ipv4_mapped
        return peer.is_loopback

    @staticmethod
    def _response(status, data):
        return Response(status=status, content_type="application/json",
                        charset="utf-8", body=json.dumps(data).encode("utf-8"))

    @route("dataset_run", "/dataset/run", methods=["POST"])
    def dataset_run(self, req, **kwargs):
        if not self._local_peer(req):
            return self._response(403, {"success": False, "message": "Loopback only"})
        try:
            data = json.loads(req.body.decode("utf-8"))
        except (ValueError, UnicodeError):
            return self._response(400, {"success": False, "message": "Invalid JSON"})
        if not isinstance(data, dict):
            return self._response(400, {"success": False, "message": "JSON object required"})
        operation = data.get("operation")
        if operation == "start":
            status, result = self.monitor.start_dataset_run(
                data.get("run_id"), data.get("generation"),
                data.get("expected_switches", 6))
        elif operation == "stop":
            status, result = self.monitor.stop_dataset_run(
                data.get("run_id"), data.get("generation"))
        elif operation == "status":
            status, result = 200, self.monitor.dataset_run_status()
        else:
            status, result = 400, {"success": False, "message": "Unknown operation"}
        return self._response(status, result)

    @route("dataset_run_status", "/dataset/run/status", methods=["GET"])
    def dataset_run_status(self, req, **kwargs):
        if not self._local_peer(req):
            return self._response(403, {"success": False, "message": "Loopback only"})
        return self._response(200, self.monitor.dataset_run_status())


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

        self.control_token = os.environ.get("SECUREIOT_CONTROL_TOKEN", "")

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

        # PacketIn-derived flow windows used when FlowStats contains only
        # MAC forwarding matches. This is telemetry state, not forwarding.
        self.packet_flow_windows = {}

        # -----------------------------------------------------
        # Action history
        # -----------------------------------------------------

        self.action_history = {}
        self.security_decisions = {}

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

        # Dataset lifecycle state (run identity is immutable and fail-closed).
        self.dataset_lock = hub.Semaphore()
        self.dataset_run = None
        self.used_run_ids = set()
        self.dataset_error = None
        self.dataset_closed = False
        self.flow_requests = {}
        self.flow_request_sequence = 0
        self.flow_used_xids = {}

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
        wsgi.register(
            DatasetRunController,
            {"traffic_monitor": self}
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
    @staticmethod
    def _valid_run_identity(run_id, generation):
        try:
            canonical_uuid = isinstance(run_id, str) and str(uuid.UUID(run_id)) == run_id
        except (ValueError, AttributeError, TypeError):
            canonical_uuid = False
        return canonical_uuid and type(generation) is int and generation >= 0
    def _active_run_matches(self, run):
        """Read the atomically replaced active_run.json and fail closed."""
        try:
            data = json.loads(ACTIVE_RUN_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError):
            return False
        return (isinstance(data, dict)
                and data.get("status") == "active"
                and data.get("run_id") == run.get("run_id")
                and type(data.get("generation")) is int
                and data.get("generation") == run.get("generation"))
    def _ready_datapaths_locked(self):
        return {dpid: dp for dpid, dp in self.datapaths.items()
                if getattr(dp, "state", MAIN_DISPATCHER) == MAIN_DISPATCHER}
    def _dataset_status_locked(self):
        run = self.dataset_run
        if run is None:
            return {"success": not bool(self.dataset_error), "state": "idle",
                    "run_id": None, "generation": None,
                    "connected_switches": len(self._ready_datapaths_locked()),
                    "error": self.dataset_error, "closed": self.dataset_closed}
        return {
            "success": not bool(self.dataset_error or run["drain_errors"]),
            "state": run["state"], "run_id": run["run_id"],
            "generation": run["generation"],
            "expected_switches": run["expected_switches"],
            "connected_switches": len(self._ready_datapaths_locked()),
            "switches": sorted(run["datapaths"]),
            "pending_final_switches": sorted(run["pending_final"]),
            "drain_errors": dict(run["drain_errors"]),
            "started_at": run["started_at"], "stopped_at": run["stopped_at"],
            "drained_at": run["drained_at"], "durable": run["durable"],
            "packet_file": str(run["packet_path"]), "flow_file": str(run["flow_path"]),
            "error": self.dataset_error, "closed": self.dataset_closed,
        }
    def dataset_run_status(self):
        with self.dataset_lock:
            return self._dataset_status_locked()
    def start_dataset_run(self, run_id, generation, expected_switches=6):
        if (not self._valid_run_identity(run_id, generation)
                or type(expected_switches) is not int or expected_switches < 1):
            return 400, {"success": False, "message": "Invalid run identity or expected_switches"}
        with self.dataset_lock:
            if self.dataset_error or self.dataset_closed:
                return 503, {"success": False, "message": self.dataset_error or "Monitor closed"}
            if self.dataset_run and self.dataset_run["state"] != "drained":
                return 409, {"success": False, "message": "An active/draining run already exists"}
            if run_id in self.used_run_ids:
                return 409, {"success": False, "message": "run_id has already been used"}
            candidate = {"run_id": run_id, "generation": generation}
            if not self._active_run_matches(candidate):
                return 409, {"success": False,
                             "message": "active_run.json missing, invalid, inactive, or identity mismatch"}
            datapaths = self._ready_datapaths_locked()
            if len(datapaths) < expected_switches:
                return 409, {"success": False, "message": "Insufficient connected datapaths",
                             "connected_switches": len(datapaths),
                             "expected_switches": expected_switches}
            try:
                packet_handle, flow_handle, packet_path, flow_path = self._open_run_csvs_locked(run_id)
                with open(DATASET_RUN_LEDGER, "a", encoding="utf-8") as ledger:
                    ledger.write(json.dumps({"run_id": run_id, "generation": generation}) + "\n")
                    ledger.flush()
                    os.fsync(ledger.fileno())
                directory = os.open(str(RAW_DATA_ROOT), os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            except Exception as exc:
                for handle in (locals().get("packet_handle"), locals().get("flow_handle")):
                    if handle is not None and not handle.closed:
                        handle.close()
                for path in (locals().get("packet_path"), locals().get("flow_path")):
                    if path is not None:
                        try:
                            path.unlink()
                        except FileNotFoundError:
                            pass
                self.dataset_error = "Run-specific CSV/ledger initialization failed: %s" % exc
                self.logger.exception("Run-specific CSV/ledger initialization failed")
                return 503, {"success": False, "message": self.dataset_error}
            self.used_run_ids.add(run_id)
            self.flow_baselines.clear()
            self.flow_last_seen.clear()
            self.packet_flow_windows.clear()
            self.flow_requests.clear()  # unknown/old replies are dropped, never relabelled
            self.packet_file, self.flow_file = packet_handle, flow_handle
            self.packet_writer, self.flow_writer = csv.writer(packet_handle), csv.writer(flow_handle)
            self.packet_rows_since_flush = self.flow_rows_since_flush = 0
            self.dataset_run = {
                "run_id": run_id, "generation": generation, "state": "active",
                "expected_switches": expected_switches, "datapaths": datapaths,
                "pending_final": {}, "final_done": set(), "last_sequence": {},
                "drain_errors": {}, "issuing_final": False,
                "started_at": time.time(), "stopped_at": None,
                "drained_at": None, "durable": False,
                "packet_path": packet_path, "flow_path": flow_path,
                "packet_observation_sequence": 0, "flow_observation_sequence": 0,
            }
            result = self._dataset_status_locked()
            result["ack"] = "started"
            return 200, result
    def stop_dataset_run(self, run_id, generation):
        if not self._valid_run_identity(run_id, generation):
            return 400, {"success": False, "message": "run_id and generation are required"}
        with self.dataset_lock:
            if self.dataset_closed:
                return 503, {"success": False, "message": "Monitor closed"}
            run = self.dataset_run
            if not run or (run_id, generation) != (run["run_id"], run["generation"]):
                return 409, {"success": False, "message": "Run identity does not match"}
            if run["state"] != "active":
                # Idempotent stop; never issue a second final request.
                return 200, self._dataset_status_locked()
            run["state"] = "draining"
            run["stopped_at"] = time.time()
            run["issuing_final"] = True
            # Include newly connected switches as well as original participants.
            for dpid, dp in self._ready_datapaths_locked().items():
                if dpid not in run["datapaths"]:
                    run["datapaths"][dpid] = dp
                elif run["datapaths"][dpid] is not dp:
                    run["drain_errors"][str(dpid)] = "Datapath reconnected during run"
            run["pending_final"] = {dpid: None for dpid in run["datapaths"]}
            for dpid, dp in list(run["datapaths"].items()):
                if self.datapaths.get(dpid) is not dp or getattr(dp, "state", MAIN_DISPATCHER) != MAIN_DISPATCHER:
                    run["drain_errors"][str(dpid)] = "Datapath disconnected; final reply unavailable"
                    continue
                try:
                    self._request_flow_stats_locked(dp, run, final=True)
                except Exception as exc:
                    run["drain_errors"][str(dpid)] = "Final request failed: %s" % exc
                    self.logger.exception("Final FlowStats request failed on s%d", dpid)
            run["issuing_final"] = False
            self._maybe_finish_dataset_run_locked(run)
            return 200, self._dataset_status_locked()
    def _maybe_finish_dataset_run_locked(self, run):
        if (self.dataset_run is not run or run["state"] != "draining"
                or run["issuing_final"] or run["pending_final"]
                or run["drain_errors"] or self.dataset_error or self.dataset_closed):
            return
        try:
            # PacketIn window rows are included in the run before fsync/drained.
            self._flush_packet_flow_windows_locked(run)
            with self.csv_lock:
                for handle in (self.packet_file, self.flow_file):
                    if handle is not None and not handle.closed:
                        handle.flush()
                        os.fsync(handle.fileno())
                        handle.close()
                for directory_path in (PACKET_DATA_DIR, FLOW_DATA_DIR):
                    directory_fd = os.open(str(directory_path), os.O_RDONLY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                self.packet_rows_since_flush = self.flow_rows_since_flush = 0
        except Exception as exc:
            self.dataset_error = "Dataset flush/fsync failed: %s" % exc
            self.logger.exception("Dataset drain failed")
            return  # fail closed: never report drained before durable output
        self.flow_requests.clear()
        run["durable"] = True
        run["drained_at"] = time.time()
        run["state"] = "drained"
    def _packet_run_context(self):
        with self.dataset_lock:
            run = self.dataset_run
            return run if (run and run["state"] == "active"
                           and not self.dataset_error and not self.dataset_closed) else None
    def _validate_run_files(self, directory, header):
        run_ids = set()
        for path in sorted(directory.glob("*.csv")):
            run_id = path.stem
            if not self._valid_run_identity(run_id, 0):
                raise ValueError("Unsafe/noncanonical run filename: %s" % path.name)
            with path.open(newline="", encoding="utf-8") as handle:
                reader = csv.reader(handle, strict=True)
                actual = next(reader, None)
                if actual != header:
                    raise ValueError("CSV header mismatch: %s" % path)
                observation_ids = set()
                for row in reader:
                    if (len(row) != len(header) or row[0] != run_id
                            or not row[1] or row[1] in observation_ids):
                        raise ValueError("Invalid row/run_id/observation_id in %s" % path)
                    observation_ids.add(row[1])
            if not self._terminated_csv(path):
                raise ValueError("Unterminated CSV record in %s" % path)
            run_ids.add(run_id)
        return run_ids
    @staticmethod
    def _terminated_csv(path):
        size = path.stat().st_size
        if size == 0:
            return False
        with path.open("rb") as raw:
            raw.seek(-1, os.SEEK_END)
            return raw.read(1) in (b"\n", b"\r")
    def _open_run_csvs_locked(self, run_id):
        """Exclusively create this run's packet and flow files before ACK."""
        if not self._valid_run_identity(run_id, 0):
            raise ValueError("run_id must be a canonical UUID")
        packet_path = PACKET_DATA_DIR / (run_id + ".csv")
        flow_path = FLOW_DATA_DIR / (run_id + ".csv")
        if packet_path.exists() or flow_path.exists():
            raise FileExistsError("run-specific output already exists for %s" % run_id)
        packet_handle = flow_handle = None
        try:
            packet_handle = packet_path.open("x", newline="", encoding="utf-8")
            flow_handle = flow_path.open("x", newline="", encoding="utf-8")
            packet_writer = csv.writer(packet_handle)
            flow_writer = csv.writer(flow_handle)
            packet_writer.writerow(PACKET_HEADER)
            flow_writer.writerow(FLOW_HEADER)
            for handle in (packet_handle, flow_handle):
                handle.flush()
                os.fsync(handle.fileno())
            for directory_path in (PACKET_DATA_DIR, FLOW_DATA_DIR):
                directory_fd = os.open(str(directory_path), os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            return packet_handle, flow_handle, packet_path, flow_path
        except Exception:
            for handle in (packet_handle, flow_handle):
                if handle is not None and not handle.closed:
                    handle.close()
            # A different monitor process may create the other path between
            # the initial exists check and the exclusive open. Only remove
            # the path whose handle proves this call created it.
            for handle, path in ((packet_handle, packet_path), (flow_handle, flow_path)):
                if handle is None:
                    continue
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            raise
    def _request_flow_stats_locked(self, datapath, run, final=False):
        request = datapath.ofproto_parser.OFPFlowStatsRequest(datapath)
        # send_msg normally assigns xid. Assign it first to register ownership
        # BEFORE send_msg can yield or a fast reply can arrive.
        used = self.flow_used_xids.setdefault(datapath, set())
        for _ in range(len(used) + 1):
            datapath.set_xid(request)
            if request.xid not in used:
                break
        else:
            raise RuntimeError("FlowStats xid allocation did not advance")
        key = (id(datapath), request.xid)
        if key in self.flow_requests:
            raise RuntimeError("Pending FlowStats xid collision")
        used.add(request.xid)
        self.flow_request_sequence += 1
        owner = {"run": run, "run_id": run["run_id"],
                 "generation": run["generation"], "datapath": datapath,
                 "sequence": self.flow_request_sequence, "final": final,
                 "body": []}
        self.flow_requests[key] = owner
        if final:
            run["pending_final"][datapath.id] = key
        try:
            if datapath.send_msg(request) is False:
                raise RuntimeError("Datapath rejected FlowStats request")
        except Exception:
            self.flow_requests.pop(key, None)
            if final:
                run["pending_final"][datapath.id] = None
            raise
        return request.xid
    def _process_flow_stats_locked(self, datapath, body, run):
        dpid = datapath.id
        now = time.time()

        for stat in body:

            # -------------------------------------------------
            # Ignore table-miss.
            # -------------------------------------------------

            if stat.priority == TABLE_MISS_PRIORITY:

                continue

            match = stat.match
            src_mac = (match.get("eth_src", "") or "").lower()
            dst_mac = (match.get("eth_dst", "") or "").lower()

            # -------------------------------------------------
            # IPv4 flow fields (present only when the OpenFlow
            # rule itself matches IPv4 fields).
            # -------------------------------------------------

            src_ip = (match.get("ipv4_src", "") or match.get("ipv6_src", "") or "")
            dst_ip = (match.get("ipv4_dst", "") or match.get("ipv6_dst", "") or "")

            # MAC-based OpenFlow rules do not carry IP fields in FlowStats.
            # Enrich from the MAC/IP pairs already observed in real packets;
            # never synthesize an address when the monitor has no mapping.
            if not src_ip and src_mac:
                src_ip = self.mac_to_ip.get(src_mac, "")
            if not dst_ip and dst_mac:
                dst_ip = self.mac_to_ip.get(dst_mac, "")

            protocol = match.get("ip_proto", "")
            try:
                protocol_number = int(protocol)
            except (TypeError, ValueError):
                protocol_number = -1

            src_port = ""
            dst_port = ""

            # -------------------------------------------------
            # TCP
            # -------------------------------------------------

            if protocol_number == 6:

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

            elif protocol_number == 17:

                src_port = match.get(
                    "udp_src",
                    ""
                )

                dst_port = match.get(
                    "udp_dst",
                    ""
                )

            # -------------------------------------------------
            # Keep L2 flows too. A switch rule may match only MAC
            # addresses, so its FlowStats match has no IPv4 fields.
            # -------------------------------------------------

            if not (src_ip or dst_ip or src_mac or dst_mac):
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
                run["run_id"], run["generation"], id(datapath),
                dpid,
                stat.priority,
                src_ip,
                dst_ip,
                src_mac,
                dst_mac,
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

            flow_row_written = self._write_flow_feature_locked([
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
                duration_sec,
                byte_count / max(packet_count, 1),
                0, 0, 0, 0, 0.0, 0.0, 0, 0,
                float(protocol_number == 6), float(protocol_number == 17), float(protocol_number == 1),
                "switch_flow_stats", src_mac, dst_mac
            ], run)

            # Shadow API is telemetry-only. Submit only a single valid TCP/UDP
            # destination port; never select an arbitrary port from an ambiguous flow.
            if (flow_row_written
                   and submit_flow_live is not None
                   and protocol_number in (6, 17)
                   and src_ip and dst_ip and time_delta > 0 and packet_delta > 0):
                try:
                    destination_port = int(dst_port)
                except (TypeError, ValueError):
                    destination_port = 0
                if 1 <= destination_port <= 65535:
                    try:
                        queued = submit_flow_live({
                            "run_id": run["run_id"],
                            "observation_id": "%s_switch_%d_%s" % (
                                run["run_id"], dpid, uuid.uuid4().hex),
                            "src_ip": str(src_ip),
                            "dst_ip": str(dst_ip),
                            "dst_port": destination_port,
                            "protocol": "TCP" if protocol_number == 6 else "UDP",
                            "ip_proto": protocol_number,
                            "packet_count": int(packet_delta),
                            "byte_count": int(byte_delta),
                            "packet_rate": float(packet_rate),
                            "byte_rate": float(byte_rate),
                            "duration_sec": float(max(time_delta, 0.001)),
                            "switch_dpid": int(dpid),
                            "priority": int(stat.priority),
                        })
                        if not queued:
                            self.logger.debug("Shadow API did not queue switch-flow observation")
                    except Exception as exc:
                        self.logger.warning("Shadow API switch-flow submission failed: %s", exc)
    def _flush_packet_flow_windows_locked(self, run=None):
        """Flush windows while dataset_lock is already held."""
        for key, state in list(self.packet_flow_windows.items()):
            if run is None or state["run"] is run:
                self._write_packet_flow_window(key, state, lock_held=True)
                self.packet_flow_windows.pop(key, None)
    def _flush_packet_flow_windows(self):
        with self.dataset_lock:
            current = self.dataset_run
            if current and current["state"] in ("active", "draining"):
                self._flush_packet_flow_windows_locked(current)
    def _flush_expired_packet_flow_windows(self):
        now = time.time()
        with self.dataset_lock:
            for key, state in list(self.packet_flow_windows.items()):
                run = state["run"]
                if (self.dataset_run is run and run["state"] in ("active", "draining")
                        and now - state["start_time"] >= PACKET_FLOW_WINDOW):
                    self._write_packet_flow_window(key, state, lock_held=True)
                    self.packet_flow_windows.pop(key, None)
    def _write_flow_feature_locked(self, row, run):
        if (run is None or self.dataset_run is not run
                or run["state"] not in ("active", "draining")
                or self.dataset_error or self.dataset_closed):
            return False
        if not self._active_run_matches(run):
            self.dataset_error = "active_run.json missing/invalid or run identity mismatch"
            self.logger.error(self.dataset_error)
            return False
        with self.csv_lock:
            if len(row) != len(FLOW_HEADER) - 2:
                raise ValueError("Flow row schema mismatch")
            run["flow_observation_sequence"] += 1
            observation_id = "%s_flow_%08d" % (run["run_id"], run["flow_observation_sequence"])
            self.flow_writer.writerow([run["run_id"], observation_id] + list(row))
            self.flow_rows_since_flush += 1
            if self.flow_rows_since_flush >= CSV_FLUSH_EVERY:
                self.flow_file.flush()
                self.flow_rows_since_flush = 0
        return observation_id
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
    def _initialize_csv_files(self):
        """Prepare per-run raw directories and validate all existing run files."""
        try:
            RAW_DATA_ROOT.mkdir(parents=True, exist_ok=True)
            PACKET_DATA_DIR.mkdir(parents=True, exist_ok=True)
            FLOW_DATA_DIR.mkdir(parents=True, exist_ok=True)
            SHADOW_API_DATA_DIR.mkdir(parents=True, exist_ok=True)
            packet_ids = self._validate_run_files(PACKET_DATA_DIR, PACKET_HEADER)
            flow_ids = self._validate_run_files(FLOW_DATA_DIR, FLOW_HEADER)
            if packet_ids != flow_ids:
                raise ValueError("packet/flow run file sets differ")
            self.used_run_ids.update(packet_ids)
            if DATASET_RUN_LEDGER.exists():
                with DATASET_RUN_LEDGER.open(encoding="utf-8") as ledger:
                    reservations = set()
                    for line in ledger:
                        if not line.endswith("\n"):
                            raise ValueError("Unterminated dataset run reservation")
                        record = json.loads(line)
                        if (not isinstance(record, dict)
                                or not self._valid_run_identity(record.get("run_id"), record.get("generation"))
                                or record["run_id"] in reservations):
                            raise ValueError("Invalid/duplicate dataset run reservation")
                        reservations.add(record["run_id"])
                    self.used_run_ids.update(reservations)
        except Exception:
            self.dataset_error = "Run-specific CSV/ledger initialization failed"
            raise
    @handler.set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
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
    @handler.set_ev_cls(
        ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
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
    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(
        self,
        ev
    ):

        # Capture at handler entry; never assign a queued packet to a later run.
        packet_run = self._packet_run_context()
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

        # Collection uses the same validated access/trunk port map as the
        # forwarding owner.  Without it, fail closed: do not append telemetry
        # from an unknown port, stale topology, or a source outside its zone.
        topology = self._get_topology_monitor()
        if topology is None or not topology.vlan_map_ready:
            return
        try:
            in_port = int(in_port)
        except (TypeError, ValueError):
            return
        vlan_id = topology._resolve_ingress_vlan(
            datapath, in_port, msg, pkt)
        if vlan_id is None or not topology._source_ip_allowed(
            vlan_id, pkt, datapath, in_port
        ):
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

        packet_timestamp = time.time()
        self._write_packet_feature([
            packet_timestamp,
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
        ], packet_run)

        # This telemetry-only aggregation complements switch FlowStats; it
        # never emits PacketOut or installs a flow. Each window retains the
        # run object captured at PacketIn entry, preventing cross-run labels.
        if packet_run is not None and ipv4_pkt is not None:
            self._update_packet_flow_window(
                packet_timestamp, packet_run, dpid, src_ip, dst_ip,
                src_port, dst_port, protocol, packet_length, tcp_flags
            )

        # -----------------------------------------------------
        # New hosts start as UNTRUSTED.
        # -----------------------------------------------------

        if src_ip:

            if src_ip not in self.trust_state:

                self.trust_state[
                    src_ip
                ] = UNTRUSTED
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
    def _update_packet_flow_window(self, now, run, dpid, src_ip, dst_ip,
                                   src_port, dst_port, protocol,
                                   packet_length, tcp_flags):
        """Aggregate observed IPv4 packets into run-scoped flow windows."""
        try:
            protocol = int(protocol)
            src_addr, dst_addr = ipaddress.ip_address(src_ip), ipaddress.ip_address(dst_ip)
        except (TypeError, ValueError):
            return
        if (src_addr.version != 4 or dst_addr.version != 4
                or src_addr.is_multicast or dst_addr.is_multicast
                or protocol not in (1, 6, 17)):
            return
        identity = (run["run_id"], run["generation"])
        key = identity + (
            dpid, str(src_addr), str(dst_addr), protocol,
            str(src_port or ""), str(dst_port or ""),
        )
        state = self.packet_flow_windows.get(key)
        if state is None or now - state["start_time"] >= PACKET_FLOW_WINDOW:
            if state is not None:
                self._write_packet_flow_window(key, state)
            state = {"run": run, "start_time": now, "last_time": now,
                     "packet_count": 0, "byte_count": 0, "syn_count": 0,
                     "ack_count": 0, "rst_count": 0, "fin_count": 0,
                     "src_ports": set(), "dst_ports": set()}
            self.packet_flow_windows[key] = state
        state["last_time"] = now
        state["packet_count"] += 1
        state["byte_count"] += int(packet_length or 0)
        if src_port not in ("", None): state["src_ports"].add(str(src_port))
        if dst_port not in ("", None): state["dst_ports"].add(str(dst_port))
        try: flags = int(tcp_flags or 0)
        except (TypeError, ValueError): flags = 0
        state["syn_count"] += int(bool(flags & 0x02))
        state["ack_count"] += int(bool(flags & 0x10))
        state["rst_count"] += int(bool(flags & 0x04))
        state["fin_count"] += int(bool(flags & 0x01))
    def _write_packet_flow_window(self, key, state, lock_held=False):
        if not state or state["packet_count"] <= 0:
            return False
        _, _, dpid, src_ip, dst_ip, protocol, _, _ = key
        run = state["run"]
        if self.dataset_run is not run or run["state"] not in ("active", "draining"):
            return False
        end_time = state["last_time"]
        duration = max(end_time - state["start_time"], 0.001)
        packets, byte_count = state["packet_count"], state["byte_count"]
        syn, ack, rst = state["syn_count"], state["ack_count"], state["rst_count"]
        name = {6: "tcp", 17: "udp", 1: "icmp"}.get(protocol, str(protocol))
        row = [end_time, dpid, src_ip, dst_ip,
               next(iter(state["src_ports"])) if len(state["src_ports"]) == 1 else "",
               next(iter(state["dst_ports"])) if len(state["dst_ports"]) == 1 else "",
               name, 0, packets, byte_count, packets / duration, byte_count / duration,
               duration, byte_count / max(packets, 1), syn, ack, rst, state["fin_count"],
               syn / max(ack, 1), rst / max(packets, 1), len(state["dst_ports"]),
               max(syn - ack, 0), float(protocol == 6), float(protocol == 17),
               float(protocol == 1), "packetin_window", "", ""]
        if lock_held:
            written = self._write_flow_feature_locked(row, run)
        else:
            written = self._write_flow_feature(row, run)
        if not written:
            return False

        # Submit only complete TCP/UDP observations. The API client queues
        # telemetry asynchronously; its verdict never controls enforcement.
        if protocol in (6, 17) and submit_flow_live is not None:
            try:
                source_port = int(next(iter(state["src_ports"])))
                destination_port = int(next(iter(state["dst_ports"])))
            except (StopIteration, TypeError, ValueError):
                source_port = destination_port = 0

            if (1 <= source_port <= 65535
                    and 1 <= destination_port <= 65535):
                try:
                    queued = submit_flow_live({
                        "run_id": run["run_id"],
                        "observation_id": written,
                        "src_ip": str(src_ip),
                        "dst_ip": str(dst_ip),
                        "dst_port": destination_port,
                        "protocol": "TCP" if protocol == 6 else "UDP",
                        "ip_proto": int(protocol),
                        "packet_count": int(packets),
                        "byte_count": int(byte_count),
                        "packet_rate": float(packets / duration),
                        "byte_rate": float(byte_count / duration),
                        "duration_sec": float(duration),
                        "switch_dpid": int(dpid),
                        "priority": 0,
                    })
                    if not queued:
                        self.logger.debug(
                            "Shadow API did not queue PacketIn observation"
                        )
                except Exception as exc:
                    self.logger.warning(
                        "Shadow API PacketIn submission failed: %s", exc
                    )

        return True
    def _flow_stats_loop(self):
        while True:
            try:
                with self.dataset_lock:
                    datapaths = list(self._ready_datapaths_locked().values())
                    closed = self.dataset_closed
                if closed:
                    return
                for datapath in datapaths:
                    self._request_flow_stats(datapath)
                self._cleanup_stale_flows()
                self._flush_expired_packet_flow_windows()
            except Exception as exc:
                self.logger.exception("FlowStats loop error: %s", exc)
            hub.sleep(FLOW_POLL_INTERVAL)
    def _request_flow_stats(self, datapath):
        with self.dataset_lock:
            run = self.dataset_run
            if (not run or run["state"] != "active"
                    or self.dataset_error or self.dataset_closed):
                return None
            if self.datapaths.get(datapath.id) is not datapath:
                return None
            owner = run["datapaths"].get(datapath.id)
            if owner is None:
                run["datapaths"][datapath.id] = datapath
            elif owner is not datapath:
                run["drain_errors"][str(datapath.id)] = "Datapath reconnected during run"
                return None
            # Bound pending polls: one multipart request per connection.
            if any(r["datapath"] is datapath and r["run"] is run
                   for r in self.flow_requests.values()):
                return None
            return self._request_flow_stats_locked(datapath, run)
    @handler.set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        key = (id(datapath), msg.xid)
        with self.dataset_lock:
            owner = self.flow_requests.get(key)
            run = self.dataset_run
            if (not owner or owner["datapath"] is not datapath
                    or owner["run"] is not run or not run
                    or (owner["run_id"], owner["generation"]) != (run["run_id"], run["generation"])
                    or run["state"] not in ("active", "draining")
                    or self.dataset_error or self.dataset_closed):
                return  # unsolicited, stale generation/run, or closed collection
            owner["body"].extend(msg.body)
            if msg.flags & datapath.ofproto.OFPMPF_REPLY_MORE:
                return  # no delta and no drain completion before the last part
            self.flow_requests.pop(key, None)
            dpid = datapath.id
            if dpid in run["final_done"]:
                return
            if owner["sequence"] > run["last_sequence"].get(dpid, -1):
                try:
                    self._process_flow_stats_locked(datapath, owner["body"], run)
                    run["last_sequence"][dpid] = owner["sequence"]
                except Exception as exc:
                    self.dataset_error = "FlowStats processing/write failed: %s" % exc
                    self.logger.exception("FlowStats processing failed")
                    return
            if owner["final"] and run["pending_final"].get(dpid) == key:
                run["pending_final"].pop(dpid)
                run["final_done"].add(dpid)
                # Older polls can neither alter the baseline nor write after
                # this connection's final snapshot, even if delivered later.
                for pending, item in list(self.flow_requests.items()):
                    if item["run"] is run and item["datapath"] is datapath:
                        self.flow_requests.pop(pending, None)
                self._maybe_finish_dataset_run_locked(run)
    def _write_packet_feature(self, row, run=None):
        with self.dataset_lock:
            if (run is None or self.dataset_run is not run or run["state"] != "active"
                    or self.dataset_error or self.dataset_closed):
                return False
            if not self._active_run_matches(run):
                self.dataset_error = "active_run.json missing/invalid or run identity mismatch"
                self.logger.error(self.dataset_error)
                return False
            try:
                with self.csv_lock:
                    if len(row) != len(PACKET_HEADER) - 2:
                        raise ValueError("Packet row schema mismatch")
                    run["packet_observation_sequence"] += 1
                    observation_id = "%s_packet_%08d" % (run["run_id"], run["packet_observation_sequence"])
                    self.packet_writer.writerow([run["run_id"], observation_id] + list(row))
                    self.packet_rows_since_flush += 1
                    if self.packet_rows_since_flush >= CSV_FLUSH_EVERY:
                        self.packet_file.flush()
                        self.packet_rows_since_flush = 0
                return True
            except Exception as exc:
                self.dataset_error = "Packet dataset write failed: %s" % exc
                self.logger.exception("Packet dataset write failed")
                return False  # preserve packet learning / ZT behavior, stop collection
    def _write_flow_feature(self, row, run=None):
        with self.dataset_lock:
            return self._write_flow_feature_locked(row, run)
    def _cleanup_stale_flows(self):
        with self.dataset_lock:
            now = time.time()
            stale_keys = [key for key, seen in self.flow_last_seen.items()
                          if now - seen > STALE_FLOW_MAX_AGE]
            for key in stale_keys:
                self.flow_last_seen.pop(key, None)
                self.flow_baselines.pop(key, None)
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
    def update_trust_state(self, host_ip, state, trust_score=None):
        if state not in {TRUSTED, UNTRUSTED}:
            return {"success": False, "message": "Invalid trust state: %s" % state}
        self.trust_state[host_ip] = state
        if trust_score is not None:
            self.trust_scores[host_ip] = trust_score
        return {"success": True, "host_ip": host_ip,
                "trust_state": state, "trust_score": trust_score}
    def handle_security_decision(self, payload):
        """Map Security's BLOCK/NOT_BLOCK decision to network behavior."""
        if not isinstance(payload, dict):
            return {"success": False, "status": "rejected",
                    "message": "Security payload must be a JSON object"}
        decision = str(payload.get("decision", "")).strip().upper()
        if decision not in {"BLOCK", "NOT_BLOCK"}:
            return {"success": False, "status": "rejected",
                    "message": "decision must be BLOCK or NOT_BLOCK"}
        request_id = payload.get("request_id") or (
            "SECURITY-%d" % int(time.time() * 1000)
        )
        src = payload.get("src") or payload.get("source_ip")
        dst = payload.get("dst") or payload.get("destination_ip")
        mac = payload.get("mac")
        telemetry = {
            "src": src, "dst": dst,
            "src_port": payload.get("src_port"),
            "dst_port": payload.get("dst_port"),
            "packets": payload.get("packets"),
            "rate": payload.get("rate"),
            "mac": mac, "decision": decision,
            "reason": payload.get("reason"),
            "request_id": request_id, "timestamp": time.time()
        }
        if decision == "NOT_BLOCK":
            self.security_decisions[request_id] = telemetry
            self._record_action(request_id, src, "NOT_BLOCK", "recorded",
                                payload.get("reason"), mac)
            return {"success": True, "status": "recorded",
                    "decision": decision, "action": "NONE",
                    "request_id": request_id, "telemetry": telemetry}
        if not mac or not src:
            return {"success": False, "status": "rejected",
                    "message": "src and mac are required for BLOCK"}
        result = self.execute_security_action(
            host_ip=src, mac=mac, action=ACTION_BLOCK_DEVICE,
            request_id=request_id, reason=payload.get("reason"))
        execution_result = dict(result)
        telemetry["action"] = "BLOCK_DEVICE"
        telemetry["execution"] = execution_result
        self.security_decisions[request_id] = telemetry
        result.update({"decision": decision, "telemetry": telemetry})
        return result
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
    def close(self):
        with self.dataset_lock:
            run = self.dataset_run
            if run and run["state"] in ("active", "draining"):
                self._flush_packet_flow_windows_locked(run)
            self.dataset_closed = True
            self.flow_requests.clear()
            try:
                with self.csv_lock:
                    for handle in (self.packet_file, self.flow_file):
                        if handle is not None and not handle.closed:
                            handle.flush()
                            os.fsync(handle.fileno())
                            handle.close()
            except Exception as exc:
                self.dataset_error = "Dataset close failed: %s" % exc
                self.logger.exception("Dataset close failed")
            # close is not a substitute for stop + complete final replies.
        self.logger.info("TrafficMonitorMerged closed")
        super(TrafficMonitorMerged, self).close()
