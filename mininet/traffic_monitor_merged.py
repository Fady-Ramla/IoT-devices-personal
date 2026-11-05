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
import ipaddress
import json
import os
from pathlib import Path
import re
import threading
import uuid
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
    ACTION_REROUTE
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

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ACTIVE_RUN_FILE = Path(os.environ.get("SECUREIOT_ACTIVE_RUN_FILE", str(PROJECT_ROOT / "New_Datasets" / "active_run.json"))).expanduser().resolve()
RAW_DATA_ROOT = Path(os.environ.get("SECUREIOT_RAW_DATA_ROOT", str(PROJECT_ROOT / "New_Datasets" / "raw"))).expanduser().resolve()
PACKET_DATA_DIR = RAW_DATA_ROOT / "packet"
FLOW_DATA_DIR = RAW_DATA_ROOT / "flow"
# Durable reservation also prevents reusing an acknowledged run with no rows.
DATASET_RUN_LEDGER = RAW_DATA_ROOT / ".dataset_run_ids.jsonl"

# Preserve the established schemas and prepend run/observation identity.
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

FLOW_POLL_INTERVAL = 2.0
PACKET_FLOW_WINDOW = 10.0

FLOW_IDLE_TIMEOUT = 15
STALE_FLOW_MAX_AGE = 60

CSV_FLUSH_EVERY = 50

NORMAL_PRIORITY = 10
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

        mac = data.get(
            "mac"
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

        normalized_action = str(action).strip().upper()
        device_action = normalized_action in (
            ACTION_BLOCK_DEVICE, ACTION_UNBLOCK_DEVICE
        )
        if device_action and not mac:
            return Response(
                status=400,
                content_type="application/json",
                body=json.dumps({
                    "success": False,
                    "status": "error",
                    "message": "mac is required for BLOCK_DEVICE/UNBLOCK_DEVICE"
                })
            )
        if not device_action and not host_ip:
            return Response(
                status=400,
                content_type="application/json",
                body=json.dumps({
                    "success": False,
                    "status": "error",
                    "message": "host_ip is required for this action"
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
                mac=mac,
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

        # Explicit device blocks are owned by TopologyMonitor and keyed by MAC.

        # -----------------------------------------------------
        # Flow monitoring
        # -----------------------------------------------------

        self.flow_baselines = {}

        self.flow_last_seen = {}
        # PacketIn-derived flow windows are isolated by immutable run identity.
        self.packet_flow_windows = {}

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
        # Ryu handlers and WSGI run in different greenlets. A native RLock
        # would NOT serialize them when they share an OS thread.
        self.dataset_lock = hub.Semaphore()
        self.dataset_run = None
        self.used_run_ids = set()
        self.dataset_error = None
        self.dataset_closed = False
        self.flow_requests = {}  # (connection identity, xid) -> immutable run owner
        self.flow_request_sequence = 0
        # Retain connections/used xids for this controller lifetime. An xid
        # wrapped or reset by the transport must not correlate an old reply
        # with a request belonging to a later run on the same connection.
        self.flow_used_xids = {}

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

        wsgi.register(DatasetRunController, {"traffic_monitor": self})

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

        self.logger.info("Run-specific packet CSV directory: %s", PACKET_DATA_DIR)
        self.logger.info("Run-specific flow CSV directory: %s", FLOW_DATA_DIR)

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
    # DATASET RUN LIFECYCLE (all *_locked helpers require dataset_lock)
    # =========================================================

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

    def _initialize_csv_files(self):
        """Prepare per-run raw directories and validate all existing run files."""
        try:
            RAW_DATA_ROOT.mkdir(parents=True, exist_ok=True)
            PACKET_DATA_DIR.mkdir(parents=True, exist_ok=True)
            FLOW_DATA_DIR.mkdir(parents=True, exist_ok=True)
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

        with self.dataset_lock:
            self.datapaths[datapath.id] = datapath

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
        [MAIN_DISPATCHER, DEAD_DISPATCHER]
    )
    def state_change_handler(self, ev):
        datapath = ev.datapath
        with self.dataset_lock:
            if ev.state == MAIN_DISPATCHER:
                self.datapaths[datapath.id] = datapath
                run = self.dataset_run
                if run and run["state"] == "active":
                    old = run["datapaths"].get(datapath.id)
                    if old is not None and old is not datapath:
                        run["drain_errors"][str(datapath.id)] = "Datapath reconnected during run"
                    else:
                        run["datapaths"][datapath.id] = datapath
                self.logger.info("Datapath registered: s%d", datapath.id)
            elif ev.state == DEAD_DISPATCHER:
                # A delayed DEAD for an old connection must not remove a new one.
                if self.datapaths.get(datapath.id) is datapath:
                    del self.datapaths[datapath.id]
                run = self.dataset_run
                if (run and run["state"] in ("active", "draining")
                        and run["datapaths"].get(datapath.id) is datapath):
                    run["drain_errors"][str(datapath.id)] = "Datapath disconnected during run"
                self.logger.info("Datapath removed: s%d", datapath.id)


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


        # -----------------------------------------------------
        # Forwarding ownership
        # -----------------------------------------------------
        # TopologyMonitor is the sole forwarding owner. This app only captures
        # packet features; emitting PacketOut here would duplicate forwarding.

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
    # PACKET-IN FLOW WINDOW FEATURES
    # =========================================================
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
        key = identity + (dpid, str(src_addr), str(dst_addr), protocol)
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
        _, _, dpid, src_ip, dst_ip, protocol = key
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
            return self._write_flow_feature_locked(row, run)
        return self._write_flow_feature(row, run)

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

    # =========================================================
    # FLOW STATS LOOP
    # =========================================================

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

    # =========================================================
    # REQUEST FLOW STATS
    # =========================================================

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

    # =========================================================
    # FLOW STATS REPLY
    # =========================================================

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

            self._write_flow_feature_locked([
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
                float(protocol == 6), float(protocol == 17), float(protocol == 1),
                "switch_flow_stats", src_mac, dst_mac
            ], run)

    # =========================================================
    # WRITE PACKET FEATURE
    # =========================================================

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

    # =========================================================
    # WRITE FLOW FEATURE
    # =========================================================

    def _write_flow_feature(self, row, run=None):
        with self.dataset_lock:
            return self._write_flow_feature_locked(row, run)

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
        return True

    # =========================================================
    # CLEANUP STALE FLOWS
    # =========================================================

    def _cleanup_stale_flows(self):
        with self.dataset_lock:
            now = time.time()
            stale_keys = [key for key, seen in self.flow_last_seen.items()
                          if now - seen > STALE_FLOW_MAX_AGE]
            for key in stale_keys:
                self.flow_last_seen.pop(key, None)
                self.flow_baselines.pop(key, None)

    # =========================================================
    # UPDATE TRUST STATE (used by the security action API)
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
    # VALIDATE NETWORK DECISION
    # =========================================================

    def _validate_network_decision(
        self,
        host_ip,
        action,
        mac=None,
        trust_state=None,
        trust_score=None,
        reason=None
    ):
        """Validate trust decisions separately from explicit device enforcement."""
        action = str(action).strip().upper()
        valid = {
            ACTION_ALLOW,
            ACTION_KEEP_UNTRUSTED,
            ACTION_BLOCK_DEVICE,
            ACTION_UNBLOCK_DEVICE,
            ACTION_REROUTE,
        }
        if action not in valid:
            return {"valid": False, "message": "Invalid action: %s" % action}

        is_device_action = action in (ACTION_BLOCK_DEVICE, ACTION_UNBLOCK_DEVICE)
        if is_device_action:
            if trust_state is not None or trust_score is not None:
                return {
                    "valid": False,
                    "message": "Device block/unblock is explicit and must not be inferred from trust state/score"
                }
            try:
                device = self.decision_validator.validate_device_action(
                    action, mac, ip=host_ip
                )
            except (TypeError, ValueError) as exc:
                return {"valid": False, "message": str(exc)}
            return {
                "valid": True,
                "host_ip": device["ip"],
                "mac": device["mac"],
                "action": device["action"],
                "trust_state": None,
                "trust_score": None,
                "reason": reason,
            }

        if not host_ip:
            return {"valid": False, "message": "host_ip is required for this action"}

        if trust_state is None or trust_score is None:
            return {
                "valid": False,
                "message": "trust_state and trust_score are required for ALLOW/KEEP_UNTRUSTED/REROUTE"
            }

        try:
            self.decision_validator.validate_decision(
                trust_score=trust_score,
                trust_state=trust_state,
                action=action,
            )
        except (TypeError, ValueError) as exc:
            return {"valid": False, "message": str(exc)}

        return {
            "valid": True,
            "host_ip": host_ip,
            "mac": mac,
            "action": action,
            "trust_state": trust_state,
            "trust_score": trust_score,
            "reason": reason,
        }

    # =========================================================
    # EXECUTE SECURITY ACTION
    # =========================================================

    def execute_security_action(
        self,
        host_ip,
        action,
        request_id=None,
        mac=None,
        trust_state=None,
        trust_score=None,
        reason=None
    ):
        action = str(action).strip().upper()
        validation = self._validate_network_decision(
            host_ip=host_ip,
            action=action,
            mac=mac,
            trust_state=trust_state,
            trust_score=trust_score,
            reason=reason,
        )
        if not validation["valid"]:
            self.logger.warning(
                "Security decision rejected: %s", validation["message"]
            )
            return {
                "success": False,
                "status": "rejected",
                "message": validation["message"],
                "host_ip": host_ip,
                "mac": mac,
                "action": action,
            }

        host_ip = validation["host_ip"]
        mac = validation["mac"]

        if action in (ACTION_BLOCK_DEVICE, ACTION_UNBLOCK_DEVICE):
            topology = self._get_topology_monitor()
            if topology is None:
                return {
                    "success": False,
                    "status": "unavailable",
                    "message": "TopologyMonitor is not available",
                    "host_ip": host_ip,
                    "mac": mac,
                    "action": action,
                }
            if action == ACTION_BLOCK_DEVICE:
                return topology.block_device(
                    mac=mac, ip=host_ip, request_id=request_id, reason=reason
                )
            return topology.unblock_device(
                mac=mac, ip=host_ip, request_id=request_id, reason=reason
            )

        if trust_score is not None:
            self.trust_scores[host_ip] = float(trust_score)

        if trust_state is not None:
            state_result = self.update_trust_state(
                host_ip, trust_state, trust_score
            )
            if not state_result["success"]:
                return state_result

        if action == ACTION_KEEP_UNTRUSTED:
            if host_ip not in self.trust_state:
                self.trust_state[host_ip] = UNTRUSTED
            self._record_action(
                request_id=request_id, host_ip=host_ip, action=action,
                status="executed", reason=reason
            )
            return {
                "success": True, "status": "executed", "action": action,
                "host_ip": host_ip, "request_id": request_id
            }

        if action == ACTION_ALLOW:
            self.trust_state[host_ip] = trust_state or TRUSTED
            self._record_action(
                request_id=request_id, host_ip=host_ip, action=action,
                status="executed", reason=reason
            )
            return {
                "success": True, "status": "executed", "action": action,
                "host_ip": host_ip, "request_id": request_id
            }

        if action == ACTION_REROUTE:
            success = self.reroute_host(
                host_ip=host_ip, request_id=request_id, reason=reason
            )
            status = "requested" if success else "failed"
            self._record_action(
                request_id=request_id, host_ip=host_ip, action=action,
                status=status, reason=reason
            )
            return {
                "success": success, "status": status, "action": action,
                "host_ip": host_ip, "request_id": request_id
            }

        return {
            "success": False,
            "status": "failed",
            "message": "Unhandled action",
            "host_ip": host_ip,
            "action": action
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
