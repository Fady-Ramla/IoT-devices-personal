#!/usr/bin/env python3
"""SecureIoT Network Dashboard API for the Ryu runtime.

The API deliberately separates configured inventory from runtime observations:
``status``/``controller_connected`` describe control-plane reachability, while
``traffic_active`` describes observed data-plane traffic.  Providers are
looked up defensively so this module can run with the existing topology,
resilience, VLAN, firewall, and load-balancer applications without requiring
hard imports between them.
"""

import hmac
import hashlib
import importlib.util
import json
import os
import re
import threading
import time
from urllib.parse import urlsplit
from functools import wraps
from collections import OrderedDict
from datetime import datetime, timezone

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response

from iot_telemetry_store import IoTTelemetryStore


RUNTIME_API_INSTANCE_NAME = "secureiot_runtime_api"

# The configured 38-host topology used by the project. Runtime providers may
# replace individual fields, but they must not make configured inventory vanish.
_TOPOLOGY_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mininet", "vlan_config_38host.py")
_spec = importlib.util.spec_from_file_location("secureiot_vlan_config_38host", _TOPOLOGY_CONFIG_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load branch-local Mininet topology configuration")
_topology_config = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_topology_config)
HOSTS = _topology_config.HOSTS
HOST_SWITCHES = {host_id: spec["switch"] for host_id, spec in HOSTS.items()}
HOST_IPS = {host_id: spec["ip"].split("/", 1)[0] for host_id, spec in HOSTS.items()}
HOST_VLANS = {host_id: int(spec["vlan"]) for host_id, spec in HOSTS.items()}
VLAN_NETWORKS = dict(_topology_config.NETWORKS)
VLAN_GATEWAYS = dict(_topology_config.VLAN_GATEWAYS)
SWITCH_DPIDS = {name: int(name[1:]) for name in _topology_config.SWITCH_NAMES}
EXPECTED_INTER_SWITCH_LINKS = len(_topology_config.INTER_SWITCH_LINKS)
LOAD_BALANCER_CONFIG = dict(_topology_config.LOAD_BALANCER)
SERVICE_PAIRS = dict(_topology_config.SERVICE_PAIRS)
LOAD_BALANCER_IP = HOST_IPS.get(LOAD_BALANCER_CONFIG.get("host"), "unknown")
LOAD_BALANCER_PORTS = {
    int(port) for port in LOAD_BALANCER_CONFIG.get("frontends", ())
}
for _service_name in ("http_api", "https"):
    _service_port = SERVICE_PAIRS.get(_service_name, {}).get("port")
    if _service_port is not None:
        LOAD_BALANCER_PORTS.add(int(_service_port))
HTTP_ACTIVITY_PORTS = frozenset(
    {80, 443, 8080, 8081} | LOAD_BALANCER_PORTS | {
        int(value) for value in os.getenv("SECUREIOT_HTTP_ACTIVITY_PORTS", "").split(",")
        if value.strip()
    }
)
SSH_ACTIVITY_PORT = 22
SSH_ACTIVITY_PORTS = frozenset({22, 2222})
SERVICE_ACTIVITY_PORTS = frozenset({53, 80, 443, 5000, 8080, 8081, 22, 2222})
SSH_AUDIT_LOG_DIR = os.getenv("SECUREIOT_SSHD_LOG_DIR", "/run/secureiot/ssh")
SSH_AUDIT_EVENT_MAX_AGE = 24 * 60 * 60
SSH_AUDIT_LOG_MAX_BYTES = 256 * 1024
# ICMP activity counters are sampled every five seconds. Keep activity visible
# across one sample interval and short scheduling jitter; expire after eight
# quiet seconds, not at exact OpenFlow rule deletion time.
TRAFFIC_ACTIVE_WINDOW = max(
    8.0, float(os.getenv("SECUREIOT_TRAFFIC_ACTIVE_WINDOW", "8"))
)
TELEMETRY_ACTIVE_WINDOW = max(15.0, TRAFFIC_ACTIVE_WINDOW)


def now_utc():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_utc_timestamp(value):
    try:
        text = str(value).strip()
        try:
            stamp = datetime.fromtimestamp(float(text), tz=timezone.utc)
        except ValueError:
            stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
        return stamp.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _timestamp_is_recent(value, max_age_seconds, now=None):
    stamp = _parse_utc_timestamp(value)
    if stamp is None:
        return False
    age = ((now or datetime.now(timezone.utc)) - stamp).total_seconds()
    return 0 <= age <= float(max_age_seconds)


def _flow_activity_category(flow):
    """Classify observed ping, HTTP/Load Balancer, and SSH flows."""
    if not isinstance(flow, dict):
        return None
    try:
        ip_proto = int(flow.get("ip_proto", -1))
    except (TypeError, ValueError):
        return None
    if ip_proto == 1:
        try:
            return "ping" if int(flow.get("icmp_type", -1)) == 8 else None
        except (TypeError, ValueError):
            return None
    if ip_proto not in (6, 17):
        return None
    try:
        ports = {
            int(port) for port in (
                flow.get("tcp_src_port") if ip_proto == 6 else flow.get("udp_src_port"),
                flow.get("tcp_dst_port") if ip_proto == 6 else flow.get("udp_dst_port"),
            ) if port is not None
        }
    except (TypeError, ValueError):
        return None
    if ports & SSH_ACTIVITY_PORTS:
        return "ssh"
    if ip_proto == 17 and ports & {53}:
        return "dns"
    if not ports.intersection(HTTP_ACTIVITY_PORTS):
        return "service" if ports.intersection(SERVICE_ACTIVITY_PORTS) else None
    endpoints = {str(flow.get("src_ip", "")), str(flow.get("dst_ip", ""))}
    if LOAD_BALANCER_IP in endpoints:
        return "load_balancer"
    return "http"


def _ssh_log_timestamp(line, fallback_epoch):
    """Parse ISO/syslog time from sshd output without exposing its raw line."""
    iso = re.search(r"\d{4}-\d{2}-\d{2}[T ][0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?", line)
    if iso:
        stamp = _parse_utc_timestamp(iso.group(0))
        if stamp is not None:
            return stamp, "sshd_log"
    syslog = re.search(
        r"\b(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
        r"\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})\b", line
    )
    if syslog:
        local_year = datetime.fromtimestamp(fallback_epoch).year
        value = "%d %s %s" % (local_year, syslog.group("month"),
                               syslog.group("day") + " " + syslog.group("clock"))
        try:
            local_stamp = datetime.strptime(value, "%Y %b %d %H:%M:%S")
            epoch = time.mktime(local_stamp.timetuple())
            if epoch > fallback_epoch + 86400:
                local_stamp = local_stamp.replace(year=local_year - 1)
                epoch = time.mktime(local_stamp.timetuple())
            return datetime.fromtimestamp(epoch, tz=timezone.utc), "sshd_log"
        except (ValueError, OverflowError, OSError):
            pass
    return datetime.fromtimestamp(fallback_epoch, tz=timezone.utc), "log_file_mtime"


def _ssh_audit_events(now_epoch=None):
    """Read bounded per-host sshd logs and return sanitized auth events only.

    Log files are expected at ``<SECUREIOT_SSHD_LOG_DIR>/secureiot-sshd-<host>.log``.
    Usernames, passwords, and raw log messages are deliberately never returned.
    """
    now_epoch = time.time() if now_epoch is None else float(now_epoch)
    host_for_ip = {ip: host_id for host_id, ip in HOST_IPS.items()}
    events = []
    source_re = re.compile(
        r"\bfrom\s+(?:\[(?P<bracketed>[0-9A-Fa-f:.]+)\]|(?P<plain>[0-9A-Fa-f:.]+))"
        r"\s+port\s+(?P<port>\d+)\b"
    )
    for server_host_id, server_ip in HOST_IPS.items():
        log_path = os.path.join(
            SSH_AUDIT_LOG_DIR, "secureiot-sshd-%s.log" % server_host_id
        )
        try:
            size = os.path.getsize(log_path)
            if size <= 0:
                continue
            fallback_epoch = os.path.getmtime(log_path)
            with open(log_path, "rb") as handle:
                handle.seek(max(0, size - SSH_AUDIT_LOG_MAX_BYTES))
                if size > SSH_AUDIT_LOG_MAX_BYTES:
                    handle.readline()
                lines = handle.read().decode("utf-8", errors="replace").splitlines()[-500:]
        except (OSError, ValueError):
            continue
        for line in lines:
            if "Connection from " in line:
                event_type, auth_status = "connection_attempt", "not_authenticated"
            elif re.search(r"\bAccepted\s+\S+\s+for\s+.+\s+from\s+", line):
                event_type, auth_status = "login_success", "success"
            elif re.search(r"\bFailed\s+\S+\s+for\s+.+\s+from\s+", line):
                event_type, auth_status = "login_failure", "failure"
            elif re.search(r"\bInvalid user\s+.+\s+from\s+", line):
                event_type, auth_status = "invalid_user", "failure"
            else:
                continue
            source_match = source_re.search(line)
            if source_match is None:
                continue
            source_ip = source_match.group("bracketed") or source_match.group("plain")
            stamp, timestamp_source = _ssh_log_timestamp(line, fallback_epoch)
            if (now_epoch - stamp.timestamp() > SSH_AUDIT_EVENT_MAX_AGE
                    or stamp.timestamp() > now_epoch + 300):
                continue
            digest = hashlib.sha256(
                (server_host_id + "\0" + line).encode("utf-8", errors="replace")
            ).hexdigest()[:16]
            events.append({
                "event_id": "ssh_" + digest,
                "event_type": event_type,
                "auth_status": auth_status,
                "protocol": "SSH",
                "source_host_id": host_for_ip.get(source_ip),
                "destination_host_id": server_host_id,
                "source_ip": source_ip,
                "destination_ip": server_ip,
                "destination_port": SSH_ACTIVITY_PORT,
                "source_port": int(source_match.group("port")),
                "timestamp": stamp.isoformat().replace("+00:00", "Z"),
                "timestamp_source": timestamp_source,
            })
    events.sort(key=lambda event: event["timestamp"])
    return events[-200:]


def _ssh_path_info(topology, source, destination):
    """Return a recent installed SSH path or an explicitly computed route."""
    if not source or not destination:
        return {"path": [], "path_source": "not_observed", "path_status": "unknown"}
    source_ip = str(HOST_IPS.get(source, source))
    destination_ip = str(HOST_IPS.get(destination, destination))
    flows = _call(topology, ["get_active_flow_paths"], []) if topology is not None else []
    recent_ssh_flow = any(
        isinstance(flow, dict)
        and {str(flow.get("src_ip", "")), str(flow.get("dst_ip", ""))}
        == {source_ip, destination_ip}
        and _flow_activity_category(flow) == "ssh"
        and _timestamp_is_recent(flow.get("last_seen"), TRAFFIC_ACTIVE_WINDOW)
        for flow in (flows if isinstance(flows, list) else [])
    )
    active_path = _active_flow_path(topology, source, destination) if recent_ssh_flow else None
    if active_path is not None:
        return {
            "path": active_path.get("nodes", []),
            "path_source": active_path.get("path_source", "installed_flow"),
            "path_status": active_path.get("status", "active"),
        }
    computed_path = _graph_path(topology, source, destination)
    return {
        "path": computed_path.get("nodes", []) if computed_path else [],
        "path_source": "computed" if computed_path else "not_observed",
        "path_status": computed_path.get("status", "unknown") if computed_path else "unknown",
    }


def _ssh_events_for_pair(topology, source, destination):
    """Return SSH audit events for a requested host pair, with an honest path label."""
    if not source or not destination:
        return []
    source_ip = str(HOST_IPS.get(source, source))
    destination_ip = str(HOST_IPS.get(destination, destination))
    path_info = _ssh_path_info(topology, source, destination)
    selected = []
    for event in _ssh_audit_events():
        if (event.get("source_ip") != source_ip
                or event.get("destination_ip") != destination_ip):
            continue
        selected.append(dict(event, **path_info))
    return selected


def json_response(payload, status=200):
    response = Response(status=status, content_type="application/json", charset="utf-8",
                        body=json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    # CORS is limited by default; wildcard mode is explicit for the local lab only.
    allowed_origin = os.environ.get("SECUREIOT_ALLOWED_ORIGIN", "").strip().rstrip("/")
    parsed_origin = urlsplit(allowed_origin)
    allow_all = os.environ.get("SECUREIOT_CORS_ALLOW_ALL", "0").strip().lower() in {"1", "true", "yes"}
    valid_origin = (
        parsed_origin.scheme in ("https", "http") and parsed_origin.netloc
        and parsed_origin.username is None and parsed_origin.password is None
        and parsed_origin.path == "" and not parsed_origin.query and not parsed_origin.fragment
    )
    if allow_all or valid_origin:
        response.headers["Access-Control-Allow-Origin"] = "*" if allow_all else allowed_origin
        response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = (
            "Accept,Content-Type,Authorization,ngrok-skip-browser-warning"
        )
        if not allow_all:
            response.headers["Vary"] = "Origin"
    response.headers["Cache-Control"] = "no-store"
    return response


def api_auth_required(handler):
    """Bearer authentication, optionally disabled for local demo testing."""
    @wraps(handler)
    def wrapped(self, req, *args, **kwargs):
        disable_auth = os.environ.get(
            "SECUREIOT_DISABLE_API_AUTH", "0"
        ).strip().lower() in {"1", "true", "yes"}

        if not disable_auth:
            expected = os.environ.get("SECUREIOT_API_TOKEN", "")
            if len(expected) < 32:
                return json_response(
                    {"error": "API authentication is not configured"},
                    status=503
                )

            authorization = req.headers.get("Authorization", "")
            scheme, separator, supplied = authorization.partition(" ")

            if (
                scheme.lower() != "bearer"
                or not separator
                or not hmac.compare_digest(supplied, expected)
            ):
                return json_response(
                    {"error": "valid bearer token required"},
                    status=401
                )

        return handler(self, req, *args, **kwargs)

    return wrapped


def compact(record):
    """Drop unset optional fields instead of serializing null/unknown noise."""
    return {key: value for key, value in record.items() if value is not None and value != "unknown"}


def _call(obj, names, default=None):
    """Call the first available provider method, tolerating old app versions."""
    for name in names:
        fn = getattr(obj, name, None) if obj is not None else None
        if callable(fn):
            try:
                return fn()
            except TypeError:
                continue
            except Exception:
                return default
    return default


def _call_args(obj, names, *args, default=None):
    for name in names:
        fn = getattr(obj, name, None) if obj is not None else None
        if callable(fn):
            try:
                return fn(*args)
            except (TypeError, KeyError, ValueError):
                continue
            except Exception:
                return default
    return default


def _host_dpid(topology, host_id):
    locations = getattr(topology, "host_location", {}) if topology is not None else {}
    location = locations.get(host_id) if isinstance(locations, dict) else None
    if isinstance(location, (tuple, list)) and location:
        return int(location[0])
    if isinstance(location, dict):
        value = location.get("dpid") or location.get("switch_dpid")
        if value is not None:
            return int(value)
    switch = HOST_SWITCHES.get(host_id)
    return SWITCH_DPIDS.get(switch)


def _graph_path(topology, source, destination):
    if topology is None or not source or not destination:
        return None
    src, dst = _host_dpid(topology, source), _host_dpid(topology, destination)
    graph = _call(topology, ["get_operational_graph", "get_graph"], None)
    if src is None or dst is None or graph is None:
        return None
    cross_vlan = HOST_VLANS.get(source) != HOST_VLANS.get(destination)
    try:
        import networkx as nx
        if cross_vlan:
            port_map = getattr(topology, "vlan_port_map", {})
            gateway_dpids = {
                int(key[0]) for key, entry in port_map.items()
                if isinstance(key, tuple) and len(key) == 2
                and isinstance(entry, dict) and entry.get("role") == "gateway"
            } if isinstance(port_map, dict) else set()
            gateway = next(iter(gateway_dpids)) if len(gateway_dpids) == 1 else SWITCH_DPIDS.get("s3")
            if gateway is not None and gateway not in (src, dst):
                left = nx.shortest_path(graph, src, gateway)
                right = nx.shortest_path(graph, gateway, dst)
                nodes = left[:-1] + right
            else:
                nodes = nx.shortest_path(graph, src, dst)
        else:
            nodes = nx.shortest_path(graph, src, dst)
    except Exception:
        if cross_vlan:
            return None
        try:
            nodes = graph.shortest_path(src, dst)
        except Exception:
            return None
    path_nodes = [int(x) for x in nodes]
    observed_links = _call(topology, ["get_links"], []) or []
    path_links = []
    for left, right in zip(path_nodes, path_nodes[1:]):
        match = next((row for row in observed_links
                      if isinstance(row, dict)
                      and int(row.get("src_dpid", -1)) == left
                      and int(row.get("dst_dpid", -1)) == right), None)
        if match is None:
            match = next((row for row in observed_links
                          if isinstance(row, dict)
                          and int(row.get("src_dpid", -1)) == right
                          and int(row.get("dst_dpid", -1)) == left), None)
        if match is not None:
            path_links.append(match)
    isolated = getattr(topology, "isolated_links", set())
    isolated_links = [list(edge) for edge in sorted(isolated)] if isinstance(isolated, (set, list, tuple)) else []
    return {"source": source, "destination": destination, "nodes": path_nodes,
            "status": "active", "links": path_links, "isolated_links": isolated_links,
            "computed": True, "last_updated": now_utc()}


def _active_flow_path(topology, source, destination):
    """Return the installed route for a matching flow, if it is tracked."""
    if topology is None or not source or not destination:
        return None
    source_ip = HOST_IPS.get(source, source)
    destination_ip = HOST_IPS.get(destination, destination)
    flows = _call(topology, ["get_active_flow_paths"], []) or []
    if not isinstance(flows, list):
        return None
    exact_flow = None
    reverse_flow = None
    for flow in flows:
        if not isinstance(flow, dict):
            continue
        flow_source = str(flow.get("src_ip", ""))
        flow_destination = str(flow.get("dst_ip", ""))
        if flow_source == str(source_ip) and flow_destination == str(destination_ip):
            exact_flow = exact_flow or flow
        elif flow_source == str(destination_ip) and flow_destination == str(source_ip):
            reverse_flow = reverse_flow or flow
    flow = exact_flow or reverse_flow
    if flow is not None:
        is_reverse = exact_flow is None
        nodes = flow.get("path")
        if not isinstance(nodes, (list, tuple)) or not nodes:
            return None
        try:
            path_nodes = [int(node) for node in nodes]
        except (TypeError, ValueError):
            return None
        if is_reverse:
            path_nodes.reverse()
        observed_links = _call(topology, ["get_links"], []) or []
        path_links = []
        for left, right in zip(path_nodes, path_nodes[1:]):
            link = next((row for row in observed_links
                         if isinstance(row, dict)
                         and int(row.get("src_dpid", -1)) == left
                         and int(row.get("dst_dpid", -1)) == right), None)
            if link is None:
                link = next((row for row in observed_links
                             if isinstance(row, dict)
                             and int(row.get("src_dpid", -1)) == right
                             and int(row.get("dst_dpid", -1)) == left), None)
            if link is not None:
                path_links.append(link)
        return {
            "source": source,
            "destination": destination,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "nodes": path_nodes,
            "status": flow.get("path_status", "active"),
            "links": path_links,
            "isolated_links": [],
            "computed": False,
            "path_source": "installed_flow",
            "flow_direction": "reverse_observation" if is_reverse else "forward_observation",
            "last_updated": now_utc(),
        }
    return None


def _path_history(topology, source=None, destination=None, host_id=None, limit=50):
    """Select history records for an existing path/host response."""
    records = _call(topology, ["get_path_history"], []) if topology is not None else []
    if not isinstance(records, list):
        return []
    source_ip = HOST_IPS.get(source, source) if source else None
    destination_ip = HOST_IPS.get(destination, destination) if destination else None
    host_ip = HOST_IPS.get(host_id, host_id) if host_id else None
    selected = []
    for record in records:
        if not isinstance(record, dict):
            continue
        reverse_observation = False
        if source_ip and destination_ip:
            exact = (str(record.get("source_ip", "")) == str(source_ip)
                     and str(record.get("destination_ip", "")) == str(destination_ip))
            reverse_observation = (
                str(record.get("source_ip", "")) == str(destination_ip)
                and str(record.get("destination_ip", "")) == str(source_ip)
            )
            if not exact and not reverse_observation:
                continue
        else:
            if source_ip and str(record.get("source_ip", "")) != str(source_ip):
                continue
            if destination_ip and str(record.get("destination_ip", "")) != str(destination_ip):
                continue
        if host_ip and host_ip not in (record.get("source_ip"), record.get("destination_ip")):
            continue
        item = dict(record)
        if reverse_observation:
            item["observed_source_ip"] = item.get("source_ip")
            item["observed_destination_ip"] = item.get("destination_ip")
            item["source_ip"] = source_ip
            item["destination_ip"] = destination_ip
            item["old_path"] = list(reversed(item.get("old_path") or []))
            item["new_path"] = list(reversed(item.get("new_path") or []))
            item["direction_reversed"] = True
        stamp = _parse_utc_timestamp(item.get("timestamp"))
        if stamp is not None:
            item["timestamp"] = stamp.isoformat().replace("+00:00", "Z")
        selected.append(item)
    return selected[-max(1, min(500, int(limit))):]


class StatsCache:
    """Non-blocking OpenFlow stats cache.

    HTTP handlers return the last known snapshot and request a fresh multipart
    reply at most once per ``request_interval``. Ryu event handlers or an
    integration adapter can feed replies through the ``record_*`` methods.
    """
    def __init__(self, interval=2.0):
        self.interval = interval
        self._lock = threading.RLock()
        self._last_request = {}
        self._datapaths = {}
        self._cache = {"desc": {}, "flow": {}, "port": {}}

    def register_datapath(self, datapath):
        with self._lock:
            self._datapaths[int(datapath.id)] = datapath

    def unregister_datapath(self, dpid):
        if dpid is None:
            return
        with self._lock:
            self._datapaths.pop(int(dpid), None)

    def record(self, kind, dpid, value):
        with self._lock:
            self._cache[kind][int(dpid)] = value

    def get(self, kind, dpid):
        dpid = int(dpid)
        with self._lock:
            value = self._cache[kind].get(dpid)
            if value is None:
                value = {} if kind == "desc" else []
            self._request(kind, dpid)
            return value

    def _request(self, kind, dpid):
        import time
        key = (kind, dpid)
        now = time.monotonic()
        if now - self._last_request.get(key, 0) < self.interval:
            return
        datapath = self._datapaths.get(dpid)
        if datapath is None:
            return
        parser = datapath.ofproto_parser
        messages = {
            "desc": parser.OFPDescStatsRequest(datapath),
            "flow": parser.OFPFlowStatsRequest(datapath),
            "port": parser.OFPPortStatsRequest(datapath, 0xffffffff),
        }
        try:
            datapath.send_msg(messages[kind])
            self._last_request[key] = now
        except Exception:
            # The cached response remains valid and the next poll retries.
            return


class RuntimeNetworkController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        runtime_app = data.get(RUNTIME_API_INSTANCE_NAME)
        self.stats = getattr(data.get(RUNTIME_API_INSTANCE_NAME), "stats", StatsCache())
        self.paths = getattr(data.get(RUNTIME_API_INSTANCE_NAME), "paths", OrderedDict())
        self.network_event_store = getattr(data.get(RUNTIME_API_INSTANCE_NAME), "network_events", [])
        # Avoid eagerly constructing a fallback store: getattr defaults are
        # evaluated even when runtime_app already owns the shared store.
        self.iot_store = getattr(runtime_app, "iot_store", None) or IoTTelemetryStore()
        self._traffic_counter_snapshot = getattr(runtime_app, "traffic_counter_snapshot", {})
        self._lb_metrics_baseline = getattr(runtime_app, "lb_metrics_baseline", {})

    @staticmethod
    def _topology():
        return app_manager.lookup_service_brick("TopologyMonitor")

    @staticmethod
    def _resilience():
        return app_manager.lookup_service_brick("ResilienceEngine")

    @staticmethod
    def _traffic_monitor():
        """Return the live TrafficMonitorMerged service across Ryu name variants."""
        for name in ("TrafficMonitorMerged", "traffic_monitor_merged", "traffic_monitor"):
            service = app_manager.lookup_service_brick(name)
            if service is not None:
                return service
        return None

    def _firewall_action_events(self):
        """Normalize live security actions for the firewall dashboard."""
        monitor = self._traffic_monitor()
        history = getattr(monitor, "action_history", {}) if monitor is not None else {}
        if not isinstance(history, dict):
            return []
        events = []
        for request_id, row in history.items():
            if not isinstance(row, dict):
                continue
            action = str(row.get("action", "")).upper()
            if action not in {"BLOCK_DEVICE", "UNBLOCK_DEVICE", "BLOCK", "DROP"}:
                continue
            event = dict(row)
            event.setdefault("request_id", request_id)
            event.setdefault("event_type", "firewall")
            event["blocked"] = action in {"BLOCK_DEVICE", "BLOCK", "DROP"}
            events.append(event)
        events.sort(key=lambda item: float(item.get("timestamp", 0) or 0))
        return events

    @staticmethod
    def _service(*names):
        for name in names:
            service = app_manager.lookup_service_brick(name)
            if service is not None:
                return service
        return None

    def _topology_status(self):
        topology = self._topology()
        return topology, (_call(topology, ["get_topology_status"], {}) or {})

    def _traffic_activity(self):
        """Map active switch DPIDs to recent service, ping, or telemetry activity."""
        activity = {}
        topology = self._topology()
        ping_activity = getattr(topology, "switch_traffic_last_seen", {}) if topology is not None else {}
        if isinstance(ping_activity, dict):
            now = time.time()
            for dpid, observed_at in ping_activity.items():
                try:
                    if now - float(observed_at) <= TRAFFIC_ACTIVE_WINDOW:
                        activity[int(dpid)] = datetime.fromtimestamp(
                            float(observed_at), tz=timezone.utc).isoformat().replace("+00:00", "Z")
                except (TypeError, ValueError, OSError):
                    continue

        # Service activity is tracked by host IP in TopologyMonitor. Include
        # HTTP/HTTPS, SSH, and DNS on the same switch signal as ping.
        for attribute in (
            "web_traffic_last_seen",
            "ssh_traffic_last_seen",
            "service_traffic_last_seen",
        ):
            seen_by_ip = getattr(topology, attribute, {}) if topology is not None else {}
            if not isinstance(seen_by_ip, dict):
                continue
            for host_id, host_ip in HOST_IPS.items():
                observed_at = seen_by_ip.get(host_ip)
                if observed_at is None:
                    continue
                try:
                    if time.time() - float(observed_at) > TRAFFIC_ACTIVE_WINDOW:
                        continue
                    dpid = SWITCH_DPIDS[HOST_SWITCHES[host_id]]
                    timestamp = datetime.fromtimestamp(
                        float(observed_at), tz=timezone.utc
                    ).isoformat().replace("+00:00", "Z")
                    current = _parse_utc_timestamp(activity.get(dpid))
                    observed = _parse_utc_timestamp(timestamp)
                    if current is None or (observed is not None and observed > current):
                        activity[dpid] = timestamp
                except (KeyError, TypeError, ValueError, OSError):
                    continue

        # A fresh SQLite sample proves that the private sensor GET succeeded.
        # Mark only the current operational path from the polling API host to
        # that sensor; generic flows and unrelated counters do not qualify.
        try:
            devices = self.iot_store.devices()
        except Exception:
            devices = []
        for device in devices:
            if not isinstance(device, dict):
                continue
            host_id = str(device.get("device_id", ""))
            if host_id not in HOSTS or HOST_VLANS.get(host_id) != 10:
                continue
            if not _timestamp_is_recent(device.get("last_seen"), TELEMETRY_ACTIVE_WINDOW):
                continue
            path = _graph_path(topology, "h2", host_id)
            if isinstance(path, dict):
                seen = _parse_utc_timestamp(device.get("last_seen"))
                if seen is None:
                    continue
                timestamp = seen.isoformat().replace("+00:00", "Z")
                for dpid in path.get("nodes", []):
                    dpid = int(dpid)
                    current = _parse_utc_timestamp(activity.get(dpid))
                    if current is None or seen > current:
                        activity[dpid] = timestamp
        return activity

    def _traffic_dpids(self):
        """Compatibility helper returning switches with scoped recent activity."""
        return set(self._traffic_activity())

    def _collect_active_dpids(self, value, active):
        if isinstance(value, dict):
            dpid = value.get("dpid") or value.get("switch_id") or value.get("datapath_id")
            counters = ("rate", "rate_mbps", "bytes", "byte_count", "packet_count", "packets", "rx_bytes", "tx_bytes")
            if dpid is not None and any(isinstance(value.get(key), (int, float)) and value.get(key) > 0 for key in counters):
                try:
                    active.add(int(str(dpid).lower().lstrip("s")))
                except (TypeError, ValueError):
                    pass
            for child in value.values():
                self._collect_active_dpids(child, active)
        elif isinstance(value, (list, tuple)):
            for child in value:
                self._collect_active_dpids(child, active)

    @route("runtime_options", "/{path:.*}", methods=["OPTIONS"])
    def options(self, req, **kwargs):
        return json_response({}, status=204)

    @route("runtime_health", "/health", methods=["GET"])
    def health_public(self, req, **kwargs):
        topology = self._topology()
        return json_response({"status": "healthy" if topology is not None else "degraded", "timestamp": now_utc()})

    @route("runtime_health_legacy", "/runtime/health", methods=["GET"])
    def health(self, req, **kwargs):
        topology = self._topology()
        return json_response({"status": "connected" if topology is not None else "degraded",
                              "topology_monitor_available": topology is not None, "timestamp": now_utc()})

    @api_auth_required
    @route("iot_devices", "/api/iot/devices", methods=["GET"])
    def iot_devices(self, req, **kwargs):
        return json_response(self.iot_store.devices())

    @api_auth_required
    @route("iot_sensors", "/api/iot/sensors", methods=["GET"])
    def iot_sensors(self, req, **kwargs):
        return json_response(self.iot_store.sensors())

    @api_auth_required
    @route("iot_telemetry_get", "/api/iot/telemetry", methods=["GET"])
    def iot_telemetry_get(self, req, **kwargs):
        return json_response(self.iot_store.telemetry(req.GET.get("device_id"), req.GET.get("sensor_id"), req.GET.get("limit", 100)))

    # Private legacy ingress retained for local lab clients. The public
    # WebTrack gateway must never forward non-GET methods to this API.
    @api_auth_required
    @route("iot_telemetry_post", "/api/iot/telemetry", methods=["POST"])
    def iot_telemetry_post(self, req, **kwargs):
        try:
            payload = json.loads(req.body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("JSON object required")
            return json_response({"status": "accepted", "telemetry": self.iot_store.record(payload)}, status=201)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return json_response({"status": "rejected", "error": str(exc)}, status=400)

    @api_auth_required
    @route("runtime_controller", "/controller/state", methods=["GET"])
    def controller(self, req, **kwargs):
        topology, status = self._topology_status()
        switches = status.get("switches") or []
        links = status.get("operational_links") or []
        ready = bool(topology is not None and status.get("topology_ready", True))
        payload = {"controller_id": "ryu", "status": "connected" if topology else "degraded",
                   "state": "active" if ready else "degraded", "expected_switches": len(SWITCH_DPIDS),
                   "connected_switches": len(switches) if switches else (6 if ready else 0),
                   "expected_inter_switch_links": EXPECTED_INTER_SWITCH_LINKS,
                   "active_inter_switch_links": len(links),
                   "forwarding_owner": "TopologyMonitor", "traffic_monitor_forwarding": False,
                   "clff_enabled": getattr(topology, "clff", None) is not None,
                   "clff_ready": status.get("clff_ready", ready),
                   "resilience_status": "ready" if ready else "degraded",
                   "last_seen": now_utc(), "last_error": None if topology else "TopologyMonitor unavailable"}
        return json_response(payload, status=200 if topology else 503)

    @api_auth_required
    @route("runtime_controller_legacy", "/runtime/controller", methods=["GET"])
    def controller_legacy(self, req, **kwargs):
        """Compatibility alias for clients using the original runtime path."""
        return self.controller(req, **kwargs)

    @api_auth_required
    @route("runtime_topology", "/runtime/topology", methods=["GET"])
    def topology(self, req, **kwargs):
        topology, status = self._topology_status()
        if topology is None:
            return json_response({"error": "TopologyMonitor service is unavailable"}, status=503)
        return json_response({"status": status, "links": _call(topology, ["get_links"], []) or [],
                              "hosts": _call(topology, ["get_host_status"], {}) or {}, "timestamp": now_utc()})

    def _switches(self):
        topology, status = self._topology_status()
        observed = _call(topology, ["get_switch_inventory", "get_switches"], None) if topology else None
        observed = observed if isinstance(observed, (list, tuple)) else status.get("switches", [])
        by_dpid = {int(x.get("dpid")): x for x in observed if isinstance(x, dict) and str(x.get("dpid", "")).isdigit()}
        datapaths = getattr(topology, "datapaths", {}) if topology is not None else {}
        port_desc = getattr(topology, "port_desc", {}) if topology is not None else {}
        activity = self._traffic_activity()
        active_dpids = set(activity)
        result = []
        for name, dpid in SWITCH_DPIDS.items():
            item = dict(by_dpid.get(dpid, {}))
            provider_dp = datapaths.get(dpid) if isinstance(datapaths, dict) else None
            provider_ports = [key[1] for key in port_desc if isinstance(key, tuple) and len(key) == 2 and int(key[0]) == dpid]
            if not provider_ports and provider_dp is not None:
                provider_ports = list(getattr(provider_dp, "ports", {}) or {})
            n_ports = item.get("n_ports")
            if n_ports is None:
                ports = item.get("ports") or item.get("port_inventory") or []
                n_ports = len(ports) if ports else len(provider_ports)
            if not n_ports:
                n_ports = 1 if provider_dp is not None else 0
            result.append(compact({"switch_id": name, "name": name, "dpid": dpid, "n_ports": int(n_ports),
                           "status": item.get("status", "up" if provider_dp is not None else "unknown"),
                           "controller_connected": bool(item.get("controller_connected", provider_dp is not None)),
                           "traffic_active": dpid in active_dpids,
                           "last_traffic_at": activity.get(dpid)}))
        return result

    @api_auth_required
    @route("topology_switches", "/topology/switches", methods=["GET"])
    def switches(self, req, **kwargs):
        return json_response(self._switches())

    @api_auth_required
    @route("topology_links", "/topology/links", methods=["GET"])
    def links(self, req, **kwargs):
        topology, _ = self._topology_status()
        links = _call(topology, ["get_links"], []) if topology is not None else []
        if not isinstance(links, list):
            return json_response([])
        return json_response([dict(link, status=("isolated" if link.get("isolated") else "active"))
                              for link in links if isinstance(link, dict)])

    @api_auth_required
    @route("topology_hosts", "/topology/hosts", methods=["GET"])
    def hosts(self, req, **kwargs):
        topology, _ = self._topology_status()
        observed = _call(topology, ["get_host_inventory", "get_hosts", "get_host_status"], {}) if topology else {}
        if isinstance(observed, list):
            observed = {x.get("host_id", x.get("id")): x for x in observed if isinstance(x, dict)}
        observed = observed if isinstance(observed, dict) else {}
        observed_by_ip = {}
        for key, row in observed.items():
            if not isinstance(row, dict):
                continue
            address = row.get("ip") or row.get("ipv4")
            if isinstance(address, (list, tuple)):
                address = address[0] if address else None
            if address:
                observed_by_ip[str(address).split("/", 1)[0]] = (str(key), row)
        result = []
        vlan_port_map = getattr(topology, "vlan_port_map", {}) if topology is not None else {}
        access_ports = {}
        if isinstance(vlan_port_map, dict):
            for key, value in vlan_port_map.items():
                if not isinstance(key, tuple) or len(key) != 2:
                    continue
                dpid, port_no = int(key[0]), int(key[1])
                kind = value.get("kind", "access") if isinstance(value, dict) else "access"
                if kind == "access":
                    access_ports.setdefault(dpid, []).append(port_no)
            for ports in access_ports.values():
                ports.sort()
        datapaths = getattr(topology, "datapaths", {}) if topology is not None else {}
        ping_activity = getattr(topology, "ping_traffic_last_seen", {}) if topology is not None else {}
        web_activity = getattr(topology, "web_traffic_last_seen", {}) if topology is not None else {}
        ssh_activity = getattr(topology, "ssh_traffic_last_seen", {}) if topology is not None else {}
        now = time.time()
        ssh_events = _ssh_audit_events()
        ssh_path_cache = {}
        for event in ssh_events:
            source_host = event.get("source_host_id")
            destination_host = event.get("destination_host_id")
            pair = (source_host, destination_host)
            if pair not in ssh_path_cache:
                ssh_path_cache[pair] = _ssh_path_info(
                    topology, source_host, destination_host
                )
            event.update(ssh_path_cache[pair])
        telemetry_by_device = {}
        try:
            for device in self.iot_store.devices():
                if not isinstance(device, dict):
                    continue
                device_id = str(device.get("device_id", ""))
                if (device_id in HOSTS and HOST_VLANS.get(device_id) == 10
                        and _timestamp_is_recent(device.get("last_seen"), TELEMETRY_ACTIVE_WINDOW)):
                    telemetry_by_device[device_id] = device
        except Exception:
            telemetry_by_device = {}
        for host_id in sorted(HOST_SWITCHES, key=lambda x: int(x[1:])):
            observed_row = observed_by_ip.get(HOST_IPS[host_id])
            item = dict(observed_row[1]) if observed_row else {}
            observed_mac = observed_row[0] if observed_row else item.get("mac")
            dpid = int(item.get("dpid") or SWITCH_DPIDS[HOST_SWITCHES[host_id]])
            host_index = sum(1 for h in HOST_SWITCHES if HOST_SWITCHES[h] == HOST_SWITCHES[host_id] and int(h[1:]) < int(host_id[1:]))
            provider_port = (access_ports.get(dpid) or [])[host_index % len(access_ports.get(dpid, [1]))] if access_ports.get(dpid) else 1 + (host_index % 48)
            port_no = int(item.get("port") or item.get("port_no") or provider_port)
            ping_seen = ping_activity.get(HOST_IPS[host_id]) if isinstance(ping_activity, dict) else None
            try:
                ping_active = ping_seen is not None and 0 <= now - float(ping_seen) <= TRAFFIC_ACTIVE_WINDOW
            except (TypeError, ValueError):
                ping_active = False
            web_seen = web_activity.get(HOST_IPS[host_id]) if isinstance(web_activity, dict) else None
            web_active = _timestamp_is_recent(web_seen, TRAFFIC_ACTIVE_WINDOW)
            ssh_seen = ssh_activity.get(HOST_IPS[host_id]) if isinstance(ssh_activity, dict) else None
            ssh_active = _timestamp_is_recent(ssh_seen, TRAFFIC_ACTIVE_WINDOW)
            telemetry_record = telemetry_by_device.get(host_id)
            telemetry_active = telemetry_record is not None
            raw_flows = item.get("active_flows") if isinstance(item.get("active_flows"), list) else []
            raw_flows = list(raw_flows)
            tracked_flows = _call(topology, ["get_active_flow_paths"], []) if topology else []
            if isinstance(tracked_flows, list):
                for flow in tracked_flows:
                    if not isinstance(flow, dict):
                        continue
                    if HOST_IPS[host_id] not in (flow.get("src_ip"), flow.get("dst_ip")):
                        continue
                    if not any(existing.get("src_ip") == flow.get("src_ip")
                               and existing.get("dst_ip") == flow.get("dst_ip")
                               and existing.get("vlan_id") == flow.get("vlan_id")
                               for existing in raw_flows if isinstance(existing, dict)):
                        raw_flows.append(flow)
            flows = []
            for flow in raw_flows:
                if not isinstance(flow, dict):
                    continue
                if HOST_IPS[host_id] not in (flow.get("src_ip"), flow.get("dst_ip")):
                    continue
                category = _flow_activity_category(flow)
                if category is None or not _timestamp_is_recent(
                        flow.get("last_seen"), TRAFFIC_ACTIVE_WINDOW):
                    continue
                active_flow = dict(flow)
                active_flow["traffic_category"] = category
                active_flow["last_seen"] = _parse_utc_timestamp(
                    flow.get("last_seen")).isoformat().replace("+00:00", "Z")
                if category == "ping":
                    ping_active = True
                elif category == "ssh":
                    ssh_active = True
                else:
                    web_active = True
                flows.append(active_flow)
            telemetry_path = _graph_path(topology, "h2", host_id) if telemetry_active else None
            if telemetry_active:
                flows.append({
                    "traffic_category": "telemetry",
                    "source_host_id": "h2",
                    "destination_host_id": host_id,
                    "source_ip": HOST_IPS.get("h2"),
                    "destination_ip": HOST_IPS.get(host_id),
                    "protocol": "TCP",
                    "destination_port": 8081,
                    "path": telemetry_path.get("nodes", []) if isinstance(telemetry_path, dict) else [],
                    "path_type": "inter_switch",
                    "path_status": "active",
                    "last_seen": telemetry_record.get("last_seen"),
                    "activity_source": "successful_sensor_poll",
                })
            host_active = bool(telemetry_active or ping_active or web_active or ssh_active)
            primary_flow = max(
                flows,
                key=lambda flow: _parse_utc_timestamp(flow.get("last_seen"))
                or datetime.min.replace(tzinfo=timezone.utc),
            ) if flows else {}
            fallback_path = self.paths.get(host_id, {}) if host_active else {}
            traffic_timestamps = [
                _parse_utc_timestamp(flow.get("last_seen"))
                for flow in flows if isinstance(flow, dict)
            ]
            if web_active and web_seen is not None:
                traffic_timestamps.append(_parse_utc_timestamp(web_seen))
            if ping_active and ping_seen is not None:
                traffic_timestamps.append(_parse_utc_timestamp(ping_seen))
            if ssh_active and ssh_seen is not None:
                traffic_timestamps.append(_parse_utc_timestamp(ssh_seen))
            traffic_timestamps = [stamp for stamp in traffic_timestamps if stamp is not None]
            last_traffic_at = max(traffic_timestamps).isoformat().replace("+00:00", "Z") if traffic_timestamps else None
            telemetry_path_nodes = telemetry_path.get("nodes", []) if isinstance(telemetry_path, dict) else []
            host_ssh_events = [
                dict(event) for event in ssh_events
                if host_id in (event.get("source_host_id"), event.get("destination_host_id"))
            ]
            result.append(compact({"host_id": host_id, "dpid": dpid, "port_no": port_no,
                           # Mininet creates gw before h1, so the default
                           # fallback MAC for h16 is ...:11, not ...:10.
                           "mac": item.get("mac", observed_mac or f"00:00:00:00:00:{int(host_id[1:]) + 1:02x}"),
                           "ipv4": item.get("ipv4", [HOST_IPS[host_id]]), "vlan_id": HOST_VLANS[host_id],
                           "status": item.get("status", "configured" if topology else "unknown"),
                           "controller_seen": bool(item.get("controller_seen", dpid in datapaths)),
                           "traffic_active": host_active,
                           "telemetry_active": telemetry_active,
                           "last_seen": item.get("last_seen"),
                           "last_traffic_at": last_traffic_at,
                           "active_flows": flows,
                           "ssh_events": host_ssh_events,
                           "path_history": _path_history(topology, host_id=host_id, limit=20),
                           "path": primary_flow.get("path", telemetry_path_nodes or fallback_path.get("nodes", [])),
                           "path_type": (primary_flow.get("path_type")
                                         or fallback_path.get("path_type")
                                         or "none"),
                           "path_status": (primary_flow.get("path_status")
                                           or fallback_path.get("path_status")
                                           or ("active" if host_active else "inactive"))}))
        return json_response(result)

    @api_auth_required
    @route("stats_desc", "/stats/desc/{dpid}", methods=["GET"])
    def stats_desc(self, req, dpid, **kwargs):
        value = self.stats.get("desc", int(dpid))
        return json_response(value if value else {"status": "pending", "dpid": int(dpid)}, status=200 if value else 202)

    @api_auth_required
    @route("stats_flow", "/stats/flow/{dpid}", methods=["GET"])
    def stats_flow(self, req, dpid, **kwargs):
        value = self.stats.get("flow", int(dpid))
        return json_response(value if value else {"status": "pending", "dpid": int(dpid), "flows": []}, status=200 if value else 202)

    @api_auth_required
    @route("stats_port", "/stats/port/{dpid}", methods=["GET"])
    def stats_port(self, req, dpid, **kwargs):
        value = self.stats.get("port", int(dpid))
        return json_response(value if value else {"status": "pending", "dpid": int(dpid), "ports": []}, status=200 if value else 202)

    @api_auth_required
    @route("vlan_list", "/network/vlans", methods=["GET"])
    def vlans(self, req, **kwargs):
        return json_response([{"vlan_id": vlan, "network": network, "gateway": VLAN_GATEWAYS[vlan], "status": "active"}
                              for vlan, network in VLAN_NETWORKS.items()])

    @api_auth_required
    @route("vlan_ports", "/network/vlan-ports", methods=["GET"])
    def vlan_ports(self, req, **kwargs):
        rows = []
        for host_id, switch in HOST_SWITCHES.items():
            host_index = sum(1 for h in HOST_SWITCHES if HOST_SWITCHES[h] == switch and int(h[1:]) < int(host_id[1:]))
            rows.append({"vlan_id": HOST_VLANS[host_id], "switch_id": switch, "dpid": SWITCH_DPIDS[switch],
                         "port_no": 1 + (host_index % 48), "host_id": host_id, "mode": "access", "status": "configured"})
        return json_response(rows)

    @api_auth_required
    @route("load_balancer", "/network/load-balancer", methods=["GET"])
    def load_balancer(self, req, **kwargs):
        aggregate = self._aggregate_load_balancer_stats()
        return json_response({"service_id": "secureiot-lb", "host_id": LOAD_BALANCER_CONFIG.get("host"),
                              "vip": LOAD_BALANCER_IP,
                              "status": aggregate["status"],
                              "algorithm": "round_robin", "backend_count": aggregate["total_backends"],
                              "frontends": [53] + list(LOAD_BALANCER_CONFIG.get("frontends", ())),
                              "requests_total": aggregate["requests_total"],
                              "requests_active": aggregate["requests_active"],
                              "inflight": aggregate["inflight"],
                              "last_backend": aggregate["last_backend"],
                              "backend_requests": aggregate["backend_requests"],
                              "healthy_backends": aggregate["healthy_backends"],
                              "failed_backends": aggregate["failed_backends"],
                              "failure_events_total": aggregate["failure_events_total"],
                              "active_failures": aggregate["active_failures"],
                              "recovery_events": aggregate["recovery_events"],
                              "total_failover_requests": aggregate["total_failover_requests"],
                              "services": aggregate["services"]})

    @api_auth_required
    @route("load_balancer_status", "/network/load-balancer/status", methods=["GET"])
    def load_balancer_status(self, req, **kwargs):
        aggregate = self._aggregate_load_balancer_stats()
        if not aggregate["services"]:
            return json_response({"status": "unavailable", "health_checks_performed": False,
                                  "healthy_backends": [], "failed_backends": [], "total_backends": 0,
                                  "failure_events_total": 0, "active_failures": 0,
                                  "recovery_events": 0, "total_failover_requests": 0,
                                  "source": "stats-files-unavailable"}, status=503)
        return json_response({"status": aggregate["status"],
                              "health_checks_performed": aggregate["health_checks_performed"],
                              "healthy_backends": aggregate["healthy_backends"],
                              "failed_backends": aggregate["failed_backends"],
                              "total_backends": aggregate["total_backends"],
                              "requests_active": aggregate["requests_active"],
                              "inflight": aggregate["inflight"],
                              "failure_events_total": aggregate["failure_events_total"],
                              "active_failures": aggregate["active_failures"],
                              "recovery_events": aggregate["recovery_events"],
                              "total_failover_requests": aggregate["total_failover_requests"],
                              "last_check": aggregate["last_check"],
                              "updated_at": aggregate["updated_at"],
                              "services": aggregate["services"],
                              "source": "aggregated-load-balancer-stats"})

    @api_auth_required
    @route("load_balancer_backends", "/network/load-balancer/backends", methods=["GET"])
    def load_balancer_backends(self, req, **kwargs):
        backends = []
        snapshots = self._load_balancer_stats_by_service()
        for service_name, service in SERVICE_PAIRS.items():
            stats = snapshots.get(service_name) or {}
            healthy = set(stats.get("healthy_backends", []))
            checked = bool(stats.get("health_checks_performed"))
            for key in ("primary", "backup"):
                host_id = service.get(key)
                if host_id and host_id in HOST_IPS:
                    address = "%s:%s" % (HOST_IPS[host_id], service.get("port", 5000))
                    backends.append({"service": service_name, "backend_id": host_id,
                                     "address": address,
                                     "status": ("healthy" if address in healthy
                                                 else ("unhealthy" if checked else "unknown")),
                                     "health_checked": checked, "weight": 1,
                                     "failure_events_total": stats.get("failure_events_total", 0),
                                     "active_failures": address in set(stats.get("failed_backends", [])),
                                     "recovery_events": stats.get("recovery_events", 0),
                                     "last_check": stats.get("last_health_check")})
        return json_response(backends)

    @api_auth_required
    @route("load_balancer_stats", "/network/load-balancer/stats", methods=["GET"])
    def load_balancer_stats(self, req, **kwargs):
        aggregate = self._aggregate_load_balancer_stats()
        if aggregate["services"]:
            aggregate["timestamp"] = now_utc()
            aggregate["source"] = "aggregated-load-balancer-stats"
            return json_response(aggregate)
        return json_response({"status": "unavailable", "requests_total": 0, "requests_active": 0,
                              "bytes_in": 0, "bytes_out": 0, "backend_failovers": 0,
                              "failure_events_total": 0, "active_failures": 0,
                              "recovery_events": 0, "total_failover_requests": 0,
                              "timestamp": now_utc(), "source": "stats-files-unavailable"}, status=503)

    @staticmethod
    def _load_balancer_stats():
        path = os.environ.get("SECUREIOT_LB_STATS_FILE", "/var/tmp/secureiot-lb-stats.json")
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None

    @staticmethod
    def _load_balancer_stats_by_service():
        paths = {
            "dns": os.environ.get("SECUREIOT_DNS_LB_STATS_FILE", "/tmp/secureiot-lb-dns-stats.json"),
            "http_api": os.environ.get("SECUREIOT_LB_STATS_FILE", "/var/tmp/secureiot-lb-stats.json"),
            "https": os.environ.get("SECUREIOT_HTTPS_LB_STATS_FILE", "/tmp/secureiot-lb-https-stats.json"),
            "ssh": os.environ.get("SECUREIOT_SSH_LB_STATS_FILE", "/tmp/secureiot-lb-ssh-stats.json"),
        }
        result = {}
        for service, path in paths.items():
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    value = json.load(handle)
                if isinstance(value, dict):
                    result[service] = value
            except (FileNotFoundError, json.JSONDecodeError, OSError):
                continue
        return result

    def _aggregate_load_balancer_stats(self):
        snapshots = self._load_balancer_stats_by_service()
        healthy, failed, backend_requests, backends = [], [], {}, []
        services = {}
        totals = {key: 0 for key in (
            "requests_total", "requests_active", "bytes_in", "bytes_out",
            "backend_failovers", "failure_events_total", "active_failures",
            "recovery_events")}
        last_backend = None
        last_check = None
        updated_at = None
        for service, stats in snapshots.items():
            baseline = self._lb_metrics_baseline.get(service, {})
            def session_value(key):
                return max(0, int(stats.get(key, 0) or 0) - int(baseline.get(key, 0) or 0))

            for key in totals:
                if key == "requests_active" or key == "active_failures":
                    totals[key] += int(stats.get(key, 0) or 0)
                else:
                    totals[key] += session_value(key)
            service_healthy = list(stats.get("healthy_backends", []))
            service_failed = list(stats.get("failed_backends", []))
            healthy.extend(service_healthy)
            failed.extend(service_failed)
            for backend, count in stats.get("backend_requests", {}).items():
                baseline_count = baseline.get("backend_requests", {}).get(backend, 0)
                backend_requests[backend] = max(0, int(count or 0) - int(baseline_count or 0))
            backends.extend(stats.get("backends", []))
            if stats.get("last_backend"):
                last_backend = stats["last_backend"]
            if stats.get("last_health_check") is not None:
                last_check = max(last_check or 0, stats["last_health_check"])
            if stats.get("updated_at") is not None:
                updated_at = max(updated_at or 0, stats["updated_at"])
            services[service] = {
                "status": "degraded" if stats.get("active_failures", 0) else "running",
                "primary": SERVICE_PAIRS.get(service, {}).get("primary"),
                "backup": SERVICE_PAIRS.get(service, {}).get("backup"),
                "healthy_backends": service_healthy,
                "failed_backends": service_failed,
                "requests_total": session_value("requests_total"),
                "requests_active": stats.get("requests_active", 0),
                "inflight": stats.get("requests_active", 0),
                "backend_failovers": session_value("backend_failovers"),
                "failure_events_total": session_value("failure_events_total"),
                "active_failures": stats.get("active_failures", 0),
                "recovery_events": session_value("recovery_events"),
                "last_backend": stats.get("last_backend"),
                "last_health_check": stats.get("last_health_check"),
            }
        totals["total_failover_requests"] = totals["backend_failovers"]
        totals["inflight"] = totals["requests_active"]
        totals["total_backends"] = len(set(backends))
        totals["healthy_backends"] = sorted(set(healthy))
        totals["failed_backends"] = sorted(set(failed))
        totals["backend_requests"] = backend_requests
        totals["backends"] = sorted(set(backends))
        totals["last_backend"] = last_backend
        totals["last_check"] = last_check
        totals["updated_at"] = updated_at
        totals["health_checks_performed"] = any(
            bool(stats.get("health_checks_performed")) for stats in snapshots.values())
        totals["status"] = ("unavailable" if not snapshots else
                             ("degraded" if totals["active_failures"] else "running"))
        totals["services"] = services
        return totals

    @api_auth_required
    @route("firewall_status", "/firewall/status", methods=["GET"])
    def firewall_status(self, req, **kwargs):
        topology, topology_status = self._topology_status()
        action_events = self._firewall_action_events()
        blocked = 0
        for name in ("blocked_flows", "blocked_devices", "blocked_macs"):
            value = getattr(topology, name, None) if topology is not None else None
            if isinstance(value, dict):
                blocked = max(blocked, len(value))
            elif isinstance(value, (list, set, tuple)):
                blocked = max(blocked, len(value))
            elif isinstance(value, int):
                blocked = max(blocked, value)
        blocked = max(blocked, sum(1 for event in action_events if event.get("blocked")))
        return json_response({"status": "active" if topology is not None else "unavailable",
                              "default_policy": "DROP", "protected_vlans": sorted(VLAN_NETWORKS),
                              "blocked_flows": blocked, "controller_connected": topology is not None,
                              "topology_status": topology_status, "last_update": now_utc(),
                              "source": "topology-monitor-and-traffic-monitor",
                              "event_count": len(action_events)})

    @api_auth_required
    @route("firewall_rules", "/firewall/rules", methods=["GET"])
    def firewall_rules(self, req, **kwargs):
        topology, _ = self._topology_status()
        provider_rules = _call(topology, ["get_firewall_rules", "get_security_rules"], None) if topology else None
        if provider_rules is None and topology is not None:
            provider_rules = getattr(topology, "firewall_rules", None)
        if isinstance(provider_rules, dict):
            provider_rules = list(provider_rules.values())
        rules = list(provider_rules) if isinstance(provider_rules, list) else []
        blocked_devices = getattr(topology, "blocked_devices", {}) if topology is not None else {}
        if isinstance(blocked_devices, dict):
            for mac, details in blocked_devices.items():
                details = details if isinstance(details, dict) else {}
                rules.append({"rule_id": "device-block-%s" % mac.replace(":", ""),
                              "priority": 50000, "action": "DROP", "direction": "ingress",
                              "source": mac, "source_ip": details.get("ip"),
                              "enabled": True, "status": "installed",
                              "reason": details.get("reason"), "blocked_at": details.get("blocked_at"),
                              "source_provider": "topology-monitor"})
        rules.insert(0, {"rule_id": "default-deny", "priority": 1000, "action": "DROP", "direction": "both",
                         "source": "any", "destination": "any", "enabled": True,
                         "status": "installed", "source_provider": "topology-monitor"})
        return json_response(rules)

    @api_auth_required
    @route("firewall_events", "/firewall/events", methods=["GET"])
    def firewall_events(self, req, **kwargs):
        topology = self._topology()
        provider_events = _call(topology, ["get_firewall_events"], []) if topology else []
        events = list(provider_events) if isinstance(provider_events, list) else []
        events.extend(event for event in self.network_event_store
                      if isinstance(event, dict) and any(key in event for key in ("action", "blocked", "rule_id")))
        events.extend(self._firewall_action_events())
        events.sort(key=lambda item: float(item.get("timestamp", 0) or 0))
        return json_response(events[-200:])

    @api_auth_required
    @route("topology_paths", "/topology/paths", methods=["GET"])
    def topology_paths(self, req, **kwargs):
        topology, _ = self._topology_status()
        source = req.GET.get("source") or req.GET.get("src")
        destination = req.GET.get("destination") or req.GET.get("dst")
        active_path = _active_flow_path(topology, source, destination)
        if active_path is not None:
            active_path["history"] = _path_history(topology, source, destination)
            active_path["ssh_events"] = _ssh_events_for_pair(topology, source, destination)
            return json_response([active_path])
        computed = _graph_path(topology, source, destination)
        if computed is not None:
            computed["history"] = _path_history(topology, source, destination)
            computed["ssh_events"] = _ssh_events_for_pair(topology, source, destination)
            return json_response([computed])
        provider_paths = _call(topology, ["get_host_paths", "get_paths"], None) if topology is not None else None
        if isinstance(provider_paths, dict):
            provider_paths = list(provider_paths.values())
        if isinstance(provider_paths, list):
            enriched = []
            for record in provider_paths:
                if not isinstance(record, dict):
                    continue
                item = dict(record)
                item["history"] = _path_history(
                    topology,
                    source or item.get("source") or item.get("src_ip"),
                    destination or item.get("destination") or item.get("dst_ip"),
                )
                enriched.append(item)
            return json_response(enriched)
        active_flow_paths = _call(topology, ["get_active_flow_paths"], None) if topology is not None else None
        if isinstance(active_flow_paths, list) and active_flow_paths:
            enriched = []
            for record in active_flow_paths:
                if not isinstance(record, dict):
                    continue
                item = dict(record)
                item["history"] = _path_history(
                    topology,
                    source or item.get("source") or item.get("src_ip"),
                    destination or item.get("destination") or item.get("dst_ip"),
                )
                enriched.append(item)
            return json_response(enriched)
        saved_paths = []
        for record in self.paths.values():
            if not isinstance(record, dict):
                continue
            item = dict(record)
            item["history"] = _path_history(topology, source, destination)
            saved_paths.append(item)
        return json_response(saved_paths)

    @api_auth_required
    @route("host_path", "/topology/hosts/{host_id}/path", methods=["GET"])
    def host_path(self, req, host_id, **kwargs):
        topology, _ = self._topology_status()
        source = req.GET.get("source") or req.GET.get("src")
        destination = req.GET.get("destination") or req.GET.get("dst") or host_id
        active_path = _active_flow_path(topology, source, destination)
        if active_path is not None:
            active_path["host_id"] = host_id
            active_path["history"] = _path_history(topology, source, destination)
            active_path["ssh_events"] = _ssh_events_for_pair(topology, source, destination)
            return json_response(active_path)
        computed = _graph_path(topology, source, destination)
        if computed is not None:
            computed["history"] = _path_history(topology, source, destination)
            computed["ssh_events"] = _ssh_events_for_pair(topology, source, destination)
            return json_response(computed)
        provider_paths = _call(topology, ["get_host_paths", "get_paths"], None) if topology is not None else None
        if isinstance(provider_paths, dict) and host_id in provider_paths:
            record = dict(provider_paths[host_id])
            record["history"] = _path_history(topology, source, destination, host_id)
            record["ssh_events"] = _ssh_events_for_pair(topology, source, destination)
            return json_response(record)
        if host_id in self.paths:
            record = dict(self.paths[host_id])
            record["history"] = _path_history(topology, source, destination, host_id)
            return json_response(record)
        return json_response({"host_id": host_id, "path": [], "history": _path_history(topology, host_id=host_id), "status": "not_observed"})

    @api_auth_required
    @route("network_events", "/network/events", methods=["GET"])
    def network_events(self, req, **kwargs):
        events = list(self.network_event_store)
        topology = self._topology()
        topology_events = _call(topology, ["get_network_events"], []) if topology else []
        if isinstance(topology_events, list):
            events.extend(topology_events)
        resilience = self._resilience()
        resilience_status = _call(resilience, ["get_status"], {}) or {}
        for event in (resilience_status.get("last_event"), resilience_status.get("last_recovery")):
            if isinstance(event, dict):
                events.append(dict(event, source="resilience"))
        return json_response(events[-500:])

    @api_auth_required
    @route("runtime_clff", "/controller/clff", methods=["GET"])
    def clff(self, req, **kwargs):
        topology, status = self._topology_status()
        ready = bool(topology is not None and status.get("clff_ready", True))
        provider = _call(topology, ["get_clff_status"], None) if topology is not None else None
        result = provider if isinstance(provider, dict) else {
            "enabled": topology is not None, "ready": ready, "algorithm": "bfs_per_root",
            "root_count": len(SWITCH_DPIDS) if ready else 0, "tree_count": len(SWITCH_DPIDS) if ready else 0,
            "broadcast_ports": 0, "uses_ofpp_flood": False, "uses_stp": False,
            "physical_graph_nodes": len(SWITCH_DPIDS), "physical_graph_edges": EXPECTED_INTER_SWITCH_LINKS,
            "last_rebuild_at": None, "last_rebuild_reason": None, "last_error": None,
        }
        result["timestamp"] = now_utc()
        return json_response(result)

    @api_auth_required
    @route("runtime_clff_legacy", "/runtime/clff", methods=["GET"])
    def clff_legacy(self, req, **kwargs):
        """Compatibility alias for clients using the original runtime path."""
        return self.clff(req, **kwargs)

    @api_auth_required
    @route("runtime_resilience", "/controller/resilience", methods=["GET"])
    def resilience(self, req, **kwargs):
        service = self._resilience()
        result = _call(service, ["get_status"], {}) or {}
        return json_response({"enabled": service is not None, "status": "ready" if service else "unknown",
                              "event_count": result.get("event_count", len(self.network_event_store)),
                              "recovery_count": result.get("recovery_count", 0),
                              "last_event_at": result.get("last_event_at"), "last_recovery": result.get("last_recovery"),
                              "last_event": result.get("last_event"), "last_error": None if service else "ResilienceEngine unavailable"})

    @api_auth_required
    @route("runtime_resilience_legacy", "/runtime/resilience", methods=["GET"])
    def resilience_legacy(self, req, **kwargs):
        """Compatibility alias for clients using the original runtime path."""
        return self.resilience(req, **kwargs)


class RuntimeNetworkApi(app_manager.RyuApp):
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stats = StatsCache()
        self.iot_store = IoTTelemetryStore()
        self.paths = OrderedDict()
        self.lb_metrics_baseline = RuntimeNetworkController._load_balancer_stats_by_service()
        # Do not assign to self.events: RyuApp owns that name for its event queue.
        self.network_events = []
        self.traffic_counter_snapshot = {}
        kwargs["wsgi"].register(RuntimeNetworkController, {RUNTIME_API_INSTANCE_NAME: self})
        self.logger.info("SecureIoT Network API registered")

    def record_stats(self, kind, dpid, value):
        if kind not in ("desc", "flow", "port"):
            raise ValueError("stats kind must be desc, flow, or port")
        self.stats.record(kind, dpid, value)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _datapath_state_change(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.stats.register_datapath(datapath)
        elif ev.state == DEAD_DISPATCHER:
            self.stats.unregister_datapath(datapath.id)

    @set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER)
    def _desc_stats_reply(self, ev):
        body = ev.msg.body
        if not body:
            return
        desc = body[0]
        dpid = int(ev.msg.datapath.id)
        clean = lambda name: str(getattr(desc, name, "")).strip("\\x00 ")
        switch_id = "s%d" % dpid
        self.record_stats("desc", ev.msg.datapath.id, {
            "dpid": dpid,
            "switch_id": switch_id,
            "mfr_desc": clean("mfr_desc") or "OpenFlow switch",
            "hw_desc": clean("hw_desc") or "virtual-datapath",
            "sw_desc": clean("sw_desc") or "Ryu/OpenFlow 1.3",
            "serial_num": clean("serial_num") or "dpid-%d" % dpid,
            "dp_desc": clean("dp_desc") or "SecureIoT %s" % switch_id,
            "of_version": "1.3",
            "description_source": "OpenFlow DESC reply; fallback used for empty vendor fields",
            "status": "ready",
        })

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply(self, ev):
        dpid = int(ev.msg.datapath.id)
        ports = []
        for stat in ev.msg.body:
            ports.append({
                "port_no": int(stat.port_no),
                "rx_packets": int(getattr(stat, "rx_packets", 0)),
                "tx_packets": int(getattr(stat, "tx_packets", 0)),
                "rx_bytes": int(getattr(stat, "rx_bytes", 0)),
                "tx_bytes": int(getattr(stat, "tx_bytes", 0)),
                "rx_dropped": int(getattr(stat, "rx_dropped", 0)),
                "tx_dropped": int(getattr(stat, "tx_dropped", 0)),
                "rx_errors": int(getattr(stat, "rx_errors", 0)),
                "tx_errors": int(getattr(stat, "tx_errors", 0)),
                "duration_sec": int(getattr(stat, "duration_sec", 0)),
            })
        self.record_stats("port", dpid, {
            "dpid": dpid,
            "status": "ready",
            "ports": ports,
            "timestamp": now_utc(),
        })

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply(self, ev):
        dpid = int(ev.msg.datapath.id)
        flows = []
        for stat in ev.msg.body:
            flows.append({
                "table_id": int(getattr(stat, "table_id", 0)),
                "priority": int(getattr(stat, "priority", 0)),
                "idle_timeout": int(getattr(stat, "idle_timeout", 0)),
                "hard_timeout": int(getattr(stat, "hard_timeout", 0)),
                "cookie": int(getattr(stat, "cookie", 0)),
                "duration_sec": int(getattr(stat, "duration_sec", 0)),
                "packet_count": int(getattr(stat, "packet_count", 0)),
                "byte_count": int(getattr(stat, "byte_count", 0)),
                "match": str(getattr(stat, "match", "")),
                "instructions": [str(item) for item in (getattr(stat, "instructions", []) or [])],
            })
        self.record_stats("flow", dpid, {
            "dpid": dpid,
            "status": "ready",
            "flows": flows,
            "timestamp": now_utc(),
        })

    def record_path(self, host_id, destination, nodes, links, status="active", event_id=None, reroute_count=0):
        self.paths[host_id] = {"host_id": host_id, "destination": destination, "path_status": status,
                               "nodes": nodes, "links": links, "reroute_count": reroute_count,
                               "last_reroute_event_id": event_id, "last_updated": now_utc()}

    def record_reroute(self, host_id, destination, old_path, new_path, reason="link_failure", status="completed", affected_flows=None):
        """Persist a reroute event and make the new host trace immediately queryable."""
        event_id = "reroute_%06d" % (len(self.network_events) + 1)
        old_nodes = [hop.get("dpid") for hop in old_path if isinstance(hop, dict)]
        new_nodes = [hop.get("dpid") for hop in new_path if isinstance(hop, dict)]
        previous = self.paths.get(host_id, {})
        self.record_path(host_id, destination, new_nodes, new_path, status=status, event_id=event_id,
                         reroute_count=int(previous.get("reroute_count", 0)) + 1)
        self.record_event({"event_id": event_id, "event_type": "rerouting", "status": status,
                           "reason": reason, "host_id": host_id, "old_path": old_path,
                           "new_path": new_path, "old_nodes": old_nodes, "new_nodes": new_nodes,
                           "affected_flows": affected_flows or [], "timestamp": now_utc()})
        return event_id

    def record_event(self, event):
        self.network_events.append(dict(event))
        self.network_events[:] = self.network_events[-500:]
