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
import importlib.util
import json
import os
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
# A switch is active only briefly after a real data-plane counter increase.
# The previous 15-second window made a 5-second IoT polling cycle look like
# every switch was permanently active.
TRAFFIC_ACTIVE_WINDOW = max(
    1.0, float(os.getenv("SECUREIOT_TRAFFIC_ACTIVE_WINDOW", "3"))
)


def now_utc():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def json_response(payload, status=200):
    response = Response(status=status, content_type="application/json", charset="utf-8",
                        body=json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    # CORS is opt-in and limited to the one explicitly configured dashboard origin.
    allowed_origin = os.environ.get("SECUREIOT_ALLOWED_ORIGIN", "").strip().rstrip("/")
    parsed_origin = urlsplit(allowed_origin)
    if (parsed_origin.scheme in ("https", "http") and parsed_origin.netloc
            and parsed_origin.username is None and parsed_origin.password is None
            and parsed_origin.path == "" and not parsed_origin.query and not parsed_origin.fragment):
        response.headers["Access-Control-Allow-Origin"] = allowed_origin
        response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
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
    try:
        import networkx as nx
        nodes = nx.shortest_path(graph, src, dst)
    except Exception:
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
    return {"source": source, "destination": destination, "nodes": path_nodes,
            "status": "active", "links": path_links, "computed": True, "last_updated": now_utc()}


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

    @staticmethod
    def _topology():
        return app_manager.lookup_service_brick("TopologyMonitor")

    @staticmethod
    def _resilience():
        return app_manager.lookup_service_brick("ResilienceEngine")

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

    def _traffic_dpids(self):
        """Return DPIDs with recent growth on endpoint access-port counters."""
        active = set()
        topology = self._topology()
        host_activity = getattr(topology, "switch_traffic_last_seen", None) if topology is not None else None
        if not isinstance(host_activity, dict):
            host_activity = getattr(topology, "host_traffic_last_seen", {}) if topology is not None else {}
        now = time.time()
        if isinstance(host_activity, dict):
            for key, observed_at in host_activity.items():
                try:
                    dpid = key[0] if isinstance(key, tuple) else key
                    if now - float(observed_at) <= TRAFFIC_ACTIVE_WINDOW:
                        active.add(int(dpid))
                except (TypeError, ValueError, IndexError):
                    continue
            return active

        # Compatibility fallback for older TopologyMonitor versions.
        # TopologyMonitor stores (byte_counter, sample_time) in this map, and
        # only for currently discovered inter-switch ports.
        samples = getattr(topology, "port_stats_previous", {}) if topology is not None else {}
        port_to_link = getattr(topology, "port_to_link", {}) if topology is not None else {}
        now = time.time()
        if isinstance(samples, dict):
            for key, sample in samples.items():
                if not isinstance(key, tuple) or len(key) != 2:
                    continue
                try:
                    dpid, _port_no = int(key[0]), int(key[1])
                    counter, observed_at = sample
                    counter, observed_at = float(counter), float(observed_at)
                    old = self._traffic_counter_snapshot.get(key)
                    self._traffic_counter_snapshot[key] = (counter, observed_at)
                    if (old is None or counter <= float(old[0])
                            or now - observed_at > TRAFFIC_ACTIVE_WINDOW):
                        continue
                    active.add(dpid)
                    peer = port_to_link.get(key)
                    if isinstance(peer, (tuple, list)) and peer:
                        active.add(int(peer[0]))
                except (TypeError, ValueError, IndexError):
                    continue
        return active

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

    # Lab-mode telemetry ingress is intentionally public because the internal
    # server-side poller POSTs fresh readings through the configured ngrok
    # endpoint. Read/query endpoints remain protected below.
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
    @route("runtime_controller_legacy", "/runtime/controller", methods=["GET"])
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
        active_dpids = self._traffic_dpids()
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
                           "last_traffic_at": (item.get("last_traffic_at")
                                                if dpid in active_dpids else None)}))
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
        host_activity = getattr(topology, "host_traffic_last_seen", {}) if topology is not None else {}
        now = time.time()
        telemetry_online = set()
        try:
            telemetry_online = {
                str(device.get("device_id"))
                for device in self.iot_store.devices()
                if isinstance(device, dict) and device.get("status") == "online"
            }
        except Exception:
            telemetry_online = set()
        for host_id in sorted(HOST_SWITCHES, key=lambda x: int(x[1:])):
            observed_row = observed_by_ip.get(HOST_IPS[host_id])
            item = dict(observed_row[1]) if observed_row else {}
            observed_mac = observed_row[0] if observed_row else item.get("mac")
            dpid = int(item.get("dpid") or SWITCH_DPIDS[HOST_SWITCHES[host_id]])
            host_index = sum(1 for h in HOST_SWITCHES if HOST_SWITCHES[h] == HOST_SWITCHES[host_id] and int(h[1:]) < int(host_id[1:]))
            provider_port = (access_ports.get(dpid) or [])[host_index % len(access_ports.get(dpid, [1]))] if access_ports.get(dpid) else 1 + (host_index % 48)
            port_no = int(item.get("port") or item.get("port_no") or provider_port)
            observed_at = host_activity.get((dpid, port_no)) if isinstance(host_activity, dict) else None
            host_active = False
            if observed_at is not None:
                try:
                    host_active = now - float(observed_at) <= TRAFFIC_ACTIVE_WINDOW
                except (TypeError, ValueError):
                    host_active = False
            flows = item.get("active_flows") if isinstance(item.get("active_flows"), list) else []
            if not host_active:
                flows = []
            flow_active = bool(flows)
            telemetry_active = host_id in telemetry_online
            # Port counters alone include ARP and load-balancer health checks.
            # A host is active for this endpoint only when that recent traffic
            # is corroborated by fresh telemetry or a registered flow.
            host_active = bool(host_active and (telemetry_active or flow_active))
            if not host_active:
                flows = []
            primary_flow = flows[0] if flows else {}
            fallback_path = self.paths.get(host_id, {}) if host_active else {}
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
                           "last_traffic_at": observed_at,
                           "active_flows": flows,
                           "path": primary_flow.get("path", fallback_path.get("nodes", [])),
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
        service = SERVICE_PAIRS.get("http_api", {})
        stats = self._load_balancer_stats() or {}
        return json_response({"service_id": "secureiot-lb", "host_id": LOAD_BALANCER_CONFIG.get("host"),
                              "vip": LOAD_BALANCER_IP,
                              "status": "running" if stats else "configured",
                              "algorithm": "round_robin", "backend_count": len(stats.get("backends", [])) or 2,
                              "frontends": list(LOAD_BALANCER_CONFIG.get("frontends", ())),
                              "service_port": service.get("port"),
                              "requests_total": stats.get("requests_total", 0),
                              "last_backend": stats.get("last_backend"),
                              "backend_requests": stats.get("backend_requests", {}),
                              "healthy_backends": stats.get("healthy_backends", [])})

    @api_auth_required
    @route("load_balancer_status", "/network/load-balancer/status", methods=["GET"])
    def load_balancer_status(self, req, **kwargs):
        stats = self._load_balancer_stats()
        if stats is None:
            return json_response({"status": "unavailable", "health_checks_performed": False,
                                  "healthy_backends": [], "total_backends": 2, "last_check": None,
                                  "source": "stats-file-unavailable"}, status=503)
        healthy = stats.get("healthy_backends", [])
        return json_response({"status": "running", "health_checks_performed": bool(stats.get("health_checks_performed")),
                              "healthy_backends": healthy, "total_backends": len(stats.get("backends", [])) or 2,
                              "last_check": stats.get("last_health_check"),
                              "updated_at": stats.get("updated_at"), "source": "shared-load-balancer-stats"})

    @api_auth_required
    @route("load_balancer_backends", "/network/load-balancer/backends", methods=["GET"])
    def load_balancer_backends(self, req, **kwargs):
        service = SERVICE_PAIRS.get("http_api", {})
        stats = self._load_balancer_stats() or {}
        healthy = set(stats.get("healthy_backends", []))
        checked = bool(stats.get("health_checks_performed"))
        backends = []
        for key in ("primary", "backup"):
            host_id = service.get(key)
            if host_id and host_id in HOST_IPS:
                backends.append({"backend_id": host_id,
                                 "address": "%s:%s" % (HOST_IPS[host_id], service.get("port", 5000)),
                                 "status": ("healthy" if "%s:%s" % (HOST_IPS[host_id], service.get("port", 5000)) in healthy
                                             else ("unhealthy" if checked else "unknown")),
                                 "health_checked": checked, "weight": 1,
                                 "last_check": stats.get("last_health_check")})
        return json_response(backends)

    @api_auth_required
    @route("load_balancer_stats", "/network/load-balancer/stats", methods=["GET"])
    def load_balancer_stats(self, req, **kwargs):
        value = self._load_balancer_stats()
        if value is not None:
            value["timestamp"] = now_utc()
            value["source"] = "shared-load-balancer-stats"
            return json_response(value)
        return json_response({"status": "unavailable", "requests_total": 0, "requests_active": 0,
                              "bytes_in": 0, "bytes_out": 0, "backend_failovers": 0,
                              "timestamp": now_utc(), "source": "stats-file-unavailable"}, status=503)

    @staticmethod
    def _load_balancer_stats():
        path = os.environ.get("SECUREIOT_LB_STATS_FILE", "/var/tmp/secureiot-lb-stats.json")
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None

    @api_auth_required
    @route("firewall_status", "/firewall/status", methods=["GET"])
    def firewall_status(self, req, **kwargs):
        topology, topology_status = self._topology_status()
        blocked = 0
        for name in ("blocked_flows", "blocked_devices", "blocked_macs"):
            value = getattr(topology, name, None) if topology is not None else None
            if isinstance(value, dict):
                blocked = max(blocked, len(value))
            elif isinstance(value, (list, set, tuple)):
                blocked = max(blocked, len(value))
            elif isinstance(value, int):
                blocked = max(blocked, value)
        return json_response({"status": "active" if topology is not None else "unavailable",
                              "default_policy": "DROP", "protected_vlans": sorted(VLAN_NETWORKS),
                              "blocked_flows": blocked, "controller_connected": topology is not None,
                              "topology_status": topology_status, "last_update": now_utc(),
                              "source": "topology-monitor-and-traffic-monitor"})

    @api_auth_required
    @route("firewall_rules", "/firewall/rules", methods=["GET"])
    def firewall_rules(self, req, **kwargs):
        topology, _ = self._topology_status()
        provider_rules = _call(topology, ["get_firewall_rules", "get_security_rules"], None) if topology else None
        if provider_rules is None and topology is not None:
            provider_rules = getattr(topology, "firewall_rules", None)
        if isinstance(provider_rules, dict):
            provider_rules = list(provider_rules.values())
        if isinstance(provider_rules, list):
            return json_response(provider_rules)
        return json_response([{"rule_id": "default-deny", "priority": 1000, "action": "DROP", "direction": "both",
                               "source": "any", "destination": "any", "enabled": True,
                               "status": "installed", "source_provider": "topology-monitor"}])

    @api_auth_required
    @route("firewall_events", "/firewall/events", methods=["GET"])
    def firewall_events(self, req, **kwargs):
        topology = self._topology()
        provider_events = _call(topology, ["get_firewall_events"], []) if topology else []
        events = list(provider_events) if isinstance(provider_events, list) else []
        events.extend(event for event in self.network_event_store
                      if isinstance(event, dict) and any(key in event for key in ("action", "blocked", "rule_id")))
        return json_response(events[-200:])

    @api_auth_required
    @route("topology_paths", "/topology/paths", methods=["GET"])
    def topology_paths(self, req, **kwargs):
        topology, _ = self._topology_status()
        source = req.GET.get("source") or req.GET.get("src")
        destination = req.GET.get("destination") or req.GET.get("dst")
        computed = _graph_path(topology, source, destination)
        if computed is not None:
            return json_response([computed])
        provider_paths = _call(topology, ["get_host_paths", "get_paths"], None) if topology is not None else None
        if isinstance(provider_paths, dict):
            return json_response(list(provider_paths.values()))
        if isinstance(provider_paths, list):
            return json_response(provider_paths)
        active_flow_paths = _call(topology, ["get_active_flow_paths"], None) if topology is not None else None
        if isinstance(active_flow_paths, list) and active_flow_paths:
            return json_response(active_flow_paths)
        return json_response(list(self.paths.values()))

    @api_auth_required
    @route("host_path", "/topology/hosts/{host_id}/path", methods=["GET"])
    def host_path(self, req, host_id, **kwargs):
        topology, _ = self._topology_status()
        source = req.GET.get("source") or req.GET.get("src")
        destination = req.GET.get("destination") or req.GET.get("dst") or host_id
        computed = _graph_path(topology, source, destination)
        if computed is not None:
            return json_response(computed)
        provider_paths = _call(topology, ["get_host_paths", "get_paths"], None) if topology is not None else None
        if isinstance(provider_paths, dict) and host_id in provider_paths:
            return json_response(provider_paths[host_id])
        if host_id in self.paths:
            return json_response(self.paths[host_id])
        return json_response({"host_id": host_id, "path": [], "status": "not_observed"})

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
    @route("runtime_clff_legacy", "/runtime/clff", methods=["GET"])
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
    @route("runtime_resilience", "/controller/resilience", methods=["GET"])
    @route("runtime_resilience_legacy", "/runtime/resilience", methods=["GET"])
    def resilience(self, req, **kwargs):
        service = self._resilience()
        result = _call(service, ["get_status"], {}) or {}
        return json_response({"enabled": service is not None, "status": "ready" if service else "unknown",
                              "event_count": result.get("event_count", len(self.network_event_store)),
                              "recovery_count": result.get("recovery_count", 0),
                              "last_event_at": result.get("last_event_at"), "last_recovery": result.get("last_recovery"),
                              "last_event": result.get("last_event"), "last_error": None if service else "ResilienceEngine unavailable"})


class RuntimeNetworkApi(app_manager.RyuApp):
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stats = StatsCache()
        self.iot_store = IoTTelemetryStore()
        self.paths = OrderedDict()
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
