#!/usr/bin/env python3
"""Regression checks for dynamically reported HTTP/Load Balancer activity."""
import ast
import time
from pathlib import Path
from datetime import datetime, timezone
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent


def extract_function(source_path, function_name, class_name=None, namespace=None):
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    parent = tree
    if class_name is not None:
        parent = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == class_name
        )
    function = next(
        node for node in parent.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == function_name
    )
    function.decorator_list = []
    module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    scope = dict(namespace or {})
    exec(compile(module, str(source_path), "exec"), scope)
    return scope[function_name]


def test_http_flow_stats_refresh_activity():
    flow_handler = extract_function(
        ROOT / "topology_monitor.py",
        "flow_stats_reply_handler",
        class_name="TopologyMonitor",
        namespace={
            "ACTIVITY_TRACK_PRIORITY": 110,
            "HTTP_ACTIVITY_PORTS": frozenset({80, 443, 5000, 8080, 8081}),
            "SSH_ACTIVITY_PORT": 22,
            "SSH_ACTIVITY_PORTS": frozenset({22, 2222}),
            "SERVICE_ACTIVITY_PORTS": frozenset({53, 22, 2222, 80, 443, 5000, 8080, 8081}),
            "time": SimpleNamespace(time=lambda: 125.0),
        },
    )

    class Monitor:
        def __init__(self):
            self.flow_stats_previous = {}
            self.switch_traffic_last_seen = {}
            self.ping_traffic_last_seen = {}
            self.host_traffic_last_seen = {}
            self.web_traffic_last_seen = {}
            self.ssh_traffic_last_seen = {}
            self.service_traffic_last_seen = {}
            self.active_flows = {
                "web": {
                    "src_ip": "10.10.20.21",
                    "dst_ip": "10.10.20.100",
                    "ip_proto": 6,
                    "tcp_src_port": 49152,
                    "tcp_dst_port": 5000,
                    "last_seen": 100.0,
                }
            }

    def event(packets, byte_count):
        stat = SimpleNamespace(
            priority=110,
            table_id=0,
            cookie=9,
            match={
                "ip_proto": 6,
                "ipv4_src": "10.10.20.21",
                "ipv4_dst": "10.10.20.100",
                "tcp_src": 49152,
                "tcp_dst": 5000,
            },
            packet_count=packets,
            byte_count=byte_count,
        )
        return SimpleNamespace(msg=SimpleNamespace(
            datapath=SimpleNamespace(id=4), body=[stat]
        ))

    monitor = Monitor()
    flow_handler(monitor, event(10, 800))  # baseline sample is not activity
    assert monitor.switch_traffic_last_seen == {}
    flow_handler(monitor, event(14, 1200))  # counter delta proves current traffic

    assert monitor.switch_traffic_last_seen == {4: 125.0}
    assert monitor.web_traffic_last_seen == {
        "10.10.20.21": 125.0,
        "10.10.20.100": 125.0,
    }
    assert monitor.host_traffic_last_seen == monitor.web_traffic_last_seen
    assert monitor.ping_traffic_last_seen == {}
    assert monitor.active_flows["web"]["last_seen"] == 125.0
    assert monitor.active_flows["web"]["activity_source"] == "openflow_counter_delta"


def test_http_packet_observation_marks_activity_immediately():
    register_flow = extract_function(
        ROOT / "topology_monitor.py",
        "register_active_flow",
        class_name="TopologyMonitor",
        namespace={
            "HTTP_ACTIVITY_PORTS": frozenset({80, 443, 5000, 8080, 8081}),
            "SSH_ACTIVITY_PORT": 22,
            "SSH_ACTIVITY_PORTS": frozenset({22, 2222}),
            "time": SimpleNamespace(time=lambda: 200.0),
        },
    )

    class Monitor:
        def __init__(self):
            self.active_flows = {}
            self.host_traffic_last_seen = {}
            self.web_traffic_last_seen = {}
            self.ping_traffic_last_seen = {}
            self.switch_traffic_last_seen = {}
            self.congestion_last_reroute = {}

        def _record_path_history(self, *args, **kwargs):
            pass

    monitor = Monitor()
    register_flow(monitor, "http", {
        "src_ip": "10.10.20.21",
        "dst_ip": "10.10.20.100",
        "src_mac": "02:00:00:00:00:21",
        "dst_mac": "02:00:00:00:00:38",
        "vlan_id": 20,
        "ip_proto": 6,
        "tcp_dst_port": 5000,
        "path": [3, 1],
        "path_status": "active",
    })

    assert monitor.active_flows["http"]["last_seen"] == 200.0
    assert monitor.web_traffic_last_seen == {
        "10.10.20.21": 200.0,
        "10.10.20.100": 200.0,
    }
    assert monitor.switch_traffic_last_seen == {3: 200.0, 1: 200.0}


def test_api_classifies_ping_web_and_ssh_services():
    classify = extract_function(
        ROOT / "runtime_network_api.py",
        "_flow_activity_category",
        namespace={
            "HTTP_ACTIVITY_PORTS": frozenset({80, 443, 5000, 8080, 8081}),
            "SSH_ACTIVITY_PORT": 22,
            "SSH_ACTIVITY_PORTS": frozenset({22, 2222}),
            "SERVICE_ACTIVITY_PORTS": frozenset({53, 80, 443, 5000, 8080, 8081, 22, 2222}),
            "LOAD_BALANCER_PORTS": {443, 5000},
            "LOAD_BALANCER_IP": "10.10.20.100",
        },
    )

    assert classify({"ip_proto": 1, "icmp_type": 8}) == "ping"
    assert classify({
        "ip_proto": 6, "tcp_dst_port": 5000,
        "src_ip": "10.10.20.21", "dst_ip": "10.10.20.100",
    }) == "load_balancer"
    assert classify({
        "ip_proto": 6, "tcp_dst_port": 443,
        "src_ip": "10.10.20.4", "dst_ip": "10.10.20.19",
    }) == "http"
    assert classify({
        "ip_proto": 6, "tcp_dst_port": 5000,
        "src_ip": "10.10.20.100", "dst_ip": "10.10.20.2",
    }) == "load_balancer"
    assert classify({"ip_proto": 6, "tcp_dst_port": 80}) == "http"
    assert classify({"ip_proto": 6, "tcp_dst_port": 22}) == "ssh"
    assert classify({"ip_proto": 6, "tcp_src_port": 22}) == "ssh"
    assert classify({"ip_proto": 17, "udp_dst_port": 53}) == "dns"


def test_hosts_endpoint_exposes_recent_load_balancer_activity():
    source_path = ROOT / "runtime_network_api.py"
    classify = extract_function(
        source_path,
        "_flow_activity_category",
        namespace={
            "HTTP_ACTIVITY_PORTS": frozenset({80, 443, 5000, 8080, 8081}),
            "SSH_ACTIVITY_PORT": 22,
            "SSH_ACTIVITY_PORTS": frozenset({22, 2222}),
            "SERVICE_ACTIVITY_PORTS": frozenset({53, 80, 443, 5000, 8080, 8081, 22, 2222}),
            "LOAD_BALANCER_PORTS": {443, 5000},
            "LOAD_BALANCER_IP": "10.10.20.100",
        },
    )
    hosts_handler = extract_function(
        source_path,
        "hosts",
        class_name="RuntimeNetworkController",
        namespace={
            "HOSTS": {"h2": {}, "h21": {}, "h38": {}},
            "HOST_IPS": {
                "h2": "10.10.20.2",
                "h21": "10.10.20.21",
                "h38": "10.10.20.100",
            },
            "HOST_VLANS": {"h2": 20, "h21": 20, "h38": 20},
            "HOST_SWITCHES": {"h2": "s1", "h21": "s3", "h38": "s2"},
            "SWITCH_DPIDS": {"s1": 1, "s2": 2, "s3": 3},
            "TRAFFIC_ACTIVE_WINDOW": 8.0,
            "TELEMETRY_ACTIVE_WINDOW": 15.0,
            "time": time,
            "datetime": datetime,
            "timezone": timezone,
            "_flow_activity_category": classify,
            "_ssh_audit_events": lambda: [],
            "_parse_utc_timestamp": lambda value: (
                datetime.fromtimestamp(float(value), tz=timezone.utc)
                if isinstance(value, (int, float))
                else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            ),
            "_timestamp_is_recent": lambda value, age: (
                value is not None
                and 0 <= time.time() - float(value) <= age
            ),
            "_call": lambda obj, names, default=None: next(
                (getattr(obj, name)() for name in names
                 if callable(getattr(obj, name, None))), default
            ),
            "_graph_path": lambda *args, **kwargs: None,
            "_path_history": lambda *args, **kwargs: [],
            "compact": lambda value: value,
            "json_response": lambda value: value,
        },
    )

    now = time.time()
    flow = {
        "src_ip": "10.10.20.21",
        "dst_ip": "10.10.20.100",
        "ip_proto": 6,
        "tcp_src_port": 49152,
        "tcp_dst_port": 5000,
        "path": [3, 1, 2],
        "path_type": "inter_switch",
        "path_status": "active",
        "last_seen": now,
    }

    class Topology:
        datapaths = {1: object(), 2: object(), 3: object()}
        vlan_port_map = {}
        ping_traffic_last_seen = {}
        web_traffic_last_seen = {
            "10.10.20.21": now,
            "10.10.20.100": now,
        }

        def get_host_inventory(self):
            return {}

        def get_active_flow_paths(self):
            return [flow]

    class Api:
        paths = {}
        iot_store = SimpleNamespace(devices=lambda: [])

        def _topology_status(self):
            return Topology(), {}

    rows = hosts_handler(Api(), SimpleNamespace(GET={}))
    by_id = {row["host_id"]: row for row in rows}
    assert by_id["h21"]["traffic_active"] is True
    assert by_id["h38"]["traffic_active"] is True
    assert by_id["h21"]["active_flows"][0]["traffic_category"] == "load_balancer"
    assert by_id["h21"]["path"] == [3, 1, 2]

    stale_flow = dict(flow, last_seen=now - 20)
    class StaleTopology(Topology):
        web_traffic_last_seen = {
            "10.10.20.21": now - 20,
            "10.10.20.100": now - 20,
        }

        def get_active_flow_paths(self):
            return [stale_flow]

    class StaleApi(Api):
        def _topology_status(self):
            return StaleTopology(), {}

    stale_rows = hosts_handler(StaleApi(), SimpleNamespace(GET={}))
    stale_by_id = {row["host_id"]: row for row in stale_rows}
    assert stale_by_id["h21"]["traffic_active"] is False
    assert stale_by_id["h21"]["active_flows"] == []


if __name__ == "__main__":
    test_http_flow_stats_refresh_activity()
    test_http_packet_observation_marks_activity_immediately()
    test_api_classifies_ping_web_and_ssh_services()
    test_hosts_endpoint_exposes_recent_load_balancer_activity()
    print("PASS: HTTP/LB activity refreshes and is classified dynamically")
