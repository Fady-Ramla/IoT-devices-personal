#!/usr/bin/env python3
"""Regression checks for SSH activity and sanitized sshd audit visibility."""
import ast
import hashlib
import ipaddress
import os
import re
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent


def extract_function(source_path, function_name, class_name=None, namespace=None):
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    parent = tree
    if class_name is not None:
        parent = next(node for node in tree.body
                      if isinstance(node, ast.ClassDef) and node.name == class_name)
    function = next(node for node in parent.body
                    if isinstance(node, ast.FunctionDef) and node.name == function_name)
    function.decorator_list = []
    module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    scope = dict(namespace or {})
    exec(compile(module, str(source_path), "exec"), scope)
    return scope[function_name]


def test_ssh_openflow_counter_delta_marks_hosts_and_switch():
    handler = extract_function(
        ROOT / "topology_monitor.py", "flow_stats_reply_handler", "TopologyMonitor",
        {
            "ACTIVITY_TRACK_PRIORITY": 110,
            "HTTP_ACTIVITY_PORTS": frozenset({80, 443, 5000, 8080, 8081}),
            "SSH_ACTIVITY_PORT": 22,
            "time": SimpleNamespace(time=lambda: 300.0),
        },
    )

    class Monitor:
        flow_stats_previous = {}
        switch_traffic_last_seen = {}
        ping_traffic_last_seen = {}
        host_traffic_last_seen = {}
        web_traffic_last_seen = {}
        ssh_traffic_last_seen = {}
        active_flows = {
            "flow": {
                "src_ip": "10.10.40.36", "dst_ip": "10.10.20.4",
                "ip_proto": 6, "tcp_src_port": 49152, "tcp_dst_port": 22,
                "last_seen": 250.0,
            }
        }

    def reply(packets):
        stat = SimpleNamespace(
            priority=110, table_id=0, cookie=44,
            match={
                "ip_proto": 6, "ipv4_src": "10.10.40.36",
                "ipv4_dst": "10.10.20.4", "tcp_src": 49152, "tcp_dst": 22,
            },
            packet_count=packets, byte_count=packets * 64,
        )
        return SimpleNamespace(msg=SimpleNamespace(
            datapath=SimpleNamespace(id=5), body=[stat]
        ))

    monitor = Monitor()
    handler(monitor, reply(1))  # establish baseline
    handler(monitor, reply(3))  # only the delta marks actual SSH traffic
    assert monitor.switch_traffic_last_seen == {5: 300.0}
    assert monitor.ssh_traffic_last_seen == {
        "10.10.40.36": 300.0,
        "10.10.20.4": 300.0,
    }
    assert monitor.active_flows["flow"]["last_seen"] == 300.0
    assert monitor.web_traffic_last_seen == {}


def test_ssh_log_events_are_sanitized_and_map_client_server():
    source_path = ROOT / "runtime_network_api.py"
    parse_timestamp = extract_function(
        source_path, "_ssh_log_timestamp",
        namespace={
            "re": re, "datetime": datetime, "timezone": timezone, "time": time,
            "_parse_utc_timestamp": lambda value: datetime.fromisoformat(
                value.replace("Z", "+00:00")
            ),
        },
    )
    now = time.time()
    prefix = time.strftime("%b %d %H:%M:%S", time.localtime(now))
    with tempfile.TemporaryDirectory() as log_dir:
        log_path = Path(log_dir) / "secureiot-sshd-h4.log"
        log_path.write_text(
            f"{prefix} vm sshd[99]: Connection from 10.10.40.36 port 49152 on 10.10.20.4 port 22\n"
            f"{prefix} vm sshd[99]: Accepted password for private_user from 10.10.40.36 port 49152 ssh2\n"
            f"{prefix} vm sshd[99]: Failed password for private_user from 10.10.40.36 port 49153 ssh2\n",
            encoding="utf-8",
        )
        parser = extract_function(
            source_path, "_ssh_audit_events",
            namespace={
                "time": time, "os": os, "re": re, "hashlib": hashlib,
                "datetime": datetime, "timezone": timezone,
                "HOST_IPS": {"h36": "10.10.40.36", "h4": "10.10.20.4"},
                "SSH_AUDIT_LOG_DIR": str(log_dir),
                "SSH_ACTIVITY_PORT": 22,
                "SSH_AUDIT_LOG_MAX_BYTES": 256 * 1024,
                "SSH_AUDIT_EVENT_MAX_AGE": 24 * 60 * 60,
                "_ssh_log_timestamp": parse_timestamp,
            },
        )
        events = parser(now)

    assert [event["event_type"] for event in events] == [
        "connection_attempt", "login_success", "login_failure",
    ]
    assert all(event["source_host_id"] == "h36" for event in events)
    assert all(event["destination_host_id"] == "h4" for event in events)
    assert all(event["destination_port"] == 22 for event in events)
    assert all("private_user" not in repr(event) for event in events)
    assert all("password" not in event for event in events)
    assert all("log_file_mtime" not in event["timestamp_source"] for event in events)


def test_hosts_endpoint_adds_ssh_events_to_both_participants():
    source_path = ROOT / "runtime_network_api.py"
    now = time.time()
    event = {
        "event_id": "ssh_example", "event_type": "login_success",
        "auth_status": "success", "source_host_id": "h36",
        "destination_host_id": "h4", "source_ip": "10.10.40.36",
        "destination_ip": "10.10.20.4", "destination_port": 22,
        "timestamp": datetime.fromtimestamp(now, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    active_path = extract_function(
        source_path, "_flow_activity_category",
        namespace={
            "HTTP_ACTIVITY_PORTS": frozenset({80, 443, 5000, 8080, 8081}),
            "SSH_ACTIVITY_PORT": 22,
            "LOAD_BALANCER_IP": "10.10.20.100",
        },
    )
    hosts = extract_function(
        source_path, "hosts", "RuntimeNetworkController",
        {
            "HOSTS": {"h36": {}, "h4": {}},
            "HOST_IPS": {"h36": "10.10.40.36", "h4": "10.10.20.4"},
            "HOST_VLANS": {"h36": 40, "h4": 20},
            "HOST_SWITCHES": {"h36": "s5", "h4": "s2"},
            "SWITCH_DPIDS": {"s2": 2, "s5": 5},
            "TRAFFIC_ACTIVE_WINDOW": 8.0,
            "TELEMETRY_ACTIVE_WINDOW": 15.0,
            "time": time, "datetime": datetime, "timezone": timezone,
            "_flow_activity_category": active_path,
            "_ssh_audit_events": lambda: [dict(event)],
            "_parse_utc_timestamp": lambda value: (
                datetime.fromtimestamp(float(value), tz=timezone.utc)
                if isinstance(value, (int, float))
                else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            ),
            "_timestamp_is_recent": lambda value, age: (
                value is not None and 0 <= time.time() - float(value) <= age
            ),
            "_call": lambda obj, names, default=None: next(
                (getattr(obj, name)() for name in names
                 if callable(getattr(obj, name, None))), default
            ),
            "_ssh_path_info": lambda *args, **kwargs: {
                "path": [5, 2], "path_source": "computed", "path_status": "active",
            },
            "_path_history": lambda *args, **kwargs: [],
            "compact": lambda value: value,
            "json_response": lambda value: value,
        },
    )

    class Topology:
        datapaths = {2: object(), 5: object()}
        vlan_port_map = {}
        ping_traffic_last_seen = {}
        web_traffic_last_seen = {}
        ssh_traffic_last_seen = {}

        def get_host_inventory(self):
            return {}

        def get_active_flow_paths(self):
            return []

    class Api:
        paths = {}
        iot_store = SimpleNamespace(devices=lambda: [])

        def _topology_status(self):
            return Topology(), {}

    rows = hosts(Api(), SimpleNamespace(GET={}))
    by_id = {row["host_id"]: row for row in rows}
    for host_id in ("h36", "h4"):
        assert by_id[host_id]["ssh_events"][0]["event_type"] == "login_success"
        assert by_id[host_id]["ssh_events"][0]["path"] == [5, 2]
        assert by_id[host_id]["ssh_events"][0]["path_source"] == "computed"
        # Authentication history alone is not mislabeled as live data-plane activity.
        assert by_id[host_id]["traffic_active"] is False

    flow = {
        "src_ip": "10.10.40.36", "dst_ip": "10.10.20.4",
        "ip_proto": 6, "tcp_src_port": 49152, "tcp_dst_port": 22,
        "path": [5, 2], "path_type": "inter_switch",
        "path_status": "active", "last_seen": now,
    }

    class LiveTopology(Topology):
        ssh_traffic_last_seen = {"10.10.40.36": now, "10.10.20.4": now}

        def get_active_flow_paths(self):
            return [flow]

    class LiveApi(Api):
        def _topology_status(self):
            return LiveTopology(), {}

    live_rows = hosts(LiveApi(), SimpleNamespace(GET={}))
    live_by_id = {row["host_id"]: row for row in live_rows}
    for host_id in ("h36", "h4"):
        assert live_by_id[host_id]["traffic_active"] is True
        assert live_by_id[host_id]["active_flows"][0]["traffic_category"] == "ssh"


def test_ssh_access_policy_drops_nonmanagement_vlan_traffic():
    purge_legacy_rules = extract_function(
        ROOT / "topology_monitor.py", "_purge_legacy_ssh_vlan_drop_rules",
        "TopologyMonitor",
        {
            "SSH_DENIED_VLANS": frozenset({10, 20, 30, 50}),
            "SSH_PROTECTED_SERVERS": {
                "h4": "10.10.20.4", "h20": "10.10.20.20",
            },
            "SSH_ACTIVITY_PORT": 22,
            "SSH_POLICY_PRIORITY": 49999,
            "OFPVID_PRESENT": 0x1000,
        },
    )
    install_policy = extract_function(
        ROOT / "topology_monitor.py", "_install_ssh_policy_rules", "TopologyMonitor",
        {
            "SSH_DENIED_VLANS": frozenset({10, 20, 30, 50}),
            "SSH_PROTECTED_SERVERS": {
                "h4": "10.10.20.4", "h20": "10.10.20.20",
            },
            "SSH_ACTIVITY_PORT": 22,
            "SSH_POLICY_PRIORITY": 49999,
            "SSH_MANAGEMENT_HOSTS": {
                "h36": "10.10.40.36", "h37": "10.10.40.37",
            },
            "OFPVID_NONE": 0,
            "OFPVID_PRESENT": 0x1000,
            "ipaddress": ipaddress,
        },
    )

    class Parser:
        @staticmethod
        def OFPMatch(**fields):
            return fields

        @staticmethod
        def OFPFlowMod(**fields):
            return fields

        @staticmethod
        def OFPActionOutput(port, max_len):
            return {"type": "output", "port": port, "max_len": max_len}

    class Monitor:
        vlan_port_map = {
            (2, 1): {"kind": "access", "vlan_id": 20, "host_id": "h21"},
            (2, 2): {"kind": "access", "vlan_id": 40, "host_id": "h36"},
            (2, 3): {"kind": "trunk", "vlan_id": None},
            (2, 4): {"kind": "access", "vlan_id": 40, "host_id": "h19"},
        }
        vlan_networks = {
            10: ipaddress.ip_network("10.10.10.0/24"),
            20: ipaddress.ip_network("10.10.20.0/24"),
            30: ipaddress.ip_network("10.10.30.0/24"),
            40: ipaddress.ip_network("10.10.40.0/24"),
            50: ipaddress.ip_network("10.10.50.0/24"),
        }
        ssh_policy_flows = {}
        ssh_policy_switches = set()
        ssh_policy_failed_switches = set()
        logger = SimpleNamespace(exception=lambda *args, **kwargs: None)

        def _purge_legacy_ssh_vlan_drop_rules(self, datapath):
            return purge_legacy_rules(self, datapath)

        def _add_flow(self, datapath, priority, match, actions, track_key=None):
            self.installed.append((priority, match, actions))

    monitor = Monitor()
    monitor.installed = []
    datapath = SimpleNamespace(
        id=2, ofproto_parser=Parser(),
        ofproto=SimpleNamespace(
            OFPFC_DELETE_STRICT=4, OFPP_ANY=0xFFFFFFFC,
            OFPG_ANY=0xFFFFFFFF, OFPP_CONTROLLER=0xFFFFFFFD,
            OFPCML_NO_BUFFER=0xFFFF),
        sent_messages=[],
    )
    datapath.send_msg = datapath.sent_messages.append
    assert install_policy(monitor, datapath) is True
    assert len(monitor.installed) == 14  # non-IT access guards + trunk guards
    assert len(datapath.sent_messages) == 12  # old IPv4 and IPv6 trunk drops
    assert all(message["priority"] == 49999
               and message["command"] == 4
               for message in datapath.sent_messages)
    assert all(priority == 49999 for priority, _match, _actions in monitor.installed)
    assert {match["ipv4_dst"] for _, match, _ in monitor.installed
            if "ipv4_dst" in match} == {
        "10.10.20.4", "10.10.20.20",
    }
    assert all(match["ip_proto"] == 6 and match["tcp_dst"] == 22
               for _, match, _ in monitor.installed)
    assert sum(match["eth_type"] == 0x86DD
               for _, match, _ in monitor.installed) == 2
    assert all(match["in_port"] != 2 for _, match, _ in monitor.installed)
    access_rules = [match for _, match, _ in monitor.installed
                    if match["in_port"] == 1]
    unauthorized_management_rules = [match for _, match, _ in monitor.installed
                                     if match["in_port"] == 4]
    trunk_rules = [match for _, match, _ in monitor.installed
                   if match["in_port"] == 3]
    assert len(access_rules) == 3
    assert len(unauthorized_management_rules) == 3
    assert len(trunk_rules) == 8
    assert all(match["vlan_vid"] == 0 for match in access_rules)
    assert all(match["vlan_vid"] == 0 for match in unauthorized_management_rules)
    assert all("vlan_vid" not in match for match in trunk_rules)
    assert all(match["ipv4_src"] != ("10.10.40.0", "255.255.255.0")
               for match in trunk_rules)
    assert all(len(actions) == 1 and actions[0]["type"] == "output"
               and actions[0]["port"] == 0xFFFFFFFD
               for _priority, match, actions in monitor.installed
               if match["eth_type"] == 0x0800)
    assert all(actions == [] for _priority, match, actions in monitor.installed
               if match["eth_type"] == 0x86DD)
    assert monitor.ssh_policy_switches == {2}


def test_ssh_denial_audit_is_bounded_and_installs_exact_drop_cache():
    source_path = ROOT / "topology_monitor.py"
    namespace = {
        "SSH_DENIED_VLANS": frozenset({10, 20, 30, 50}),
        "SSH_MANAGEMENT_HOSTS": {
            "h36": "10.10.40.36", "h37": "10.10.40.37",
        },
        "SSH_PROTECTED_SERVERS": {
            "h4": "10.10.20.4", "h20": "10.10.20.20",
        },
        "SSH_ACTIVITY_PORT": 22,
        "SSH_DENY_CACHE_PRIORITY": 50001,
        "SSH_DENY_CACHE_IDLE_TIMEOUT": 30,
        "SSH_DENY_CACHE_HARD_TIMEOUT": 300,
        "SSH_DENY_AUDIT_INTERVAL": 5,
        "ipaddress": ipaddress,
        "time": time,
    }
    is_denied = extract_function(
        source_path, "_is_ssh_policy_denial", "TopologyMonitor", namespace)
    audit = extract_function(
        source_path, "_audit_denied_ssh_packet", "TopologyMonitor", namespace)

    class Parser:
        @staticmethod
        def OFPMatch(**fields):
            return fields

    class Monitor:
        _is_ssh_policy_denial = is_denied
        _audit_denied_ssh_packet = audit
        vlan_port_map = {
            (2, 1): {"kind": "access", "vlan_id": 10, "host_id": "h21"},
        }
        vlan_networks = {
            10: ipaddress.ip_network("10.10.10.0/24"),
            20: ipaddress.ip_network("10.10.20.0/24"),
            30: ipaddress.ip_network("10.10.30.0/24"),
            40: ipaddress.ip_network("10.10.40.0/24"),
            50: ipaddress.ip_network("10.10.50.0/24"),
        }

        def __init__(self):
            self.firewall_events = []
            self.ssh_deny_audit_last_seen = {}
            self.installed = []
            self.logger = SimpleNamespace(
                warning=lambda *args, **kwargs: None,
                exception=lambda *args, **kwargs: None,
            )

        def _add_flow(self, datapath, priority, match, actions,
                      idle_timeout=0, hard_timeout=0, track_key=None):
            self.installed.append((priority, match, actions,
                                   idle_timeout, hard_timeout, track_key))

    monitor = Monitor()
    datapath = SimpleNamespace(id=2, ofproto_parser=Parser())
    ip_pkt = SimpleNamespace(proto=6, src="10.10.10.21", dst="10.10.20.4")
    tcp_pkt = SimpleNamespace(src_port=49152, dst_port=22)
    assert monitor._audit_denied_ssh_packet(datapath, 1, ip_pkt, tcp_pkt) is True
    assert monitor._audit_denied_ssh_packet(datapath, 1, ip_pkt, tcp_pkt) is True
    assert len(monitor.firewall_events) == 1
    event = monitor.firewall_events[0]
    assert event["event_type"] == "ssh_access_denied"
    assert event["action"] == "DROP"
    assert event["source_ip"] == "10.10.10.21"
    assert event["destination_host_id"] == "h4"
    assert event["destination_port"] == 22
    assert len(monitor.installed) == 2
    priority, match, actions, idle_timeout, hard_timeout, track_key = monitor.installed[0]
    assert priority == 50001 and actions == []
    assert match["in_port"] == 1 and match["ipv4_src"] == "10.10.10.21"
    assert match["ipv4_dst"] == "10.10.20.4" and match["tcp_src"] == 49152
    assert idle_timeout == 30 and hard_timeout == 300 and track_key is None


def test_gateway_ssh_allowlist_is_exact_and_preserves_other_it_services():
    source_path = ROOT / "mininet" / "configure_gateway.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    assignment = next(
        node for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "FORWARD_RULES"
                for target in node.targets)
    )
    rules = ast.literal_eval(assignment.value)
    ssh_rules = [rule for rule in rules if "--dport 22" in rule]
    actual_pairs = set()
    for rule in ssh_rules:
        fields = rule.split()
        actual_pairs.add((fields[fields.index("-s") + 1],
                          fields[fields.index("-d") + 1]))
    assert actual_pairs == {
        ("10.10.40.36/32", "10.10.20.4/32"),
        ("10.10.40.36/32", "10.10.20.20/32"),
        ("10.10.40.37/32", "10.10.20.4/32"),
        ("10.10.40.37/32", "10.10.20.20/32"),
    }
    application_rule = next(rule for rule in rules
                            if "--dports 443,5000" in rule)
    assert "22" not in application_rule


if __name__ == "__main__":
    test_ssh_openflow_counter_delta_marks_hosts_and_switch()
    test_ssh_log_events_are_sanitized_and_map_client_server()
    test_hosts_endpoint_adds_ssh_events_to_both_participants()
    test_ssh_access_policy_drops_nonmanagement_vlan_traffic()
    test_ssh_denial_audit_is_bounded_and_installs_exact_drop_cache()
    test_gateway_ssh_allowlist_is_exact_and_preserves_other_it_services()
    print("PASS: SSH host allow-list, SDN deny audit, counters, and gateway ACL")
