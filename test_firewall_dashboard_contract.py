#!/usr/bin/env python3
"""Regression checks for the existing firewall/status and firewall/events contracts."""
import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def extract_method(name, namespace=None):
    source_path = ROOT / "runtime_network_api.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    controller = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "RuntimeNetworkController"
    )
    function = next(node for node in controller.body if isinstance(node, ast.FunctionDef) and node.name == name)
    function.decorator_list = []
    module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    scope = dict(namespace or {})
    exec(compile(module, str(source_path), "exec"), scope)
    return scope[name]


def test_three_blocking_scenarios_have_distinct_reasons_and_count_once():
    reason = extract_method("_firewall_event_reason")
    dedupe = extract_method("_dedupe_firewall_events")
    is_blocked = extract_method("_is_blocked_flow")

    class Controller:
        _firewall_event_reason = staticmethod(reason)

    events = [
        {
            "event_type": "ssh_access_denied",
            "action": "DROP",
            "destination_ip": "10.10.20.4",
            "destination_port": 22,
            "timestamp": 1.0,
        },
        {
            "event_type": "ssh_access_denied",
            "action": "DROP",
            "destination_ip": "10.10.20.100",
            "destination_port": 2222,
            "timestamp": 2.0,
        },
        {
            "event_type": "firewall_action",
            "action": "BLOCK_DEVICE",
            "mac": "02:00:00:00:00:21",
            "request_id": "block-h21-1",
            "timestamp": 3.0,
        },
        # The same BLOCK_DEVICE is mirrored by the topology and action stores.
        {
            "event_type": "firewall",
            "action": "BLOCK_DEVICE",
            "request_id": "block-h21-1",
            "timestamp": 3.0,
        },
    ]

    normalized = dedupe(Controller, events)
    blocked = [event for event in normalized if is_blocked(event)]

    assert len(blocked) == 3
    assert len({event["reason"] for event in blocked}) == 3
    assert blocked[0]["reason"] == "Backend SSH access is restricted to the SSH load balancer"
    assert blocked[1]["reason"] == "SSH frontend access is restricted to management hosts h36 and h37"
    assert blocked[2]["reason"] == "Source host was quarantined by the firewall block action"


def test_active_hosts_count_starts_at_38_and_decrements_for_blocked_hosts():
    active_hosts = extract_method("_active_hosts_count")

    assert active_hosts(38, 0) == 38
    assert active_hosts(38, 1) == 37
    assert active_hosts(38, 3) == 35
    assert active_hosts(38, 99) == 0


def test_firewall_status_reports_active_hosts_and_all_blocked_events():
    status = extract_method(
        "firewall_status",
        namespace={
            "HOSTS": {"h%d" % number: {} for number in range(1, 39)},
            "VLAN_NETWORKS": {10: "10.10.10.0/24"},
            "json_response": lambda payload: payload,
            "now_utc": lambda: "now",
        },
    )

    class Topology:
        blocked_devices = {"02:00:00:00:00:21": {"ip": "10.10.20.21"}}

    class Controller:
        def _topology_status(self):
            # Runtime discovery can report only learned hosts; the API contract
            # must still use the configured 38-host inventory in host_count.
            return Topology(), {"host_count": 21}

        def _firewall_events(self):
            return [
                {"event_type": "ssh_access_denied", "action": "DROP"},
                {"event_type": "ssh_access_denied", "action": "DROP"},
                {
                    "event_type": "firewall_action",
                    "action": "BLOCK_DEVICE",
                    "mac": "02:00:00:00:00:21",
                },
            ]

        @staticmethod
        def _is_blocked_flow(event):
            return event["action"] in {"DROP", "BLOCK_DEVICE"}

        @staticmethod
        def _active_hosts_count(total, blocked):
            return max(0, total - blocked)

    response = status(Controller(), None)

    assert "hosts_count" not in response
    assert response["topology_status"]["host_count"] == 37
    assert response["blocked_flows"] == 3
    assert response["event_count"] == 3


if __name__ == "__main__":
    test_three_blocking_scenarios_have_distinct_reasons_and_count_once()
    test_active_hosts_count_starts_at_38_and_decrements_for_blocked_hosts()
    test_firewall_status_reports_active_hosts_and_all_blocked_events()
    print("PASS: firewall dashboard counters and reasons")
