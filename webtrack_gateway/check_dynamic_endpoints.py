#!/usr/bin/env python3
"""Read-only two-sample diagnostic for contract dynamic API fields.

Run while the bounded h27 -> h28 ping is active. Sends only HTTP GETs and no
client token. It never changes VLANs, links, firewall rules, or controller state.
"""
from __future__ import annotations

import json
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

SOURCE = "h27"
DESTINATION = "h28"
SOURCE_IP = "10.10.50.27"
DESTINATION_IP = "10.10.50.28"
POLL_SECONDS = 11
TIMEOUT = 12
FAILURES = []


def get_json(base: str, path: str):
    request = Request(base + path, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=TIMEOUT) as response:
            code = response.status
            body = response.read()
    except HTTPError as exc:
        code = exc.code
        body = exc.read()
    except (URLError, TimeoutError, OSError) as exc:
        return 0, None, str(exc)
    try:
        payload = json.loads(body.decode("utf-8")) if body else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    return code, payload, None


def response(base: str, path: str, allowed=(200,)):
    code, payload, error = get_json(base, path)
    label = "PASS" if code in allowed and payload is not None else "FAIL"
    if label == "FAIL":
        FAILURES.append(f"{path}: HTTP {code or '000'}")
    print(f"{label} HTTP {code or '000'} GET {path}")
    if error:
        print("  error:", error)
    elif payload is None:
        print("  response is not JSON")
    return code, payload


def find_host(hosts, host_id):
    if not isinstance(hosts, list):
        return None
    return next((row for row in hosts if isinstance(row, dict)
                 and row.get("host_id") == host_id), None)


def find_path(payload):
    if isinstance(payload, list):
        return payload[0] if payload and isinstance(payload[0], dict) else {}
    return payload if isinstance(payload, dict) else {}


def summarize_host(row):
    if not row:
        return {"missing": True}
    flows = row.get("active_flows", [])
    return {
        "traffic_active": row.get("traffic_active"),
        "controller_seen": row.get("controller_seen"),
        "path_status": row.get("path_status"),
        "path": row.get("path"),
        "active_flows_count": len(flows) if isinstance(flows, list) else None,
        "active_flows": flows if isinstance(flows, list) else flows,
    }


def summarize_stats(payload, kind):
    if not isinstance(payload, dict):
        return None
    if kind == "flow":
        flows = payload.get("flows", [])
        matches = []
        if isinstance(flows, list):
            for flow in flows:
                if not isinstance(flow, dict):
                    continue
                match = str(flow.get("match", ""))
                if SOURCE_IP in match or DESTINATION_IP in match:
                    matches.append({
                        "match": match,
                        "packet_count": flow.get("packet_count"),
                        "byte_count": flow.get("byte_count"),
                        "priority": flow.get("priority"),
                    })
        return {"status": payload.get("status"), "matching_flows": matches}
    ports = payload.get("ports", [])
    counters = {"rx_packets": 0, "tx_packets": 0, "rx_bytes": 0, "tx_bytes": 0}
    if isinstance(ports, list):
        for port in ports:
            if not isinstance(port, dict):
                continue
            if port.get("port_no") == 4294967294:
                continue
            for key in counters:
                try:
                    counters[key] += int(port.get(key, 0) or 0)
                except (ValueError, TypeError):
                    pass
    return {"status": payload.get("status"), **counters}


def sample(base: str, index: int):
    print(f"\n===== SAMPLE {index} =====")
    result = {}
    for endpoint in ("/runtime/health", "/topology/switches", "/topology/hosts",
                     "/topology/links", "/api/iot/devices", "/api/iot/sensors",
                     "/api/iot/telemetry?" + urlencode({"device_id": "h16", "limit": "1"}),
                     "/network/load-balancer/stats", "/network/events?limit=20",
                     "/firewall/events?limit=20", "/controller/resilience"):
        allowed = (200, 202) if endpoint.startswith("/stats/") else (200,)
        code, payload = response(base, endpoint, allowed)
        result[endpoint] = payload if code in allowed else None

    for dpid in (5, 6):
        for kind in ("flow", "port"):
            endpoint = f"/stats/{kind}/{dpid}"
            code, payload = response(base, endpoint, (200, 202))
            result[endpoint] = payload if code in (200, 202) else None

    path_query = "/topology/paths?" + urlencode({"source": SOURCE, "destination": DESTINATION})
    code, payload = response(base, path_query)
    result["host_pair_path"] = find_path(payload) if code == 200 else None
    host_path = f"/topology/hosts/{DESTINATION}/path?source={SOURCE}"
    code, payload = response(base, host_path)
    result["host_path"] = payload if code == 200 and isinstance(payload, dict) else None

    hosts = result.get("/topology/hosts")
    result["hosts_pair"] = {
        SOURCE: summarize_host(find_host(hosts, SOURCE)),
        DESTINATION: summarize_host(find_host(hosts, DESTINATION)),
    }
    result["stats_summary"] = {
        f"{kind}_{dpid}": summarize_stats(result.get(f"/stats/{kind}/{dpid}"), kind)
        for dpid in (5, 6) for kind in ("flow", "port")
    }
    telemetry = result.get("/api/iot/telemetry?device_id=h16&limit=1")
    if isinstance(telemetry, list):
        result["iot_latest"] = telemetry[0] if telemetry else None
    else:
        result["iot_latest"] = None
    lb = result.get("/network/load-balancer/stats")
    result["lb_counters"] = {
        key: lb.get(key) for key in ("requests_total", "requests_active", "bytes_in",
                                     "bytes_out", "backend_failovers", "timestamp")
    } if isinstance(lb, dict) else None
    event_values = {
        "network_events": result.get("/network/events?limit=20"),
        "firewall_events": result.get("/firewall/events?limit=20"),
        "resilience": result.get("/controller/resilience"),
    }
    result["event_summary"] = {
        "network_events_count": len(event_values["network_events"])
            if isinstance(event_values["network_events"], list) else None,
        "firewall_events_count": len(event_values["firewall_events"])
            if isinstance(event_values["firewall_events"], list) else None,
        "resilience": event_values["resilience"],
    }
    print("\nDynamic fields:")
    print(json.dumps({
        "hosts": result["hosts_pair"],
        "host_pair_path": result["host_pair_path"],
        "host_path": result["host_path"],
        "flow_port_stats": result["stats_summary"],
        "iot_latest_h16": result["iot_latest"],
        "load_balancer_counters": result["lb_counters"],
        "events": result["event_summary"],
    }, indent=2, sort_keys=True))
    return result


def main():
    if len(sys.argv) != 2 or not sys.argv[1].startswith("https://"):
        raise SystemExit("Usage: python3 check_dynamic_endpoints.py https://<ngrok-host>")
    base = sys.argv[1].rstrip("/")
    first = sample(base, 1)
    print(f"\nWaiting {POLL_SECONDS}s for counters/poller to advance...")
    time.sleep(POLL_SECONDS)
    second = sample(base, 2)

    print("\n===== DELTAS / OBSERVATIONS =====")
    for dpid in (5, 6):
        before = first["stats_summary"].get(f"port_{dpid}") or {}
        after = second["stats_summary"].get(f"port_{dpid}") or {}
        keys = ("rx_packets", "tx_packets", "rx_bytes", "tx_bytes")
        delta = {key: (after.get(key, 0) or 0) - (before.get(key, 0) or 0) for key in keys}
        print(f"s{dpid} port-counter deltas:", json.dumps(delta))
        for kind in ("flow",):
            left = first["stats_summary"].get(f"{kind}_{dpid}") or {}
            right = second["stats_summary"].get(f"{kind}_{dpid}") or {}
            print(f"s{dpid} host-pair {kind} entries before:",
                  json.dumps(left.get("matching_flows", [])))
            print(f"s{dpid} host-pair {kind} entries after:",
                  json.dumps(right.get("matching_flows", [])))

    left_iot, right_iot = first.get("iot_latest"), second.get("iot_latest")
    if left_iot and right_iot:
        print("h16 telemetry sequence:", left_iot.get("sequence"), "->", right_iot.get("sequence"))
        print("h16 telemetry timestamp:", left_iot.get("timestamp"), "->", right_iot.get("timestamp"))
    elif not right_iot:
        print("h16 telemetry: no latest row; check simulator/poller/SQLite separately")

    for host_id in (SOURCE, DESTINATION):
        a = first["hosts_pair"].get(host_id, {})
        b = second["hosts_pair"].get(host_id, {})
        print(f"{host_id} traffic_active:", a.get("traffic_active"), "->", b.get("traffic_active"),
              "active_flows:", a.get("active_flows_count"), "->", b.get("active_flows_count"))

    path = second.get("host_pair_path") or {}
    print("host-pair path evidence:", json.dumps({
        "nodes": path.get("nodes", path.get("path")),
        "status": path.get("status", path.get("path_status")),
        "path_source": path.get("path_source"),
        "computed": path.get("computed"),
        "flow_direction": path.get("flow_direction"),
        "history_count": len(path.get("history", [])) if isinstance(path.get("history"), list) else None,
    }))
    print("\nThis diagnostic uses GET only. It does not change VLANs, links, policy, or controller state.")
    print("Empty event arrays are valid until a real event occurs. Load-balancer counters change only after traffic reaches its VIP.")
    if FAILURES:
        print("\nEndpoint failures:")
        for failure in FAILURES:
            print("-", failure)
        return 1
    print("\nAll queried contract endpoints returned JSON with HTTP 200/202.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
