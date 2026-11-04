#!/usr/bin/env python3
"""Connect the dashboard Flask API to the live Ryu runtime read API."""
from pathlib import Path
from datetime import datetime
import re
import shutil

TARGET = Path("mininet/servers/web_api_server.py")
MARKER = "RUNTIME_PROVIDER_CONNECTED_V1"

if not TARGET.exists():
    raise SystemExit(f"Missing {TARGET}")

text = TARGET.read_text(encoding="utf-8")
if MARKER in text:
    print("Runtime provider is already connected; no changes made.")
    raise SystemExit(0)

backup = TARGET.with_name(
    TARGET.name + ".before_runtime_provider_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".bak"
)
shutil.copy2(TARGET, backup)

# urllib is intentionally used instead of adding a new dependency.
if "import urllib.request" not in text:
    text = text.replace("import time\n", "import time\nimport urllib.error\nimport urllib.request\n", 1)

anchor = "NETWORK_DASHBOARD_CONTRACT_V1 = True"
if anchor not in text:
    raise SystemExit("Dashboard contract block was not found")

provider = r'''# =============================================================
# LIVE RYU RUNTIME PROVIDER
# =============================================================
RUNTIME_PROVIDER_CONNECTED_V1 = True
RUNTIME_API_BASE = os.getenv("SECUREIOT_RYU_RUNTIME_URL", "http://127.0.0.1:8080").rstrip("/")


def _runtime_get(path):
    request = urllib.request.Request(
        RUNTIME_API_BASE + path,
        headers={"Accept": "application/json"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=1.5) as response:
        return json.loads(response.read().decode("utf-8"))


def _runtime_or_fallback(path, fallback):
    try:
        return _runtime_get(path)
    except (OSError, ValueError, KeyError, TypeError, urllib.error.URLError):
        return fallback

'''
text = text.replace(anchor, provider + anchor, 1)

# Replace the three existing static controller endpoints with live proxy endpoints.
def replace_function(source, name, next_name, body):
    pattern = re.compile(
        r'@app\.get\("' + re.escape({
            "dashboard_controller_state": "/controller/state",
            "dashboard_clff_state": "/controller/clff",
            "dashboard_resilience_state": "/controller/resilience",
        }[name]) + r'"\)\n'
        r'def ' + re.escape(name) + r'\(\):\n.*?(?=\n@app\.get\("' + re.escape({
            "dashboard_controller_state": "/controller/clff",
            "dashboard_clff_state": "/controller/resilience",
            "dashboard_resilience_state": "/network/events",
        }[next_name]) + r'"\))',
        re.S,
    )
    replacement = '@app.get("' + {
        "dashboard_controller_state": "/controller/state",
        "dashboard_clff_state": "/controller/clff",
        "dashboard_resilience_state": "/controller/resilience",
    }[name] + '")\ndef ' + name + '():\n' + body + '\n\n'
    updated, count = pattern.subn(replacement, source, count=1)
    if count != 1:
        raise SystemExit(f"Could not replace {name}")
    return updated

text = replace_function(
    text,
    "dashboard_controller_state",
    "dashboard_clff_state",
    '    return jsonify(_runtime_or_fallback("/runtime/controller", {\n'
    '        "controller_id": "ryu", "status": "unknown", "state": "degraded",\n'
    '        "connected_switches": None, "active_inter_switch_links": None,\n'
    '        "last_error": "Ryu runtime provider unavailable"\n'
    '    }))',
)
text = replace_function(
    text,
    "dashboard_clff_state",
    "dashboard_resilience_state",
    '    return jsonify(_runtime_or_fallback("/runtime/clff", {\n'
    '        "enabled": True, "ready": None,\n'
    '        "last_error": "Ryu runtime provider unavailable"\n'
    '    }))',
)
text = replace_function(
    text,
    "dashboard_resilience_state",
    "dashboard_network_events",
    '    return jsonify(_runtime_or_fallback("/runtime/resilience", {\n'
    '        "enabled": True, "status": "unknown", "event_count": 0,\n'
    '        "recovery_count": 0, "last_recovery": None,\n'
    '        "last_error": "Ryu runtime provider unavailable"\n'
    '    }))',
)

# Add normalized topology endpoints immediately before controller state.
topology_routes = r'''@app.get("/topology/switches")
def dashboard_topology_switches():
    payload = _runtime_or_fallback("/runtime/topology", {})
    status = payload.get("status", {}) if isinstance(payload, dict) else {}
    return jsonify([
        {
            "dpid": int(dpid),
            "switch": "s%d" % int(dpid),
            "n_ports": None,
            "status": "up" if status.get("topology_ready") else "degraded",
            "controller_connected": bool(status.get("topology_ready")),
            "last_seen": payload.get("timestamp"),
        }
        for dpid in status.get("switches", [])
    ])


@app.get("/topology/links")
def dashboard_topology_links():
    payload = _runtime_or_fallback("/runtime/topology", {})
    status = payload.get("status", {}) if isinstance(payload, dict) else {}
    metrics = (status.get("path_engine") or {}).get("metrics") or {}
    result = []
    for link in payload.get("links", []) if isinstance(payload, dict) else []:
        src = int(link.get("src_dpid"))
        dst = int(link.get("dst_dpid"))
        metric = metrics.get("%d-%d" % tuple(sorted((src, dst))), {})
        utilization = metric.get("utilization")
        result.append({
            "src": {"dpid": src, "port_no": link.get("src_port")},
            "dst": {"dpid": dst, "port_no": link.get("dst_port")},
            "status": "isolated" if link.get("isolated") else "up",
            "utilization": utilization,
            "congestion": utilization,
            "rate_bps": metric.get("rate_bps"),
            "capacity_bps": metric.get("capacity_bps"),
            "last_state_change": None,
        })
    return jsonify(result)


@app.get("/topology/hosts")
def dashboard_topology_hosts():
    payload = _runtime_or_fallback("/runtime/topology", {})
    hosts = payload.get("hosts", {}) if isinstance(payload, dict) else {}
    result = []
    for mac, item in hosts.items():
        result.append({
            "dpid": item.get("dpid"),
            "port_no": item.get("port"),
            "mac": mac,
            "ipv4": [item["ip"]] if item.get("ip") else [],
            "status": "online",
            "last_seen": payload.get("timestamp"),
        })
    return jsonify(result)


'''
needle = '@app.get("/controller/state")'
if needle not in text:
    raise SystemExit("Controller endpoint marker not found")
text = text.replace(needle, topology_routes + needle, 1)

TARGET.write_text(text, encoding="utf-8")
print(f"Connected Flask API to live Ryu runtime. Backup: {backup}")
