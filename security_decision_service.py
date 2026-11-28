#!/usr/bin/env python3
"""Block/unblock one remaining service primary via the SecureIoT API.

Supported primaries: h1 (DNS), h2 (HTTP/API), h4 (SSH).
Inventory: GET /topology/hosts with Authorization: Bearer SECUREIOT_API_TOKEN.
Action: POST /network/action with X-SecureIoT-Token: SECUREIOT_CONTROL_TOKEN.
"""
import json
import os
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

PROJECT_DIR = Path(__file__).resolve().parent
ENV_FILE = PROJECT_DIR / ".env"
API_BASE = os.environ.get("SECUREIOT_CONTROL_API_BASE", "http://127.0.0.1:8080").rstrip("/")
TARGETS = {
    "h1": "10.10.30.2",  # DNS primary; backup h17
    "h2": "10.10.20.2",  # HTTP/API primary; backup h18
    "h4": "10.10.20.4",  # SSH primary; backup h20
}


def read_env(path: Path) -> dict[str, str]:
    values = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def api_request(path: str, headers: dict[str, str], method="GET", payload=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request_headers = dict(headers)
    if body is not None:
        request_headers["Content-Type"] = "application/json"
    request = Request(API_BASE + path, data=body, headers=request_headers, method=method)
    try:
        with urlopen(request, timeout=8) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw) if raw else {}
    except HTTPError as exc:
        raw = exc.read(4000).decode("utf-8", errors="replace")
        try:
            result = json.loads(raw)
        except ValueError:
            result = {"message": raw}
        return exc.code, result


def _record_ip(record):
    value = record.get("ip") or record.get("ipv4")
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    return value.split("/", 1)[0] if isinstance(value, str) else None


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1].upper() not in {"BLOCK", "UNBLOCK"}:
        print("Usage: python3 security_decision_service.py BLOCK|UNBLOCK h1|h2|h4")
        return 2
    decision, host_id = sys.argv[1].upper(), sys.argv[2].lower()
    if host_id not in TARGETS:
        print("ERROR: supported service primaries are h1 (DNS), h2 (HTTP/API), h4 (SSH)")
        return 2
    if not ENV_FILE.is_file():
        print("ERROR: .env not found next to this script")
        return 2
    config = read_env(ENV_FILE)
    control_token = os.environ.get("SECUREIOT_CONTROL_TOKEN", config.get("SECUREIOT_CONTROL_TOKEN", "")).strip()
    api_token = os.environ.get("SECUREIOT_API_TOKEN", config.get("SECUREIOT_API_TOKEN", "")).strip()
    if len(control_token) < 32 or control_token.startswith("CHANGE_ME"):
        print("ERROR: valid SECUREIOT_CONTROL_TOKEN is not configured")
        return 2
    if len(api_token) < 32 or api_token.startswith("CHANGE_ME"):
        print("ERROR: valid SECUREIOT_API_TOKEN is required to read /topology/hosts")
        return 2

    target_ip = TARGETS[host_id]
    status, inventory = api_request("/topology/hosts", {"Authorization": f"Bearer {api_token}"})
    if status != 200 or not isinstance(inventory, list):
        print(f"Host inventory check failed: HTTP {status}; {inventory}")
        return 1
    record = next((item for item in inventory if isinstance(item, dict)
                   and item.get("host_id") == host_id and _record_ip(item) == target_ip), None)
    mac = record.get("mac") if record else None
    if not isinstance(mac, str) or not mac.strip():
        print(f"ERROR: {host_id} MAC missing from /topology/hosts; no action sent")
        return 1
    mac = mac.strip().lower()

    action = "BLOCK_DEVICE" if decision == "BLOCK" else "UNBLOCK_DEVICE"
    payload = {
        "action": action,
        "ip": target_ip,
        "mac": mac,
        "request_id": f"{host_id}-{decision.lower()}-{int(time.time() * 1000)}",
        "reason": f"Approved service failover test for {host_id}",
    }
    status, result = api_request(
        "/network/action", {"X-SecureIoT-Token": control_token},
        method="POST", payload=payload,
    )
    print(f"HTTP {status}; host={host_id}; action={action}; ip={target_ip}; mac={mac}")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if status == 200 and isinstance(result, dict) and result.get("success") else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}")
        sys.exit(1)
