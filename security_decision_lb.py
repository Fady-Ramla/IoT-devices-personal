#!/usr/bin/env python3
"""Explicitly block/unblock h38 through SecureIoT's authenticated API."""
import json
import os
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

TARGET_ID = "h38"
TARGET_IP = "10.10.20.100"
TARGET_MAC = "00:00:00:00:00:27"
BASE = os.environ.get("SECUREIOT_CONTROL_API_BASE", "http://127.0.0.1:8080").rstrip("/")
ENV_FILE = Path(__file__).resolve().parent / ".env"


def read_env():
    values = {}
    for raw in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip().removeprefix("export ")
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def request(path, headers, method="GET", payload=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = dict(headers)
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = Request(BASE + path, data=body, headers=headers, method=method)
    try:
        with urlopen(req, timeout=45) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw) if raw else {}
    except HTTPError as exc:
        raw = exc.read(4000).decode("utf-8", errors="replace")
        try:
            data = json.loads(raw)
        except ValueError:
            data = {"message": raw}
        return exc.code, data


def main():
    if len(sys.argv) != 2 or sys.argv[1].upper() not in {"BLOCK", "UNBLOCK"}:
        print("Usage: python3 security_decision_lb.py BLOCK|UNBLOCK")
        return 2
    decision = sys.argv[1].upper()
    if not ENV_FILE.is_file():
        print("ERROR: .env not found next to this script")
        return 2
    env = read_env()
    api_token = os.environ.get("SECUREIOT_API_TOKEN", env.get("SECUREIOT_API_TOKEN", "")).strip()
    control_token = os.environ.get("SECUREIOT_CONTROL_TOKEN", env.get("SECUREIOT_CONTROL_TOKEN", "")).strip()
    if len(api_token) < 32 or api_token.startswith("CHANGE_ME"):
        print("ERROR: valid SECUREIOT_API_TOKEN is required")
        return 2
    if len(control_token) < 32 or control_token.startswith("CHANGE_ME"):
        print("ERROR: valid SECUREIOT_CONTROL_TOKEN is required")
        return 2

    status, inventory = request("/topology/hosts", {"Authorization": f"Bearer {api_token}"})
    if status != 200:
        print(f"Inventory check failed: HTTP {status}; {json.dumps(inventory)}")
        return 1
    hosts = inventory.get("hosts", inventory) if isinstance(inventory, dict) else inventory
    if isinstance(hosts, dict):
        record = hosts.get(TARGET_ID)
        if record is None:
            record = next((v for v in hosts.values() if isinstance(v, dict) and v.get("host_id") == TARGET_ID), None)
    elif isinstance(hosts, list):
        record = next((v for v in hosts if isinstance(v, dict) and v.get("host_id") == TARGET_ID), None)
    else:
        record = None
    if not isinstance(record, dict):
        print("ERROR: h38 not found in /topology/hosts; no action sent")
        return 1
    ip = record.get("ip") or record.get("ipv4")
    if isinstance(ip, (list, tuple)):
        ip = ip[0] if ip else None
    if isinstance(ip, str):
        ip = ip.split("/", 1)[0]
    mac = str(record.get("mac") or "").strip().lower()
    if ip != TARGET_IP or mac != TARGET_MAC:
        print(f"ERROR: h38 inventory mismatch (ip={ip}, mac={mac}); no action sent")
        return 1

    action = "BLOCK_DEVICE" if decision == "BLOCK" else "UNBLOCK_DEVICE"
    payload = {
        "action": action,
        "ip": TARGET_IP,
        "mac": TARGET_MAC,
        "request_id": f"h38-{decision.lower()}-{int(time.time() * 1000)}",
        "reason": "Approved live load-balancer VIP takeover test",
    }
    status, result = request("/network/action", {"X-SecureIoT-Token": control_token}, "POST", payload)
    print(f"HTTP {status}; host=h38; action={action}; ip={TARGET_IP}; mac={TARGET_MAC}")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if status == 200 and isinstance(result, dict) and result.get("success") else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}")
        sys.exit(1)
