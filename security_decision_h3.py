#!/usr/bin/env python3
"""Send an explicit, authenticated Security decision for h3 only.

Usage from the SecureIoT project directory:
  python3 security_decision_h3.py BLOCK
  python3 security_decision_h3.py UNBLOCK
The control token is read from .env and never printed.
"""
import json
import os
from pathlib import Path
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

PROJECT_DIR = Path(__file__).resolve().parent
ENV_FILE = PROJECT_DIR / ".env"
API_BASE = os.environ.get("SECUREIOT_CONTROL_API_BASE", "http://127.0.0.1:8080").rstrip("/")
H3_ID = "h3"
H3_IP = "10.10.20.3"


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


def api_request(path: str, headers: dict[str, str], method: str = "GET", payload=None):
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
            data = json.loads(raw)
        except ValueError:
            data = {"message": raw}
        return exc.code, data


def _host_ip(record: dict) -> str | None:
    address = record.get("ip") or record.get("ipv4")
    if isinstance(address, (list, tuple)):
        address = address[0] if address else None
    if not isinstance(address, str):
        return None
    return address.split("/", 1)[0]


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1].upper() not in {"BLOCK", "UNBLOCK"}:
        print("Usage: python3 security_decision_h3.py BLOCK|UNBLOCK")
        return 2
    decision = sys.argv[1].upper()
    if not ENV_FILE.is_file():
        print("ERROR: .env not found next to this script")
        return 2
    config = read_env(ENV_FILE)
    control_token = os.environ.get(
        "SECUREIOT_CONTROL_TOKEN", config.get("SECUREIOT_CONTROL_TOKEN", "")
    ).strip()
    api_token = os.environ.get(
        "SECUREIOT_API_TOKEN", config.get("SECUREIOT_API_TOKEN", "")
    ).strip()
    if len(control_token) < 32 or control_token.startswith("CHANGE_ME"):
        print("ERROR: valid SECUREIOT_CONTROL_TOKEN is not configured")
        return 2
    if len(api_token) < 32 or api_token.startswith("CHANGE_ME"):
        print(
            "ERROR: valid SECUREIOT_API_TOKEN is required to read /topology/hosts; "
            "enable runtime_network_api.py and configure the API token"
        )
        return 2

    status, inventory = api_request(
        "/topology/hosts", {"Authorization": f"Bearer {api_token}"}
    )
    if status != 200 or not isinstance(inventory, list):
        print(f"Host inventory check failed: HTTP {status}; {inventory}")
        return 1
    h3_record = next((record for record in inventory
                      if isinstance(record, dict)
                      and record.get("host_id") == H3_ID
                      and _host_ip(record) == H3_IP), None)
    h3_mac = h3_record.get("mac") if h3_record else None
    if not isinstance(h3_mac, str) or not h3_mac.strip():
        print("ERROR: h3 MAC is absent from /topology/hosts; no decision sent")
        return 1
    h3_mac = h3_mac.strip().lower()

    action = "BLOCK_DEVICE" if decision == "BLOCK" else "UNBLOCK_DEVICE"
    request_id = f"h3-{decision.lower()}-{int(time.time() * 1000)}"
    payload = {
        "action": action,
        "ip": H3_IP,
        "mac": h3_mac,
        "request_id": request_id,
        "reason": "Approved temporary HTTPS failover test for h3",
    }
    status, result = api_request(
        "/network/action",
        {"X-SecureIoT-Token": control_token},
        method="POST",
        payload=payload,
    )
    print(f"HTTP {status}; action={action}; target={H3_IP}; mac={h3_mac}")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if status == 200 and isinstance(result, dict) and result.get("success") else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}")
        sys.exit(1)
