#!/usr/bin/env python3
"""Send an explicit, authenticated Security decision for h3 only.

Usage from the SecureIoT project directory:
  python3 security_decision_h3.py BLOCK
  python3 security_decision_h3.py UNBLOCK
The control token is read from .env and never printed.
"""
import json
from pathlib import Path
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

PROJECT_DIR = Path(__file__).resolve().parent
ENV_FILE = PROJECT_DIR / ".env"
API_BASE = "http://127.0.0.1:8080"
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


def api_request(path: str, token: str, method: str = "GET", payload=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"X-SecureIoT-Token": token}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = Request(API_BASE + path, data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=8) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raw = exc.read(4000).decode("utf-8", errors="replace")
        try:
            data = json.loads(raw)
        except ValueError:
            data = {"message": raw}
        return exc.code, data


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1].upper() not in {"BLOCK", "UNBLOCK"}:
        print("Usage: python3 security_decision_h3.py BLOCK|UNBLOCK")
        return 2
    decision = sys.argv[1].upper()
    if not ENV_FILE.is_file():
        print("ERROR: .env not found next to this script")
        return 2
    token = read_env(ENV_FILE).get("SECUREIOT_CONTROL_TOKEN", "").strip()
    if len(token) < 32 or token.startswith("CHANGE_ME"):
        print("ERROR: valid SECUREIOT_CONTROL_TOKEN is not configured")
        return 2

    status, inventory = api_request("/network/hosts", token)
    if status != 200 or not inventory.get("success"):
        print(f"Host inventory check failed: HTTP {status}; {inventory}")
        return 1
    hosts = inventory.get("hosts", {})
    h3_mac = next((mac for mac, record in hosts.items()
                   if isinstance(record, dict) and record.get("ip") == H3_IP), None)
    if not h3_mac:
        print("ERROR: h3 is not currently learned by Ryu; no decision sent")
        return 1

    request_id = f"h3-{decision.lower()}-{int(time.time() * 1000)}"
    payload = {
        "decision": decision,
        "src": H3_IP,
        "mac": h3_mac,
        "request_id": request_id,
        "reason": "Approved temporary HTTPS failover test for h3",
    }
    status, result = api_request(
        "/security/decision", token, method="POST", payload=payload
    )
    print(f"HTTP {status}; decision={decision}; target={H3_IP}; mac={h3_mac}")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if status == 200 and result.get("success") else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}")
        sys.exit(1)
