#!/usr/bin/env python3
"""Verify the local Ryu control API using .env without printing credentials."""
import json
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


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


def main() -> int:
    project = Path(__file__).resolve().parent
    env = read_env(project / ".env")
    token = env.get("SECUREIOT_CONTROL_TOKEN", "").strip()
    if len(token) < 32 or token.startswith("CHANGE_ME"):
        print("Control token missing/invalid in .env; no request sent.")
        return 2

    request = Request(
        "http://127.0.0.1:8080/network/hosts",
        headers={"X-SecureIoT-Token": token},
        method="GET",
    )
    try:
        with urlopen(request, timeout=4) as response:
            body = response.read(1_000_000)
            status = response.status
    except HTTPError as exc:
        message = exc.read(2000).decode("utf-8", errors="replace")
        print(f"Ryu control API HTTP {exc.code}: {message}")
        return 1
    except (URLError, TimeoutError, OSError) as exc:
        print(f"Ryu control API unreachable: {type(exc).__name__}")
        return 1

    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        print(f"Ryu control API HTTP {status}: invalid JSON response")
        return 1

    hosts = data.get("hosts", {})
    h3 = next((mac for mac, record in hosts.items()
               if isinstance(record, dict) and record.get("ip") == "10.10.20.3"), None)
    print(f"Ryu control API HTTP {status}; success={bool(data.get('success'))}; host_count={data.get('host_count', 0)}")
    print(f"h3 learned: {bool(h3)}" + (f"; MAC={h3}" if h3 else ""))
    return 0 if data.get("success") else 1


if __name__ == "__main__":
    sys.exit(main())
