#!/usr/bin/env python3
"""Set the approved all-host enforcement scope for a controlled Mininet test.

This helper never prints secret values. It preserves unrelated .env lines and
writes a timestamped backup before atomically replacing the file.
"""
from datetime import datetime
import os
from pathlib import Path
import shutil
import tempfile

ENV_FILE = Path(__file__).resolve().parent / ".env"
UPDATES = {
    "SHADOW_ENFORCE": "1",
    "SHADOW_AUTO_UNBLOCK": "1",
    "SHADOW_ENFORCEMENT_ALL_ACCESS": "1",
    "SHADOW_ENFORCEMENT_IPS": "",
    "SHADOW_ENFORCEMENT_VLANS": "10,20,30,40,50",
    "SECUREIOT_PROTECTED_IPS": "",
    # Keep this run deterministic: only the explicitly approved Security
    # decision should affect a device during the manual failover test.
    "SHADOW_API_LIVE": "0",
    "SHADOW_API_CONTINUOUS": "0",
}


def main() -> None:
    if not ENV_FILE.is_file():
        raise SystemExit("ERROR: .env not found; refusing to create one without credentials")

    original = ENV_FILE.read_text(encoding="utf-8")
    lines = original.splitlines()
    backup = ENV_FILE.with_name(
        ".env.pre_allhost_" + datetime.now().strftime("%Y%m%d_%H%M%S")
    )
    shutil.copy2(ENV_FILE, backup)

    output = []
    seen = set()
    for line in lines:
        stripped = line.strip()
        candidate = stripped[7:].lstrip() if stripped.startswith("export ") else stripped
        key = candidate.split("=", 1)[0].strip() if "=" in candidate else ""
        if key in UPDATES:
            if key not in seen:
                output.append(f"{key}={UPDATES[key]}")
                seen.add(key)
            continue
        output.append(line)

    for key, value in UPDATES.items():
        if key not in seen:
            output.append(f"{key}={value}")

    content = "\n".join(output) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=".env.", dir=str(ENV_FILE.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, ENV_FILE.stat().st_mode & 0o777)
        os.replace(temp_name, ENV_FILE)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)

    # Secret-safe readiness report. Do not display the token or API keys.
    token = ""
    for line in content.splitlines():
        if line.startswith("SECUREIOT_CONTROL_TOKEN="):
            token = line.split("=", 1)[1].strip().strip("\"'")
            break
    print(f"Updated {ENV_FILE.name}; backup: {backup.name}")
    print("Enforcement scope: validated access hosts, VLANs 10,20,30,40,50")
    print("Protected-IP exclusions: none; Shadow automatic polling disabled for this manual test")
    print(f"Control token present and 32+ characters: {len(token) >= 32}")
    if len(token) < 32 or token.startswith("CHANGE_ME"):
        raise SystemExit("ERROR: control token is missing or invalid; do not start Ryu")


if __name__ == "__main__":
    main()
