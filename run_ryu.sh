#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

python3 - <<'PY'
import os
import re
import shutil
import sys
from pathlib import Path

env = os.environ.copy()
env_file = Path(".env")

if not env_file.is_file():
    sys.exit("ERROR: .env file not found")

# Load .env as plain KEY=VALUE data. Never execute it as shell code.
for number, raw in enumerate(env_file.read_text().splitlines(), 1):
    line = raw.strip()

    if not line or line.startswith("#"):
        continue

    if line.startswith("export "):
        line = line[7:].lstrip()

    if "=" not in line:
        sys.exit(f"ERROR: invalid .env line {number}")

    key, value = line.split("=", 1)
    key = key.strip()
    value = value.strip()

    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        sys.exit(f"ERROR: invalid variable name at .env line {number}")

    if value.startswith(("'", '"')):
        if len(value) < 2 or value[-1] != value[0]:
            sys.exit(f"ERROR: unmatched quote at .env line {number}")
        value = value[1:-1]

    env[key] = value

# Compatibility with the existing .env variable names.
env["SHADOW_API_URL"] = (
    env.get("SHADOW_API_URL") or env.get("SHADOW_VERDICT_URL", "")
)
env["SHADOW_API_KEY"] = (
    env.get("SHADOW_API_KEY") or env.get("SHADOW_VERDICT_API_KEY", "")
)

control_token = env.get("SECUREIOT_CONTROL_TOKEN", "").strip()
if len(control_token) < 32 or control_token.startswith("CHANGE_ME"):
    sys.exit("ERROR: SECUREIOT_CONTROL_TOKEN is missing or invalid in .env")
env["SECUREIOT_CONTROL_TOKEN"] = control_token

# Safe defaults. These can later be enabled deliberately in .env.
for key in (
    "SHADOW_API_LIVE",
    "SHADOW_API_CONTINUOUS",
    "SHADOW_ENFORCE",
    "SHADOW_AUTO_UNBLOCK",
    "SHADOW_ENFORCEMENT_ALL_ACCESS",
):
    env.setdefault(key, "0")

# Do not allow inherited shell settings to silently enable enforcement.
for key in (
    "SHADOW_API_LIVE",
    "SHADOW_API_CONTINUOUS",
    "SHADOW_ENFORCE",
    "SHADOW_AUTO_UNBLOCK",
    "SHADOW_ENFORCEMENT_ALL_ACCESS",
):
    if key not in {
        line.split("=", 1)[0].strip().removeprefix("export ").strip()
        for line in env_file.read_text().splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    }:
        env[key] = "0"

ryu = shutil.which("ryu-manager")
if not ryu:
    candidate = Path.home() / ".local/bin/ryu-manager"
    if candidate.is_file():
        ryu = str(candidate)

if not ryu:
    sys.exit("ERROR: ryu-manager not found")

# Optional dashboard / IoT telemetry API (no route conflicts with the apps
# above). Off by default to keep the originally tested launch set.
APPS_EXTRA = []
if env.get("SECUREIOT_ENABLE_RUNTIME_API") == "1":
    if len(env.get("SECUREIOT_API_TOKEN", "")) < 32:
        sys.exit("ERROR: SECUREIOT_ENABLE_RUNTIME_API=1 needs SECUREIOT_API_TOKEN (32+ chars)")
    APPS_EXTRA.append("runtime_network_api.py")
    print("Runtime Network API enabled.")

print("Starting Ryu with SecureIoT applications.")
print("Shadow LIVE / CONTINUOUS / ENFORCE / AUTO_UNBLOCK settings are loaded.")
print("Sensitive environment values are hidden.")

os.execve(
    ryu,
    [
        ryu,
        "--ofp-tcp-listen-port", "6633",
        "--wsapi-host", env.get("SECUREIOT_WSGI_HOST", "127.0.0.1"),
        "--wsapi-port", env.get("SECUREIOT_WSGI_PORT", "8080"),
        "--observe-links",
        "topology_monitor.py",
        "traffic_monitor_merged.py",
        "resilience_engine.py",
    ] + APPS_EXTRA,
    env,
)
PY
