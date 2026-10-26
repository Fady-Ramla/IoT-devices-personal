#!/usr/bin/env python3
"""Safely add the TrustFlow telemetry hook and benign IoT POST route."""
from __future__ import annotations

import argparse
from datetime import datetime
import os
from pathlib import Path
import re
import shutil
import tempfile

HOOK = (
    "app = Flask(__name__)\n"
    "\n"
    "# TrustFlow: request metadata only; never records request bodies.\n"
    "from trustflow_app_telemetry import install_trustflow_telemetry\n"
    "install_trustflow_telemetry(app)"
)
APP_PATTERN = re.compile(r"(?m)^app\s*=\s*Flask\(__name__\)\s*$")
HEALTH_MARKER = '@app.route("/health", methods=["GET"])'
TELEMETRY_ROUTE = '''@app.route("/api/iot/telemetry", methods=["POST"])
def receive_iot_telemetry():
    """Accept a minimal demo telemetry envelope without persisting its body."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"status": "rejected", "message": "JSON object required"}), 400
    device_id = data.get("device_id")
    telemetry = data.get("telemetry")
    if not isinstance(device_id, str) or not device_id.strip() or not isinstance(telemetry, dict):
        return jsonify({"status": "rejected", "message": "device_id and telemetry object required"}), 400
    # Do not store or echo readings, identifiers, credentials, or payload content.
    return jsonify({"status": "accepted"}), 202


'''


def atomic_replace(path: Path, content: str) -> None:
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, path.stat().st_mode)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "server", nargs="?", type=Path,
        default=Path(__file__).resolve().parent / "web_api_server.py",
        help="path to mininet/servers/web_api_server.py",
    )
    args = parser.parse_args()
    server = args.server.expanduser().resolve()
    if not server.is_file():
        raise SystemExit(f"Web API server not found: {server}")

    original = server.read_text(encoding="utf-8")
    has_import = "from trustflow_app_telemetry import install_trustflow_telemetry" in original
    has_call = "install_trustflow_telemetry(app)" in original
    if has_import != has_call:
        raise SystemExit("Partial telemetry hook found; inspect manually; no changes made.")

    updated = original
    if not has_call:
        matches = list(APP_PATTERN.finditer(updated))
        if len(matches) != 1:
            raise SystemExit(
                f"Expected exactly one line 'app = Flask(__name__)'; found {len(matches)}. No changes made."
            )
        updated = APP_PATTERN.sub(lambda _: HOOK, updated, count=1)

    has_route = '@app.route("/api/iot/telemetry", methods=["POST"])' in updated
    if not has_route:
        marker_count = updated.count(HEALTH_MARKER)
        if marker_count != 1:
            raise SystemExit(
                f"Expected exactly one health-route insertion marker; found {marker_count}. No changes made."
            )
        updated = updated.replace(HEALTH_MARKER, TELEMETRY_ROUTE + HEALTH_MARKER, 1)

    if updated == original:
        print("Telemetry hook and benign IoT POST route already installed; no changes made.")
        return 0

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = server.with_name(server.name + f".before_app_telemetry_{stamp}")
    shutil.copy2(server, backup)
    atomic_replace(server, updated)

    print(f"Installed TrustFlow HTTP metadata hook and /api/iot/telemetry route in: {server}")
    print(f"Original server backup: {backup}")
    print("The new POST route returns an acknowledgement and never persists the request payload.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
