#!/usr/bin/env python3
"""Minimal Flask hook for TrustFlow application-layer telemetry.

Records request metadata only (never headers, query strings, or request bodies)
while a dataset run is active. Output is one CSV per run under
New_Datasets/raw/application/.

Integration in web_api_server.py, immediately after app = Flask(__name__):
    from trustflow_app_telemetry import install_trustflow_telemetry
    install_trustflow_telemetry(app)
"""
from __future__ import annotations

import csv
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import time
import uuid
from urllib.parse import urlsplit

from flask import g, request

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ACTIVE_RUN_FILE = Path(os.environ.get(
    "SECUREIOT_ACTIVE_RUN_FILE", str(PROJECT_ROOT / "New_Datasets" / "active_run.json")
)).expanduser().resolve()
APPLICATION_DATA_DIR = Path(os.environ.get(
    "SECUREIOT_APPLICATION_DATA_DIR", str(PROJECT_ROOT / "New_Datasets" / "raw" / "application")
)).expanduser().resolve()
CSV_HEADER = [
    "run_id", "generation", "application_observation_id", "timestamp",
    "src_ip", "src_port", "dst_ip", "dst_port", "http_method",
    "route_category", "response_status",
]


def _active_run() -> tuple[str, int] | None:
    """Return the active, valid UUID/generation only; fail closed otherwise."""
    try:
        data = json.loads(ACTIVE_RUN_FILE.read_text(encoding="utf-8"))
        run_id = str(data.get("run_id", ""))
        generation = data.get("generation")
        if data.get("status") != "active" or type(generation) is not int or generation < 1:
            return None
        if str(uuid.UUID(run_id)) != run_id.lower():
            return None
        return run_id, generation
    except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError):
        return None


def _route_category() -> str:
    """Map known Flask route templates to low-cardinality, non-payload categories."""
    rule = getattr(getattr(request, "url_rule", None), "rule", "") or ""
    if rule in {"/login", "/auth", "/admin"}:
        return "auth"
    if rule.startswith("/api/iot/"):
        return "iot_api"
    if rule == "/health":
        return "health"
    if rule == "/":
        return "root"
    return "other"


def _host_ip_and_port() -> tuple[str, str]:
    """Parse the request Host header; only numeric IPs are kept as dst_ip."""
    try:
        parsed = urlsplit("//" + str(request.host))
        host = parsed.hostname or ""
        try:
            dst_ip = str(ipaddress.ip_address(host))
        except ValueError:
            dst_ip = ""
        port = parsed.port or int(request.environ.get("SERVER_PORT", "0") or 0)
        return dst_ip, str(port) if 0 < port <= 65535 else ""
    except (TypeError, ValueError):
        return "", ""


def _append_event(row: list[object], run_id: str) -> None:
    APPLICATION_DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = APPLICATION_DATA_DIR / (run_id + ".csv")
    # The run_id was validated as a UUID; lock protects header and row writes
    # when Flask serves requests concurrently in different threads.
    with path.open("a+", newline="", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            handle.seek(0, os.SEEK_END)
            writer = csv.writer(handle)
            if handle.tell() == 0:
                writer.writerow(CSV_HEADER)
            writer.writerow(row)
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def install_trustflow_telemetry(app) -> None:
    """Install metadata-only hooks on a Flask app, idempotently."""
    if app.extensions.get("trustflow_app_telemetry_installed"):
        return
    app.extensions["trustflow_app_telemetry_installed"] = True

    @app.before_request
    def _trustflow_capture_start():
        g._trustflow_started_at = time.time()
        return None

    @app.after_request
    def _trustflow_record_request(response):
        try:
            identity = _active_run()
            if identity is None:
                return response
            run_id, generation = identity
            timestamp = getattr(g, "_trustflow_started_at", time.time())
            dst_ip, dst_port = _host_ip_and_port()
            src_ip = str(request.remote_addr or "")
            try:
                src_ip = str(ipaddress.ip_address(src_ip))
            except ValueError:
                src_ip = ""
            try:
                src_port = int(request.environ.get("REMOTE_PORT", "0") or 0)
                src_port = str(src_port) if 0 < src_port <= 65535 else ""
            except (TypeError, ValueError):
                src_port = ""
            method = str(request.method or "OTHER").upper()
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                method = "OTHER"
            row = [
                run_id, generation, str(uuid.uuid4()), f"{timestamp:.6f}",
                src_ip, src_port, dst_ip, dst_port, method,
                _route_category(), int(response.status_code),
            ]
            _append_event(row, run_id)
        except Exception:
            # Telemetry must never break API behavior; an error is visible in
            # the service log, while the model/data pipeline separately checks
            # for missing app events in required canary runs.
            app.logger.exception("TrustFlow application telemetry write failed")
        return response
