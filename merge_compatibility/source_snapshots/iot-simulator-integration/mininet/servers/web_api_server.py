#!/usr/bin/env python3
"""SecureIoT Web/API demo service.

Security properties:
- No hardcoded password or reusable fake token.
- Password verification uses PBKDF2-HMAC-SHA256.
- JWT-like compact tokens are signed with HMAC-SHA256 and validated strictly.
- /admin requires a valid Bearer token with role=admin.
- Administrative commands are an allowlist of safe demo actions; user input is
  never passed to a shell or subprocess.

Required for authenticated use:
  JWT_SECRET: high-entropy secret, at least 32 characters
  ADMIN_PASSWORD_HASH: value produced by make_password_hash()
Optional:
  ADMIN_USERNAME (default: admin)
  JWT_TTL_SECONDS (default: 900)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from functools import wraps
from typing import Any, Callable

from flask import Flask, jsonify, request

# The topology and Ryu API share the VM filesystem even though this Flask
# process runs inside h2's Mininet network namespace.
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
from iot_telemetry_store import IoTTelemetryStore

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
iot_telemetry_store = IoTTelemetryStore()

# TrustFlow: request metadata only; never records request bodies.
from trustflow_app_telemetry import install_trustflow_telemetry
install_trustflow_telemetry(app)
JWT_ALG = "HS256"
JWT_TTL_SECONDS = int(os.getenv("JWT_TTL_SECONDS", "900"))
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
JWT_SECRET = os.getenv("JWT_SECRET", "")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")

if not JWT_SECRET:
    # Keeps health checks usable in Mininet, but authentication is disabled
    # until the operator supplies a secret explicitly.
    JWT_SECRET = secrets.token_urlsafe(48)
    app.logger.warning("JWT_SECRET is not configured; login is disabled")


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def make_password_hash(password: str, iterations: int = 310_000) -> str:
    """Return a portable PBKDF2 password record for ADMIN_PASSWORD_HASH."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64e(salt)}${_b64e(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, iterations, salt, expected = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), _b64d(salt), int(iterations)
        )
        return hmac.compare_digest(_b64e(actual), expected)
    except (TypeError, ValueError):
        return False


def issue_token(username: str, role: str) -> str:
    now = int(time.time())
    header = {"alg": JWT_ALG, "typ": "JWT"}
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + JWT_TTL_SECONDS,
        "iss": "secureiot-web-api",
    }
    encoded_header = _b64e(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    signature = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{_b64e(signature)}"


def decode_token(token: str) -> dict[str, Any] | None:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".", 2)
        signing_input = f"{header_b64}.{payload_b64}".encode()
        expected = hmac.new(
            JWT_SECRET.encode(), signing_input, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(_b64e(expected), signature_b64):
            return None
        header = json.loads(_b64d(header_b64))
        payload = json.loads(_b64d(payload_b64))
        now = int(time.time())
        if header.get("alg") != JWT_ALG or header.get("typ") != "JWT":
            return None
        if payload.get("iss") != "secureiot-web-api":
            return None
        if not isinstance(payload.get("sub"), str):
            return None
        if int(payload.get("exp", 0)) <= now:
            return None
        if int(payload.get("iat", 0)) > now + 30:
            return None
        return payload
    except (TypeError, ValueError, KeyError, json.JSONDecodeError):
        return None


def bearer_claims() -> dict[str, Any] | None:
    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return decode_token(token)


def require_auth(role: str | None = None) -> Callable:
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapped(*args: Any, **kwargs: Any):
            claims = bearer_claims()
            if claims is None:
                return jsonify({"status": "failed", "message": "Valid Bearer token required"}), 401
            if role is not None and claims.get("role") != role:
                return jsonify({"status": "failed", "message": "Insufficient privileges"}), 403
            return func(*args, claims=claims, **kwargs)
        return wrapped
    return decorator


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "server": "IoT Web/API Server",
        "status": "running",
        "ip": os.getenv("WEB_API_SERVER_IP", "10.10.20.2"),
        "port": 5000,
    })


@app.route("/api", methods=["GET"])
def api():
    return jsonify({"status": "success", "message": "IoT API is running"})


@app.route("/api/devices", methods=["GET"])
@require_auth()
def devices(**_: Any):
    return jsonify({
        "devices": [
            {"id": 1, "ip": "10.10.10.5", "status": "normal"},
            {"id": 2, "ip": "10.10.10.6", "status": "normal"},
        ]
    })


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return jsonify({"endpoint": "/login", "method": "POST", "auth": "PBKDF2 + signed JWT"})
    if not ADMIN_PASSWORD_HASH or not os.getenv("JWT_SECRET"):
        return jsonify({"status": "failed", "message": "Authentication is not configured"}), 503
    data = request.get_json(silent=True) if request.is_json else request.form.to_dict()
    data = data or {}
    username = data.get("username") or data.get("user")
    password = data.get("password") or data.get("pass")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"status": "failed", "message": "Username and password are required"}), 400
    if not hmac.compare_digest(username, ADMIN_USERNAME) or not verify_password(password, ADMIN_PASSWORD_HASH):
        return jsonify({"status": "failed", "message": "Invalid credentials"}), 401
    return jsonify({"status": "success", "message": "Login successful", "token": issue_token(username, "admin"), "expires_in": JWT_TTL_SECONDS})


@app.route("/auth", methods=["GET", "POST"])
def auth():
    claims = bearer_claims()
    if claims is None:
        return jsonify({"status": "failed", "message": "Valid Bearer token required"}), 401
    return jsonify({"status": "authenticated", "claims": claims})


SAFE_ADMIN_ACTIONS = {
    "status": "status_requested",
    "health": "health_requested",
}


@app.route("/admin", methods=["GET", "POST"])
@require_auth(role="admin")
def admin(**kwargs: Any):
    if request.method == "GET":
        return jsonify({"status": "success", "message": "Admin endpoint", "role": kwargs["claims"]["role"], "allowed_actions": sorted(SAFE_ADMIN_ACTIONS)})
    data = request.get_json(silent=True) if request.is_json else request.form.to_dict()
    action = (data or {}).get("action")
    if action not in SAFE_ADMIN_ACTIONS:
        return jsonify({"status": "failed", "message": "Unsupported administrative action"}), 400
    return jsonify({"status": "success", "action": SAFE_ADMIN_ACTIONS[action], "executed": False, "message": "Demo action acknowledged; no system command is executed"})


@app.route("/api/iot/telemetry", methods=["POST"])
def receive_iot_telemetry():
    """Persist readings only from their expected IoT-host source address."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"status": "rejected", "message": "JSON object required"}), 400
    device_id = data.get("device_id")
    ingest_token = os.environ.get("IOT_INGEST_TOKEN", "")
    if ingest_token:
        scheme, _, supplied = request.headers.get("Authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(supplied, ingest_token):
            return jsonify({"status": "rejected", "message": "valid ingest bearer token required"}), 401
    remote = request.remote_addr or ""
    # In this lab, h5-h16 are the authorized telemetry producers and their
    # address suffix matches the Mininet host ID. Reject dashboard/public posts.
    try:
        remote_octets = [int(part) for part in remote.split(".")]
    except (TypeError, ValueError):
        remote_octets = []
    if (len(remote_octets) != 4 or remote_octets[:3] != [10, 10, 10]
            or not 5 <= remote_octets[3] <= 16
            or device_id != "h%d" % remote_octets[3]):
        return jsonify({"status": "rejected", "message": "source is not an authorized IoT host"}), 403
    try:
        record = iot_telemetry_store.record(data)
    except (ValueError, TypeError) as exc:
        return jsonify({"status": "rejected", "message": str(exc)}), 400
    return jsonify({"status": "accepted", "record_id": record["id"],
                    "device_id": record["device_id"], "timestamp": record["timestamp"]}), 202


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "service": "IoT Web/API Server"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("WEB_API_PORT", "5000")), debug=False)
