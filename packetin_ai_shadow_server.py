#!/usr/bin/env python3
"""Loopback-only inference service for the PacketIn Flow model.

Run from the repository root with dataset_env/bin/python. It loads the existing
ryu_flow_inference adapter and model; it does not train, write datasets, or
perform network actions.
"""
import json
import math
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ryu_flow_inference import FEATURES, predict_ryu_flow

HOST = "127.0.0.1"
PORT = 8765
MAX_BODY_BYTES = 8192
MODEL_VERSION = "packetin_ryu_flow_v1"
CATEGORICAL = {"protocol", "source"}
ALLOWED_PROTOCOLS = {"tcp", "udp", "icmp"}


class Handler(BaseHTTPRequestHandler):
    server_version = "PacketInShadowInference/1.0"
    sys_version = ""

    def _send_json(self, status, body):
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path != "/health":
            self._send_json(404, {"error": "not_found"})
            return
        self._send_json(200, {
            "status": "ready",
            "model_version": MODEL_VERSION,
            "feature_count": len(FEATURES),
            "source": "packetin_window",
            "actions_enabled": False,
        })

    def do_POST(self):
        if self.path != "/predict":
            self._send_json(404, {"error": "not_found"})
            return
        try:
            raw_length = self.headers.get("Content-Length", "")
            length = int(raw_length)
        except (TypeError, ValueError):
            self._send_json(411, {"error": "content_length_required"})
            return
        if length <= 0 or length > MAX_BODY_BYTES:
            self._send_json(413, {"error": "invalid_body_size"})
            return
        try:
            body = self.rfile.read(length)
            record = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"error": "invalid_json"})
            return
        if not isinstance(record, dict):
            self._send_json(400, {"error": "json_object_required"})
            return
        expected = set(FEATURES)
        actual = set(record)
        if actual != expected:
            self._send_json(422, {
                "error": "feature_contract_mismatch",
                "missing": sorted(expected - actual),
                "unexpected": sorted(actual - expected),
            })
            return
        if record.get("source") != "packetin_window":
            self._send_json(422, {"error": "wrong_telemetry_source"})
            return
        if str(record.get("protocol", "")).lower() not in ALLOWED_PROTOCOLS:
            self._send_json(422, {"error": "unsupported_protocol"})
            return
        for feature in FEATURES:
            if feature in CATEGORICAL:
                continue
            value = record.get(feature)
            if value in (None, ""):
                continue
            if isinstance(value, bool):
                self._send_json(422, {"error": "invalid_numeric_feature", "feature": feature})
                return
            try:
                number = float(value)
            except (TypeError, ValueError):
                self._send_json(422, {"error": "invalid_numeric_feature", "feature": feature})
                return
            if not math.isfinite(number):
                self._send_json(422, {"error": "non_finite_feature", "feature": feature})
                return
        try:
            result = predict_ryu_flow(record)
        except Exception as exc:
            # Return only the exception type; never echo feature values.
            self._send_json(500, {"error": "inference_failed", "detail": type(exc).__name__})
            return
        response = dict(result)
        response["model_version"] = MODEL_VERSION
        response["actions_enabled"] = False
        self._send_json(200, response)

    def log_message(self, fmt, *args):
        # Do not log request bodies or flow identifiers.
        return


def main():
    feature_count = len(FEATURES)
    if feature_count != 22:
        raise RuntimeError("Expected 22 model features, found %d" % feature_count)
    if not set(FEATURES).issuperset({"protocol", "source"}):
        raise RuntimeError("Model feature contract lacks required categorical fields")
    model_dir = Path("New_Datasets/models/packetin_ryu_flow_v1")
    if not (model_dir / "model.joblib").is_file():
        raise FileNotFoundError("Model artifact not found: %s" % (model_dir / "model.joblib"))
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    print("PacketIn shadow inference ready at http://%s:%d (model=%s, features=%d; actions disabled)" % (
        HOST, PORT, MODEL_VERSION, feature_count
    ), flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("Stopping PacketIn shadow inference service", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
