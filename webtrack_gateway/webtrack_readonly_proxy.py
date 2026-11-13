#!/usr/bin/env python3
"""Public GET-only WebTrack gateway for the local Ryu API.

Listens only on 127.0.0.1:8090. Public clients do not need a bearer token;
the gateway forwards only an explicit set of read-only GET routes to
127.0.0.1:8080 using the private Ryu API token stored in the service env.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, unquote
from urllib.request import Request, urlopen

BIND_HOST = "127.0.0.1"
BIND_PORT = 8090
UPSTREAM = "http://127.0.0.1:8080"
UPSTREAM_TOKEN = os.environ.get("SECUREIOT_API_TOKEN", "")
MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_QUERY_LENGTH = 2048
SNAPSHOT_PATH = "/dashboard/snapshot"
SNAPSHOT_ITEMS = {
    "health": "/health",
    "controller": "/controller/state",
    "clff": "/controller/clff",
    "resilience": "/controller/resilience",
    "hosts": "/topology/hosts",
    "switches": "/topology/switches",
    "links": "/topology/links",
    "paths": "/topology/paths",
    "vlans": "/network/vlans",
    "vlan_ports": "/network/vlan-ports",
    "network_events": "/network/events?limit=20",
    "iot_devices": "/api/iot/devices",
    "iot_sensors": "/api/iot/sensors",
    "iot_telemetry": "/api/iot/telemetry?limit=50",
    "firewall_status": "/firewall/status",
    "firewall_rules": "/firewall/rules",
    "firewall_events": "/firewall/events?limit=20",
    "load_balancer_status": "/network/load-balancer/status",
    "load_balancer_backends": "/network/load-balancer/backends",
}
for _dpid in range(1, 7):
    SNAPSHOT_ITEMS["desc_stats_s%d" % _dpid] = "/stats/desc/%d" % _dpid
    SNAPSHOT_ITEMS["flow_stats_s%d" % _dpid] = "/stats/flow/%d" % _dpid
    SNAPSHOT_ITEMS["port_stats_s%d" % _dpid] = "/stats/port/%d" % _dpid

EXACT_PATHS = {
    "/health",
    "/runtime/health",
    "/api/iot/devices",
    "/api/iot/sensors",
    "/api/iot/telemetry",
    "/controller/state",
    "/runtime/controller",
    "/runtime/topology",
    "/topology/switches",
    "/topology/links",
    "/topology/hosts",
    "/topology/paths",
    "/network/vlans",
    "/network/vlan-ports",
    "/network/load-balancer",
    "/network/load-balancer/status",
    "/network/load-balancer/backends",
    "/network/load-balancer/stats",
    "/firewall/status",
    "/firewall/rules",
    "/firewall/events",
    "/network/events",
    "/controller/clff",
    "/runtime/clff",
    "/controller/resilience",
    "/runtime/resilience",
}
STATS_PATH = re.compile(r"^/stats/(?:desc|flow|port)/[1-6]$")
HOST_PATH = re.compile(r"^/topology/hosts/h(?:[1-9]|[12][0-9]|3[0-8])/path$")
QUERY_KEYS = {
    "/api/iot/telemetry": {"device_id", "sensor_id", "limit"},
    "/topology/paths": {"source", "src", "destination", "dst"},
    "/firewall/events": {"limit"},
    "/network/events": {"limit"},
}
HOST_QUERY_KEYS = {"source", "src", "destination", "dst"}


def is_allowed_path(path: str) -> bool:
    return (path == SNAPSHOT_PATH or path in EXACT_PATHS
            or bool(STATS_PATH.fullmatch(path)) or bool(HOST_PATH.fullmatch(path)))


def validated_query(path: str, raw_query: str) -> Optional[str]:
    if len(raw_query) > MAX_QUERY_LENGTH:
        return None
    if not raw_query:
        return ""
    try:
        pairs = parse_qsl(raw_query, keep_blank_values=True, strict_parsing=True, max_num_fields=8)
    except ValueError:
        return None
    allowed = QUERY_KEYS.get(path, HOST_QUERY_KEYS if HOST_PATH.fullmatch(path) else set())
    if any(key not in allowed or len(value) > 128 for key, value in pairs):
        return None
    if len({key for key, _ in pairs}) != len(pairs):
        return None
    for key, value in pairs:
        if key == "limit":
            if not value.isdigit() or not 1 <= int(value) <= 500:
                return None
        elif key in {"device_id", "sensor_id", "source", "src", "destination", "dst"}:
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value):
                return None
    return urlencode(pairs)


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "TrustFlowReadOnlyGateway/1.0"

    def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload, separators=(",", ":")).encode("utf-8"))

    def _upstream_json(self, path_and_query: str):
        request = Request(
            UPSTREAM + path_and_query,
            headers={
                "Authorization": "Bearer " + UPSTREAM_TOKEN,
                "Accept": "application/json",
                "User-Agent": "TrustFlow-ReadOnly-Gateway/1.0",
            },
            method="GET",
        )
        try:
            with urlopen(request, timeout=2) as response:
                body = response.read(MAX_BODY_BYTES + 1)
                if len(body) > MAX_BODY_BYTES:
                    return None, "response exceeded size limit"
                return json.loads(body.decode("utf-8")), None
        except HTTPError as exc:
            return None, "local API returned HTTP %d" % exc.code
        except (URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            return None, "local API request failed: %s" % type(exc).__name__

    def _snapshot(self) -> None:
        data = {}
        errors = {}
        for name, path_and_query in SNAPSHOT_ITEMS.items():
            payload, error = self._upstream_json(path_and_query)
            if error is None:
                data[name] = payload
            else:
                errors[name] = error
        if not data:
            self._json(502, {"status": "unavailable", "errors": errors})
            return
        payload = {
            "status": "ok" if not errors else "partial",
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "data": data,
            "errors": errors,
        }
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_BODY_BYTES:
            self._json(502, {"status": "unavailable", "error": "snapshot exceeded size limit"})
            return
        self._send(200, body)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        path = unquote(parsed.path)
        # Reject encoded path changes and any traversal or double-slash variants.
        if path != parsed.path or ".." in path or "//" in path:
            self._json(400, {"error": "invalid path"})
            return
        if not is_allowed_path(path):
            self._json(404, {"error": "route is not in the read-only allowlist"})
            return
        if path == SNAPSHOT_PATH:
            if parsed.query:
                self._json(400, {"error": "snapshot does not accept query parameters"})
                return
            self._snapshot()
            return
        query = validated_query(path, parsed.query)
        if query is None:
            self._json(400, {"error": "query parameters are not allowed or exceed limits"})
            return

        upstream_url = UPSTREAM + path + ("?" + query if query else "")
        payload, error = self._upstream_json(upstream_url[len(UPSTREAM):])
        if error is not None:
            self._json(502, {"error": "local dashboard API is unavailable", "reason": error})
            return
        self._json(200, payload)

    def do_POST(self) -> None:
        self._method_not_allowed()

    def do_PUT(self) -> None:
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def do_OPTIONS(self) -> None:
        self._method_not_allowed()

    def do_HEAD(self) -> None:
        self._method_not_allowed()

    def _method_not_allowed(self) -> None:
        self._json(405, {"error": "read-only gateway accepts GET requests only"})

    def log_message(self, fmt: str, *args) -> None:
        # Avoid retaining query filters, source/destination selectors, or IDs.
        return


def main() -> None:
    if len(UPSTREAM_TOKEN) < 32:
        raise SystemExit("SECUREIOT_API_TOKEN must be at least 32 characters")
    server = ThreadingHTTPServer((BIND_HOST, BIND_PORT), GatewayHandler)
    server.daemon_threads = True
    print("TrustFlow read-only gateway listening on 127.0.0.1:8090", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
