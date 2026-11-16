#!/usr/bin/env python3
"""Public GET-only gateway for accepted SecureIoT contract read routes.

The public client does not need a bearer token. This process listens only on
127.0.0.1:8090 and forwards only accepted read paths to Ryu at 127.0.0.1:8080,
adding the VM's private SECUREIOT_API_TOKEN upstream. Contract POST ingestion
is deliberately not exposed through this public read-only gateway.
"""
from __future__ import annotations

import json
import os
import re
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

# GET paths documented in SecureIoT Network API Contract v2.0-final.
EXACT_PATHS = {
    "/runtime/health",
    "/topology/switches",
    "/topology/hosts",
    "/topology/links",
    "/topology/paths",
    "/network/vlans",
    "/network/vlan-ports",
    "/network/load-balancer",
    "/network/load-balancer/status",
    "/network/load-balancer/backends",
    "/network/load-balancer/stats",
    "/api/iot/devices",
    "/api/iot/sensors",
    "/api/iot/telemetry",
    "/firewall/status",
    "/firewall/rules",
    "/firewall/events",
    "/network/events",
    "/controller/clff",
    "/controller/resilience",
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
    return (path in EXACT_PATHS or bool(STATS_PATH.fullmatch(path))
            or bool(HOST_PATH.fullmatch(path)))


def validated_query(path: str, raw_query: str) -> Optional[str]:
    if len(raw_query) > MAX_QUERY_LENGTH:
        return None
    if not raw_query:
        return ""
    try:
        pairs = parse_qsl(raw_query, keep_blank_values=True, strict_parsing=True,
                          max_num_fields=8)
    except ValueError:
        return None
    allowed = QUERY_KEYS.get(path, HOST_QUERY_KEYS if HOST_PATH.fullmatch(path) else set())
    if any(key not in allowed or len(value) > 128 for key, value in pairs):
        return None
    if len({key for key, _ in pairs}) != len(pairs):
        return None
    for key, value in pairs:
        if key == "limit":
            if not value.isdigit() or not 1 <= int(value) <= 1000:
                return None
        elif key in {"device_id", "sensor_id", "source", "src", "destination", "dst"}:
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value):
                return None
    return urlencode(pairs)


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "TrustFlowContractReadOnlyGateway/1.1"

    def _send(self, status: int, body: bytes,
              content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Accept, Content-Type")
        self.send_header("Vary", "Origin")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, status: int, payload: object) -> None:
        self._send(status, json.dumps(payload, separators=(",", ":")).encode("utf-8"))

    def _path_query(self):
        parsed = urlsplit(self.path)
        path = unquote(parsed.path)
        # Reject encoded path changes and traversal/double-slash variants.
        if path != parsed.path or ".." in path or "//" in path:
            return None, None, None
        if not is_allowed_path(path):
            return parsed, path, None
        query = validated_query(path, parsed.query)
        return parsed, path, query

    def _upstream_json(self, path_and_query: str):
        request = Request(
            UPSTREAM + path_and_query,
            headers={
                "Authorization": "Bearer " + UPSTREAM_TOKEN,
                "Accept": "application/json",
                "User-Agent": "TrustFlow-Contract-Gateway/1.1",
            },
            method="GET",
        )
        try:
            with urlopen(request, timeout=3) as response:
                body = response.read(MAX_BODY_BYTES + 1)
                if len(body) > MAX_BODY_BYTES:
                    return None, "response exceeded size limit", 502
                payload = json.loads(body.decode("utf-8")) if body else {}
                return payload, None, int(response.status)
        except HTTPError as exc:
            body = exc.read(MAX_BODY_BYTES + 1)
            if len(body) > MAX_BODY_BYTES:
                return None, "response exceeded size limit", 502
            try:
                payload = json.loads(body.decode("utf-8")) if body else {}
            except (UnicodeDecodeError, json.JSONDecodeError):
                payload = {"error": "upstream returned HTTP %d" % exc.code}
            return payload, None, int(exc.code)
        except (URLError, TimeoutError, OSError, UnicodeDecodeError,
                json.JSONDecodeError) as exc:
            return None, "local API request failed: %s" % type(exc).__name__, 502

    def do_GET(self) -> None:
        parsed, path, query = self._path_query()
        if parsed is None:
            self._json(400, {"error": "invalid path"})
            return
        if not is_allowed_path(path):
            self._json(404, {"error": "route is not in the accepted GET contract allowlist"})
            return
        if query is None:
            self._json(400, {"error": "query parameters are not allowed or exceed limits"})
            return
        path_and_query = path + ("?" + query if query else "")
        payload, error, status = self._upstream_json(path_and_query)
        if error is not None:
            self._json(status, {"error": "local dashboard API is unavailable", "reason": error})
            return
        self._json(status, payload)

    def do_OPTIONS(self) -> None:
        parsed, path, query = self._path_query()
        if parsed is None:
            self._json(400, {"error": "invalid path"})
            return
        if not is_allowed_path(path):
            self._json(404, {"error": "route is not in the accepted GET contract allowlist"})
            return
        if query is None:
            self._json(400, {"error": "query parameters are not allowed or exceed limits"})
            return
        self._send(204, b"")

    def do_POST(self) -> None:
        self._method_not_allowed()

    def do_PUT(self) -> None:
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def do_HEAD(self) -> None:
        self._method_not_allowed()

    def _method_not_allowed(self) -> None:
        self._json(405, {"error": "public gateway accepts GET/OPTIONS only"})

    def log_message(self, fmt: str, *args) -> None:
        # Do not retain telemetry filters, source/destination selectors, or IDs.
        return


def main() -> None:
    if len(UPSTREAM_TOKEN) < 32:
        raise SystemExit("SECUREIOT_API_TOKEN must be at least 32 characters")
    server = ThreadingHTTPServer((BIND_HOST, BIND_PORT), GatewayHandler)
    server.daemon_threads = True
    print("TrustFlow contract GET gateway listening on 127.0.0.1:8090", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
