#!/usr/bin/env python3
"""Server-side polling and optional contract POST delivery for IoT sensors.

The poller reads private sensor endpoints from the Services host every interval.
When ``IOT_TELEMETRY_POST_URL`` is configured, each fresh reading is POSTed to
the existing contract endpoint (for example through ngrok); otherwise it is
written directly to the shared local store.
"""
from __future__ import annotations

import json
import http.client
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Callable, Iterable
from urllib.parse import urlencode, urlsplit

from iot_telemetry_store import IoTTelemetryStore

LOGGER = logging.getLogger("secureiot.iot_poller")
_DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def default_devices() -> list[tuple[str, str]]:
    """Return the canonical h5-h16 IoT inventory and roles."""
    try:
        from mininet.vlan_config_38host import HOSTS
        return [
            (host_id, str(spec["role"]))
            for host_id, spec in sorted(HOSTS.items(), key=lambda item: int(item[0][1:]))
            if 5 <= int(host_id[1:]) <= 16
        ]
    except (ImportError, KeyError, TypeError, ValueError):
        return [(f"h{i}", "iot_device") for i in range(5, 17)]


def read_sensor(url: str, timeout: float = 2.0,
                opener: Callable[..., object] | None = None) -> dict:
    """Fetch one sensor response and validate its minimum shape."""
    if opener is None:
        # Use an explicit socket connection for private Mininet IPs. This
        # cannot consult HTTP(S)_PROXY or perform proxy DNS resolution.
        target = urlsplit(url)
        if target.scheme != "http" or not target.hostname:
            raise ValueError("private sensor URL must be an HTTP host URL")
        connection = http.client.HTTPConnection(
            target.hostname, target.port or 80, timeout=timeout
        )
        try:
            path = target.path or "/"
            if target.query:
                path += "?" + target.query
            connection.request("GET", path, headers={
                "Accept": "application/json",
                "User-Agent": "SecureIoT-Poller/1.0",
            })
            response = connection.getresponse()
            raw = response.read()
            if not 200 <= response.status < 300:
                raise ValueError("sensor returned HTTP %d" % response.status)
            payload = json.loads(raw.decode("utf-8"))
        finally:
            connection.close()
        if not isinstance(payload, dict) or not isinstance(payload.get("readings"), dict):
            raise ValueError("sensor response must contain a readings object")
        return payload
    request = urllib.request.Request(url, headers={"Accept": "application/json",
                                                   "User-Agent": "SecureIoT-Poller/1.0"})
    # Private Mininet sensor IPs must not go through a host HTTP(S) proxy.
    fetch = opener or _DIRECT_OPENER.open
    with fetch(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("readings"), dict):
        raise ValueError("sensor response must contain a readings object")
    return payload


def post_telemetry(url: str, record: dict, timeout: float = 2.0,
                   token: str = "", opener: Callable[..., object] | None = None) -> dict:
    """POST one normalized reading and require a successful JSON response."""
    body = json.dumps(record).encode("utf-8")
    headers = {"Accept": "application/json", "Content-Type": "application/json",
               "User-Agent": "SecureIoT-Poller/1.0"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    fetch = opener or urllib.request.urlopen
    with fetch(request, timeout=timeout) as response:
        status = getattr(response, "status", 200)
        if not 200 <= int(status) < 300:
            raise urllib.error.HTTPError(url, int(status), "telemetry POST rejected", {}, None)
        raw = response.read().decode("utf-8")
    return json.loads(raw) if raw else {"status": "accepted"}


def get_telemetry(url: str, record: dict, timeout: float = 2.0,
                  token: str = "", opener: Callable[..., object] | None = None) -> dict:
    """Deliver one normalized reading through the Web GET ingestion route."""
    query = urlencode({
        "device_id": record.get("device_id", ""),
        "device_role": record.get("device_role", ""),
        "readings": json.dumps(record.get("readings", {}), separators=(",", ":")),
        "timestamp": record.get("timestamp", ""),
        "sequence": "" if record.get("sequence") is None else record.get("sequence"),
        "simulation": "1" if record.get("simulation") else "0",
    })
    separator = "&" if "?" in url else "?"
    request = urllib.request.Request(
        url + separator + query,
        headers={"Accept": "application/json", "User-Agent": "SecureIoT-Poller/1.0"},
        method="GET",
    )
    if token:
        request.add_header("Authorization", "Bearer " + token)
    fetch = opener or urllib.request.urlopen
    with fetch(request, timeout=timeout) as response:
        status = getattr(response, "status", 200)
        if not 200 <= int(status) < 300:
            raise urllib.error.HTTPError(url, int(status), "telemetry GET rejected", {}, None)
        raw = response.read().decode("utf-8")
    return json.loads(raw) if raw else {"status": "accepted"}


class IoTPoller:
    """Daemon poller with bounded timeouts and graceful shutdown."""

    def __init__(self, store: IoTTelemetryStore | None = None,
                 devices: Iterable[tuple[str, str]] | None = None,
                 interval: float | None = None, port: int | None = None,
                 timeout: float | None = None, enabled: bool | None = None,
                 reader: Callable[[str, float], dict] | None = None,
                 poster: Callable[[str, dict, float], dict] | None = None) -> None:
        self.store = store or IoTTelemetryStore()
        self.devices = list(devices or default_devices())
        self.interval = max(1.0, float(interval if interval is not None else os.getenv("IOT_POLL_INTERVAL", "5")))
        self.port = int(port if port is not None else os.getenv("IOT_SENSOR_PORT", "8081"))
        self.timeout = max(0.2, float(timeout if timeout is not None else os.getenv("IOT_POLL_TIMEOUT", "2")))
        raw_enabled = os.getenv("IOT_POLLING_ENABLED", "1").strip().lower()
        self.enabled = (enabled if enabled is not None else raw_enabled not in {"0", "false", "no", "off"})
        self.reader = reader or (lambda url, timeout: read_sensor(url, timeout))
        # GET is the Web-track delivery path. The old POST variables remain
        # accepted so existing deployments can be migrated without breaking.
        self.get_url = os.getenv("IOT_TELEMETRY_GET_URL", "").strip()
        self.get_token = os.getenv("IOT_TELEMETRY_GET_TOKEN", "").strip()
        self.post_url = os.getenv("IOT_TELEMETRY_POST_URL", "").strip()
        self.post_token = os.getenv("IOT_TELEMETRY_POST_TOKEN", "").strip()
        if not self.get_url and self.post_url:
            self.get_url = self.post_url.rstrip("/") + "/ingest"
        if not self.get_token:
            self.get_token = self.post_token
        self.poster = poster or (lambda url, record, timeout: post_telemetry(
            url, record, timeout, token=self.post_token))
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.last_poll_at: str | None = None
        self.success_count = 0
        self.failure_count = 0

    def poll_once(self) -> dict[str, int]:
        successes = failures = 0
        for device_id, role in self.devices:
            url = f"http://10.10.10.{int(device_id[1:])}:{self.port}/sensor/readings"
            try:
                payload = self.reader(url, self.timeout)
                record = {
                    "device_id": device_id,
                    "device_role": payload.get("device_role", role),
                    "readings": payload["readings"],
                    "timestamp": payload.get("timestamp") or now_utc(),
                    "sequence": payload.get("sequence"),
                    "simulation": bool(payload.get("simulation", True)),
                }
                if self.get_url:
                    accepted = get_telemetry(self.get_url, record, self.timeout, token=self.get_token)
                    LOGGER.info("IoT telemetry GET accepted device=%s sequence=%s url=%s",
                                device_id, record.get("sequence"), self.get_url)
                elif self.post_url:
                    accepted = self.poster(self.post_url, record, self.timeout)
                    LOGGER.info("IoT telemetry POST accepted device=%s sequence=%s url=%s",
                                device_id, record.get("sequence"), self.post_url)
                else:
                    accepted = self.store.record(record)
                successes += 1
            except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError,
                    urllib.error.URLError) as exc:
                failures += 1
                LOGGER.warning("IoT poll failed device=%s url=%s error=%s", device_id, url, exc)
        self.last_poll_at = now_utc()
        self.success_count += successes
        self.failure_count += failures
        return {"successes": successes, "failures": failures}

    def _run(self) -> None:
        while not self.stop_event.is_set():
            self.poll_once()
            self.stop_event.wait(self.interval)

    def start(self) -> "IoTPoller":
        if not self.enabled or (self.thread and self.thread.is_alive()):
            return self
        self.thread = threading.Thread(target=self._run, name="secureiot-iot-poller", daemon=True)
        self.thread.start()
        LOGGER.info("IoT server polling enabled devices=%d interval=%ss port=%s get_url=%s",
                    len(self.devices), self.interval, self.port, self.get_url or "local-store")
        return self

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=max(1.0, self.timeout + 1.0))


__all__ = ["IoTPoller", "default_devices", "get_telemetry", "post_telemetry", "read_sensor"]
