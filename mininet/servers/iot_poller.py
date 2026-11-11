#!/usr/bin/env python3
"""Server-side polling for Mininet IoT sensor HTTP endpoints.

The poller is deliberately internal: it adds no public API route. It reads
sensor endpoints from the Services host, then writes normalized observations to
the existing shared IoTTelemetryStore used by both the Flask service and Ryu.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Callable, Iterable

from iot_telemetry_store import IoTTelemetryStore

LOGGER = logging.getLogger("secureiot.iot_poller")


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
    request = urllib.request.Request(url, headers={"Accept": "application/json",
                                                   "User-Agent": "SecureIoT-Poller/1.0"})
    fetch = opener or urllib.request.urlopen
    with fetch(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("readings"), dict):
        raise ValueError("sensor response must contain a readings object")
    return payload


class IoTPoller:
    """Daemon poller with bounded timeouts and graceful shutdown."""

    def __init__(self, store: IoTTelemetryStore | None = None,
                 devices: Iterable[tuple[str, str]] | None = None,
                 interval: float | None = None, port: int | None = None,
                 timeout: float | None = None, enabled: bool | None = None,
                 reader: Callable[[str, float], dict] | None = None) -> None:
        self.store = store or IoTTelemetryStore()
        self.devices = list(devices or default_devices())
        self.interval = max(1.0, float(interval if interval is not None else os.getenv("IOT_POLL_INTERVAL", "5")))
        self.port = int(port if port is not None else os.getenv("IOT_SENSOR_PORT", "8081"))
        self.timeout = max(0.2, float(timeout if timeout is not None else os.getenv("IOT_POLL_TIMEOUT", "2")))
        raw_enabled = os.getenv("IOT_POLLING_ENABLED", "1").strip().lower()
        self.enabled = (enabled if enabled is not None else raw_enabled not in {"0", "false", "no", "off"})
        self.reader = reader or (lambda url, timeout: read_sensor(url, timeout))
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
                self.store.record(record)
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
        LOGGER.info("IoT server polling enabled devices=%d interval=%ss port=%s",
                    len(self.devices), self.interval, self.port)
        return self

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=max(1.0, self.timeout + 1.0))


__all__ = ["IoTPoller", "default_devices", "read_sensor"]
