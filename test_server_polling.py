#!/usr/bin/env python3
"""Regression checks for the contract-preserving server polling path."""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
from unittest.mock import patch

from iot_telemetry_store import IoTTelemetryStore

_POLLER_PATH = Path(__file__).parent / "mininet" / "servers" / "iot_poller.py"
_POLLER_SPEC = importlib.util.spec_from_file_location("secureiot_test_iot_poller", _POLLER_PATH)
if _POLLER_SPEC is None or _POLLER_SPEC.loader is None:
    raise RuntimeError(f"cannot load poller module from {_POLLER_PATH}")
_POLLER_MODULE = importlib.util.module_from_spec(_POLLER_SPEC)
_POLLER_SPEC.loader.exec_module(_POLLER_MODULE)
IoTPoller = _POLLER_MODULE.IoTPoller
read_sensor = _POLLER_MODULE.read_sensor


class ServerPollingTest(unittest.TestCase):
    def test_sensor_reader_uses_get(self):
        seen = {}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b'{"readings":{"temperature_c":21.5}}'

        def opener(request, timeout=None):
            seen["method"] = request.get_method()
            seen["url"] = request.full_url
            return Response()

        payload = read_sensor(
            "http://10.10.10.16:8081/sensor/readings", opener=opener
        )
        self.assertEqual(seen["method"], "GET")
        self.assertIn("/sensor/readings", seen["url"])
        self.assertEqual(payload["readings"]["temperature_c"], 21.5)

    def test_polling_writes_changing_values_to_existing_store(self):
        with tempfile.TemporaryDirectory() as directory:
            store = IoTTelemetryStore(f"{directory}/iot.sqlite3")
            counter = {"value": 0}

            def reader(url, timeout):
                self.assertIn("/sensor/readings", url)
                counter["value"] += 1
                return {
                    "device_id": "h16",
                    "device_role": "vibration_sensor",
                    "readings": {"vibration_mm_s": counter["value"]},
                    "sequence": counter["value"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "simulation": True,
                }

            poller = IoTPoller(store=store, devices=[("h16", "vibration_sensor")],
                                reader=reader, enabled=True)
            self.assertEqual(poller.poll_once(), {"successes": 1, "failures": 0})
            self.assertEqual(poller.poll_once(), {"successes": 1, "failures": 0})
            rows = store.telemetry(device_id="h16", sensor_id="vibration_mm_s", limit=10)
            self.assertEqual([row["readings"]["vibration_mm_s"] for row in rows], [1, 2])
            self.assertEqual(store.devices()[0]["status"], "online")
            self.assertEqual(store.sensors()[0]["value"], 2)

    def test_sensor_failure_does_not_break_the_poll_cycle(self):
        with tempfile.TemporaryDirectory() as directory:
            store = IoTTelemetryStore(f"{directory}/iot.sqlite3")

            def reader(url, timeout):
                raise OSError("sensor offline")

            poller = IoTPoller(store=store, devices=[("h5", "alarm_sensor")],
                                reader=reader, enabled=True)
            self.assertEqual(poller.poll_once(), {"successes": 0, "failures": 1})
            self.assertEqual(store.devices(), [])

    def test_polling_stores_locally_and_ignores_outbound_delivery_urls(self):
        with tempfile.TemporaryDirectory() as directory:
            store = IoTTelemetryStore(f"{directory}/iot.sqlite3")
            sequence = {"value": 40}

            def reader(url, timeout):
                sequence["value"] += 1
                return {
                    "device_id": "h16",
                    "device_role": "vibration_sensor",
                    "readings": {"vibration_mm_s": sequence["value"] / 10},
                    "sequence": sequence["value"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

            with patch.dict("os.environ", {
                "IOT_TELEMETRY_GET_URL": "https://example.ngrok-free.dev/ingest",
                "IOT_TELEMETRY_POST_URL": "https://example.ngrok-free.dev/api/iot/telemetry",
            }):
                poller = IoTPoller(store=store, devices=[("h16", "vibration_sensor")],
                                    reader=reader, enabled=True)
            self.assertEqual(poller.poll_once(), {"successes": 1, "failures": 0})
            self.assertEqual(poller.poll_once(), {"successes": 1, "failures": 0})
            rows = store.telemetry(device_id="h16", sensor_id="vibration_mm_s", limit=10)
            self.assertEqual([row["sequence"] for row in rows], [41, 42])
            self.assertEqual([row["readings"]["vibration_mm_s"] for row in rows], [4.1, 4.2])
            self.assertEqual(store.devices()[0]["status"], "online")


if __name__ == "__main__":
    unittest.main(verbosity=2)
