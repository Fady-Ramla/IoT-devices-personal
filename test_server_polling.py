#!/usr/bin/env python3
"""Regression checks for the contract-preserving server polling path."""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone

from iot_telemetry_store import IoTTelemetryStore
from mininet.servers.iot_poller import IoTPoller


class ServerPollingTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
