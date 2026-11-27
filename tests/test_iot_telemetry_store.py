import os
import stat
import tempfile
import unittest

from iot_telemetry_store import IoTTelemetryStore


class TelemetryStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = IoTTelemetryStore(os.path.join(self.tmp.name, "telemetry.sqlite3"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_simulator_envelope_round_trip(self):
        payload = {
            "device_id": "h5",
            "device_role": "alarm_sensor",
            "telemetry": {
                "timestamp": "2026-11-02T10:00:00Z",
                "sequence": 123,
                "simulation": True,
                "alarm_state": "normal",
                "battery_pct": 91,
            },
        }
        row = self.store.record(payload)
        self.assertEqual(row["sequence"], 123)
        self.assertEqual(row["readings"], {"alarm_state": "normal", "battery_pct": 91})
        self.assertEqual(self.store.devices()[0]["device_id"], "h5")
        self.assertEqual(self.store.devices()[0]["status"], "stale")
        self.assertEqual({x["sensor_id"] for x in self.store.sensors()}, {"alarm_state", "battery_pct"})
        self.assertEqual(self.store.telemetry("h5", "battery_pct", 5)[0]["id"], row["id"])
        self.assertEqual(stat.S_IMODE(os.stat(self.store.path).st_mode), 0o600)

    def test_duplicate_delivery_is_idempotent(self):
        payload = {"device_id": "h6", "device_role": "temperature_sensor",
                   "telemetry": {"timestamp": "2026-11-02T10:00:00Z", "sequence": 77,
                                 "temperature_c": 22.5}}
        first = self.store.record(payload)
        second = self.store.record(payload)
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(len(self.store.telemetry("h6")), 1)

    def test_single_sensor_contract_is_accepted(self):
        row = self.store.record({"device_id": "h7", "sensor_id": "setpoint_c",
                                 "value": 22.0, "unit": "C", "timestamp": "t1"})
        self.assertEqual(row["readings"]["setpoint_c"], 22.0)
        self.assertEqual(row["readings"]["setpoint_c_unit"], "C")

    def test_invalid_payloads_are_rejected(self):
        cases = [
            {},
            {"device_id": "h5", "telemetry": {}},
            {"device_id": "not a valid id", "telemetry": {"value": 1}},
            {"device_id": "h5", "telemetry": {"x": float("nan")}},
        ]
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.store.record(payload)


if __name__ == "__main__":
    unittest.main()
