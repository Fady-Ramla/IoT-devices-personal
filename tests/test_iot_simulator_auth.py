import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mininet"))
import iot_device_simulator


class SimulatorAuthTests(unittest.TestCase):
    def test_bearer_token_is_attached_only_when_configured(self):
        payload = {"device_id": "h5", "telemetry": {"temperature_c": 21.5}}
        class Response:
            status = 202
            def read(self, _size=-1): return b'{"status":"accepted"}'
            def __enter__(self): return self
            def __exit__(self, *args): return False
        with patch.dict(os.environ, {"IOT_INGEST_TOKEN": "secret-test-token"}):
            with patch.object(iot_device_simulator.urllib.request, "urlopen", return_value=Response()) as call:
                iot_device_simulator.send_telemetry("http://example.test/api/iot/telemetry", payload)
                request = call.call_args.args[0]
                self.assertEqual(request.get_header("Authorization"), "Bearer secret-test-token")
                self.assertEqual(request.get_header("Content-type"), "application/json")
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(iot_device_simulator.urllib.request, "urlopen", return_value=Response()) as call:
                iot_device_simulator.send_telemetry("http://example.test/api/iot/telemetry", payload)
                request = call.call_args.args[0]
                self.assertIsNone(request.get_header("Authorization"))


if __name__ == "__main__":
    unittest.main()
