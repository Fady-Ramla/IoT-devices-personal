import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import security_decision_h3 as client


class FakeResponse:
    def __init__(self, payload, status=200):
        self.status = status
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.payload


class SecurityDecisionH3Tests(unittest.TestCase):
    def test_block_uses_inventory_bearer_and_network_action_contract(self):
        api_token = "A" * 40
        control_token = "C" * 40
        inventory = [
            {
                "host_id": "h3",
                "ipv4": ["10.10.20.3/24"],
                "mac": "00:00:00:00:00:03",
            }
        ]
        responses = [
            FakeResponse(inventory),
            FakeResponse({"success": True, "status": "executed"}),
        ]
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text(
                f"SECUREIOT_API_TOKEN={api_token}\n"
                f"SECUREIOT_CONTROL_TOKEN={control_token}\n",
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with patch.object(client, "ENV_FILE", env_file), \
                 patch.object(client, "urlopen", side_effect=responses) as mocked_urlopen, \
                 patch("sys.argv", ["security_decision_h3.py", "BLOCK"]), \
                 contextlib.redirect_stdout(stdout):
                result = client.main()

        self.assertEqual(result, 0)
        self.assertEqual(mocked_urlopen.call_count, 2)
        inventory_request = mocked_urlopen.call_args_list[0].args[0]
        action_request = mocked_urlopen.call_args_list[1].args[0]
        self.assertTrue(inventory_request.full_url.endswith("/topology/hosts"))
        self.assertEqual(inventory_request.get_header("Authorization"), f"Bearer {api_token}")
        self.assertTrue(action_request.full_url.endswith("/network/action"))
        self.assertEqual(action_request.get_header("X-secureiot-token"), control_token)
        payload = json.loads(action_request.data.decode("utf-8"))
        self.assertEqual(payload["action"], "BLOCK_DEVICE")
        self.assertEqual(payload["ip"], "10.10.20.3")
        self.assertEqual(payload["mac"], "00:00:00:00:00:03")
        self.assertIn("request_id", payload)
        self.assertIn("HTTP 200; action=BLOCK_DEVICE", stdout.getvalue())

    def test_missing_api_token_stops_before_any_request(self):
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text(
                f"SECUREIOT_CONTROL_TOKEN={'C' * 40}\n",
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with patch.object(client, "ENV_FILE", env_file), \
                 patch.object(client, "urlopen") as mocked_urlopen, \
                 patch("sys.argv", ["security_decision_h3.py", "BLOCK"]), \
                 contextlib.redirect_stdout(stdout):
                result = client.main()
        self.assertEqual(result, 2)
        mocked_urlopen.assert_not_called()
        self.assertIn("SECUREIOT_API_TOKEN is required", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
