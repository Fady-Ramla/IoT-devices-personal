import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import security_decision_service as client


class FakeResponse:
    status = 200

    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.payload


class ServiceDecisionTests(unittest.TestCase):
    def test_supported_primaries_use_correct_inventory_and_action_routes(self):
        for host_id, ip in client.TARGETS.items():
            with self.subTest(host_id=host_id), tempfile.TemporaryDirectory() as directory:
                api_token, control_token = "A" * 40, "C" * 40
                env_file = Path(directory) / ".env"
                env_file.write_text(
                    f"SECUREIOT_API_TOKEN={api_token}\nSECUREIOT_CONTROL_TOKEN={control_token}\n",
                    encoding="utf-8",
                )
                inventory = [{"host_id": host_id, "ipv4": [ip], "mac": "00:00:00:00:00:aa"}]
                responses = [FakeResponse(inventory), FakeResponse({"success": True})]
                output = io.StringIO()
                with patch.object(client, "ENV_FILE", env_file), \
                     patch.object(client, "urlopen", side_effect=responses) as mocked, \
                     patch("sys.argv", ["security_decision_service.py", "BLOCK", host_id]), \
                     contextlib.redirect_stdout(output):
                    result = client.main()
                self.assertEqual(result, 0)
                read_request = mocked.call_args_list[0].args[0]
                post_request = mocked.call_args_list[1].args[0]
                self.assertTrue(read_request.full_url.endswith("/topology/hosts"))
                self.assertEqual(read_request.get_header("Authorization"), f"Bearer {api_token}")
                self.assertTrue(post_request.full_url.endswith("/network/action"))
                self.assertEqual(post_request.get_header("X-secureiot-token"), control_token)
                payload = json.loads(post_request.data.decode("utf-8"))
                self.assertEqual(payload["action"], "BLOCK_DEVICE")
                self.assertEqual(payload["ip"], ip)
                self.assertEqual(payload["mac"], "00:00:00:00:00:aa")

    def test_h3_is_not_a_target_for_this_remaining_services_helper(self):
        output = io.StringIO()
        with patch("sys.argv", ["security_decision_service.py", "BLOCK", "h3"]), \
             patch.object(client, "urlopen") as mocked, \
             contextlib.redirect_stdout(output):
            result = client.main()
        self.assertEqual(result, 2)
        mocked.assert_not_called()
        self.assertIn("supported service primaries", output.getvalue())


if __name__ == "__main__":
    unittest.main()
