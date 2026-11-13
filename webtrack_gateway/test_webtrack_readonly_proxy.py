import http.client
import importlib.util
import json
import os
from pathlib import Path
import threading
import unittest
from http.server import ThreadingHTTPServer


os.environ.setdefault("SECUREIOT_API_TOKEN", "test-only-upstream-token-" + "x" * 32)
PROXY_PATH = Path(__file__).with_name("webtrack_readonly_proxy.py")
SPEC = importlib.util.spec_from_file_location("webtrack_readonly_proxy", PROXY_PATH)
proxy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proxy)


class PublicReadOnlyGatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_upstream_json = proxy.GatewayHandler._upstream_json

        def fake_upstream(handler, path_and_query):
            return {"requested": path_and_query}, None

        proxy.GatewayHandler._upstream_json = fake_upstream
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), proxy.GatewayHandler)
        cls.server.daemon_threads = True
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        proxy.GatewayHandler._upstream_json = cls.original_upstream_json

    def request(self, method, path):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        connection.request(method, path)
        response = connection.getresponse()
        body = response.read()
        connection.close()
        return response.status, body

    def test_public_snapshot_get_needs_no_client_token(self):
        status, body = self.request("GET", "/dashboard/snapshot")
        payload = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertIn("iot_telemetry", payload["data"])
        self.assertIn("flow_stats_s6", payload["data"])

    def test_allowlisted_iot_get_needs_no_client_token(self):
        status, body = self.request("GET", "/api/iot/telemetry?limit=5")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"requested": "/api/iot/telemetry?limit=5"})

    def test_unapproved_query_is_rejected(self):
        status, _ = self.request("GET", "/api/iot/telemetry?control=1")
        self.assertEqual(status, 400)

    def test_unallowlisted_control_path_is_rejected(self):
        status, _ = self.request("GET", "/network/action")
        self.assertEqual(status, 404)

    def test_post_is_rejected(self):
        status, _ = self.request("POST", "/dashboard/snapshot")
        self.assertEqual(status, 405)

    def test_head_is_rejected(self):
        status, _ = self.request("HEAD", "/dashboard/snapshot")
        self.assertEqual(status, 405)


if __name__ == "__main__":
    unittest.main()
