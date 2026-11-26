#!/usr/bin/env python3
"""Offline/local integration test for the asynchronous AI JSON POST client."""
import ast
import json
import logging
import queue
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

SOURCE = Path(__file__).resolve().parents[1] / "traffic_monitor_merged.py"
FLOW_HEADER = [
    "run_id", "observation_id", "timestamp", "switch_dpid", "src_ip", "dst_ip",
    "src_port", "dst_port", "protocol", "priority", "packet_count", "byte_count",
    "packet_rate", "byte_rate", "duration_sec", "avg_packet_size", "syn_count",
    "ack_count", "rst_count", "fin_count", "syn_ack_ratio", "rst_ratio",
    "unique_dst_ports", "failed_connection_count", "tcp_fraction", "udp_fraction",
    "icmp_fraction", "source", "src_mac", "dst_mac",
    "src_endpoint_mac", "dst_endpoint_mac"
]
FEATURES = [
    "src_port", "dst_port", "protocol", "priority", "packet_count", "byte_count",
    "packet_rate", "byte_rate", "duration_sec", "avg_packet_size", "syn_count",
    "ack_count", "rst_count", "fin_count", "syn_ack_ratio", "rst_ratio",
    "unique_dst_ports", "failed_connection_count", "tcp_fraction", "udp_fraction",
    "icmp_fraction", "source",
]
CONTEXT = ("run_id", "observation_id", "timestamp", "switch_dpid",
           "src_ip", "dst_ip", "src_mac", "dst_mac",
           "src_endpoint_mac", "dst_endpoint_mac",
           "mac_observations", "mac_observations_truncated")


def load_subject():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    target_class = next(node for node in tree.body
                        if isinstance(node, ast.ClassDef)
                        and node.name == "AIFlowPoster")
    payload_builder = next(node for node in tree.body
                           if isinstance(node, ast.FunctionDef)
                           and node.name == "build_ai_flow_payload")
    module = ast.fix_missing_locations(ast.Module(
        body=[payload_builder, target_class], type_ignores=[]))
    namespace = {
        "AI_FEATURE_FIELDS": FEATURES,
        "AI_CONTEXT_FIELDS": CONTEXT,
        "AI_API_URL": "",
        "AI_API_TOKEN": "",
        "AI_POST_TIMEOUT": 2.0,
        "AI_QUEUE_SIZE": 100,
        "queue": queue,
        "threading": threading,
        "json": json,
        "urllib": urllib,
        "URLError": URLError,
        "Request": Request,
        "urlopen": urlopen,
    }
    exec(compile(module, str(SOURCE), "exec"), namespace)
    return namespace["AIFlowPoster"], namespace["build_ai_flow_payload"]


class NoopLock:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class CapturingWriter:
    def __init__(self):
        self.rows = []

    def writerow(self, row):
        self.rows.append(row)


class CapturingPoster:
    def __init__(self):
        self.payloads = []

    def enqueue(self, payload):
        self.payloads.append(payload)
        return True


def load_flow_writer():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    monitor = next(node for node in tree.body
                   if isinstance(node, ast.ClassDef)
                   and node.name == "TrafficMonitorMerged")
    method = next(node for node in monitor.body
                  if isinstance(node, ast.FunctionDef)
                  and node.name == "_write_flow_feature_locked")
    module = ast.fix_missing_locations(ast.Module(
        body=[ast.FunctionDef(
            name="build_ai_flow_payload",
            args=ast.arguments(posonlyargs=[], args=[ast.arg(arg="record")],
                               kwonlyargs=[], kw_defaults=[], defaults=[]),
            body=[ast.Return(value=ast.Dict(
                keys=[ast.Constant("features"), ast.Constant("context")],
                values=[
                    ast.Dict(keys=[ast.Constant(name) for name in FEATURES],
                             values=[ast.Call(func=ast.Attribute(ast.Name("record", ast.Load()),
                                                                "get", ast.Load()),
                                              args=[ast.Constant(name), ast.Constant("")],
                                              keywords=[]) for name in FEATURES]),
                    ast.Dict(keys=[ast.Constant(name) for name in CONTEXT],
                             values=[ast.Call(func=ast.Attribute(ast.Name("record", ast.Load()),
                                                                "get", ast.Load()),
                                              args=[ast.Constant(name), ast.Constant("")],
                                              keywords=[]) for name in CONTEXT]),
                ]))], decorator_list=[]),
              ast.ClassDef(name="Harness", bases=[], keywords=[],
                           body=[method], decorator_list=[])], type_ignores=[]))
    namespace = {"FLOW_HEADER": FLOW_HEADER, "CSV_FLUSH_EVERY": 50}
    exec(compile(module, str(SOURCE), "exec"), namespace)
    return namespace["Harness"]


class CaptureHandler(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.__class__.received.append((self.path, self.headers, json.loads(body)))
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"received":true}')

    def log_message(self, fmt, *args):
        pass


class AIFlowPosterTest(unittest.TestCase):
    def test_production_module_imports_http_helpers(self):
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        imported = {
            (node.module, alias.name)
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
        self.assertIn(("urllib.error", "URLError"), imported)
        self.assertIn(("urllib.request", "Request"), imported)
        self.assertIn(("urllib.request", "urlopen"), imported)

    def test_payload_has_22_features_and_trace_context(self):
        _, build_payload = load_subject()
        self.assertEqual(FLOW_HEADER[6:28], FEATURES)
        record = {name: "sample" for name in FLOW_HEADER}
        record["mac_observations"] = [{
            "switch_dpid": 4,
            "src_mac": "aa:bb:cc:dd:ee:01",
            "dst_mac": "02:10:00:00:00:01",
        }]
        record["mac_observations_truncated"] = False
        payload = build_payload(record)
        self.assertEqual(set(payload), {"features", "context"})
        self.assertEqual(list(payload["features"]), FEATURES)
        self.assertEqual(len(payload["features"]), 22)
        self.assertEqual(set(payload["context"]), set(CONTEXT))
        self.assertEqual(payload["context"]["src_mac"], "sample")
        self.assertEqual(payload["context"]["src_endpoint_mac"], "sample")
        self.assertEqual(payload["context"]["dst_endpoint_mac"], "sample")
        self.assertEqual(len(payload["context"]["mac_observations"]), 1)
        self.assertFalse(payload["context"]["mac_observations_truncated"])

    def test_missing_ambiguous_ports_match_dataset_zero_encoding(self):
        _, build_payload = load_subject()
        record = {name: 0 for name in FLOW_HEADER}
        record.update({"src_port": "", "dst_port": "5000"})
        features = build_payload(record)["features"]
        self.assertEqual(features["src_port"], 0)
        self.assertIsInstance(features["src_port"], int)
        self.assertEqual(features["dst_port"], 5000)
        self.assertIsInstance(features["dst_port"], int)
        record["src_port"] = "*"
        record["dst_port"] = "not-a-port"
        features = build_payload(record)["features"]
        self.assertEqual(features["src_port"], 0)
        self.assertEqual(features["dst_port"], 0)

    def test_flow_writer_posts_packetin_windows_only_after_csv_write(self):
        Harness = load_flow_writer()
        subject = Harness()
        run = {"run_id": "run-1", "generation": 1, "state": "active",
               "flow_observation_sequence": 0}
        subject.dataset_run = run
        subject.dataset_error = None
        subject.dataset_closed = False
        subject._active_run_matches = lambda current: True
        subject.dataset_lock = NoopLock()
        subject.csv_lock = NoopLock()
        subject.flow_writer = CapturingWriter()
        subject.flow_file = None
        subject.flow_rows_since_flush = 0
        subject.ai_flow_poster = CapturingPoster()
        subject.packet_flow_mac_observations = {
            ("run-1", 1, "10.10.10.5", "10.10.20.2", "tcp", "51514", "5000"):
                {"items": [{"switch_dpid": 4, "src_mac": "aa:bb:cc:dd:ee:01",
                            "dst_mac": "02:10:00:00:00:01"}], "truncated": False}
        }
        row = [0] * (len(FLOW_HEADER) - 2)
        row[0:6] = [123.5, 4, "10.10.10.5", "10.10.20.2", 51514, 5000]
        row[6] = "tcp"
        row[25] = "packetin_window"
        row[26:30] = [
            "aa:bb:cc:dd:ee:01", "02:10:00:00:00:01",
            "00:00:00:00:00:06", "00:00:00:00:00:03",
        ]
        self.assertTrue(subject._write_flow_feature_locked(row, run))
        self.assertEqual(len(subject.flow_writer.rows), 1)
        self.assertEqual(len(subject.ai_flow_poster.payloads), 1)
        self.assertEqual(subject.ai_flow_poster.payloads[0]["context"]["observation_id"],
                         "run-1_flow_00000001")
        payload_context = subject.ai_flow_poster.payloads[0]["context"]
        self.assertEqual(payload_context["src_mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(payload_context["dst_mac"], "02:10:00:00:00:01")
        self.assertEqual(payload_context["src_endpoint_mac"], "00:00:00:00:00:06")
        self.assertEqual(payload_context["dst_endpoint_mac"], "00:00:00:00:00:03")
        self.assertEqual(payload_context["mac_observations"],
                         [{"switch_dpid": 4, "src_mac": "aa:bb:cc:dd:ee:01",
                           "dst_mac": "02:10:00:00:00:01"}])
        row[25] = "switch_flow_stats"
        self.assertTrue(subject._write_flow_feature_locked(row, run))
        self.assertEqual(len(subject.flow_writer.rows), 2)
        self.assertEqual(len(subject.ai_flow_poster.payloads), 1)

    def test_async_post_sends_json_and_bearer_token(self):
        Poster, build_payload = load_subject()
        CaptureHandler.received = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), CaptureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            endpoint = "http://127.0.0.1:%d/predict" % server.server_address[1]
            poster = Poster(logging.getLogger("poster-test"), endpoint=endpoint,
                            token="test-token", timeout=1.5)
            record = {name: "sample" for name in FLOW_HEADER}
            record.update({"run_id": "run-1", "observation_id": "obs-1",
                           "src_ip": "10.10.10.5", "dst_ip": "10.10.20.2",
                           "src_mac": "aa:bb:cc:dd:ee:01",
                           "dst_mac": "02:20:00:00:00:01",
                           "src_endpoint_mac": "00:00:00:00:00:06",
                           "dst_endpoint_mac": "00:00:00:00:00:03"})
            payload = build_payload(record)
            self.assertTrue(poster.enqueue(payload))
            poster.pending.join()
            self.assertEqual(len(CaptureHandler.received), 1)
            path, headers, received = CaptureHandler.received[0]
            self.assertEqual(path, "/predict")
            self.assertEqual(headers.get("Content-Type"), "application/json")
            self.assertEqual(headers.get("Authorization"), "Bearer test-token")
            self.assertEqual(received, payload)
            self.assertEqual(received["context"]["src_mac"], "aa:bb:cc:dd:ee:01")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
