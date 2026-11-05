#!/usr/bin/env python3
"""Offline AST-based smoke tests for per-run raw CSV output; writes only to temp dirs."""
import ast
import csv
import json
import os
import re
import tempfile
import threading
import uuid
from contextlib import nullcontext
from pathlib import Path

SOURCE = Path("mininet/traffic_monitor_merged.py")
source = SOURCE.read_text(encoding="utf-8")
tree = ast.parse(source)
constant_names = {
    "PROJECT_ROOT", "ACTIVE_RUN_FILE", "RAW_DATA_ROOT", "PACKET_DATA_DIR",
    "FLOW_DATA_DIR", "DATASET_RUN_LEDGER", "PACKET_HEADER", "FLOW_HEADER",
    "CSV_FLUSH_EVERY",
}
selected = []
for node in tree.body:
    if isinstance(node, ast.Assign) and any(
        isinstance(target, ast.Name) and target.id in constant_names
        for target in node.targets
    ):
        selected.append(node)
monitor_class = next(
    node for node in tree.body
    if isinstance(node, ast.ClassDef) and node.name == "TrafficMonitorMerged"
)
method_names = {
    "_valid_run_identity", "_active_run_matches", "_initialize_csv_files",
    "_validate_run_files", "_terminated_csv", "_open_run_csvs_locked",
    "_write_packet_feature", "_write_flow_feature_locked",
}
harness_class = ast.ClassDef(
    name="Harness", bases=[], keywords=[],
    body=[node for node in monitor_class.body
          if isinstance(node, ast.FunctionDef) and node.name in method_names],
    decorator_list=[],
)
module = ast.fix_missing_locations(ast.Module(body=selected + [harness_class], type_ignores=[]))
namespace = {
    "Path": Path, "os": os, "re": re, "uuid": uuid, "csv": csv,
    "json": json, "threading": threading, "__file__": str(SOURCE.resolve()),
}
exec(compile(module, "<step4-raw-test>", "exec"), namespace)
Harness = namespace["Harness"]


def make_monitor():
    obj = Harness()
    obj.used_run_ids = set()
    obj.dataset_error = None
    obj.dataset_closed = False
    obj.packet_file = obj.flow_file = None
    obj.packet_writer = obj.flow_writer = None
    obj.packet_rows_since_flush = obj.flow_rows_since_flush = 0
    obj.csv_lock = threading.Lock()
    obj.dataset_lock = nullcontext()
    obj.logger = type("Logger", (), {
        "error": lambda *args: None,
        "exception": lambda *args: None,
    })()
    return obj


def main():
    with tempfile.TemporaryDirectory(prefix="step4_raw_test_") as temp:
        root = Path(temp) / "raw"
        namespace["RAW_DATA_ROOT"] = root
        namespace["PACKET_DATA_DIR"] = root / "packet"
        namespace["FLOW_DATA_DIR"] = root / "flow"
        namespace["DATASET_RUN_LEDGER"] = root / ".dataset_run_ids.jsonl"
        namespace["ACTIVE_RUN_FILE"] = Path(temp) / "active_run.json"
        run_id = str(uuid.uuid4())
        generation = 12
        namespace["ACTIVE_RUN_FILE"].write_text(json.dumps({
            "run_id": run_id, "generation": generation, "status": "active",
        }), encoding="utf-8")

        monitor = make_monitor()
        monitor._initialize_csv_files()
        packet_handle, flow_handle, packet_path, flow_path = monitor._open_run_csvs_locked(run_id)
        monitor.packet_file, monitor.flow_file = packet_handle, flow_handle
        monitor.packet_writer, monitor.flow_writer = csv.writer(packet_handle), csv.writer(flow_handle)
        monitor.dataset_run = {
            "run_id": run_id, "generation": generation, "state": "active",
            "packet_observation_sequence": 0, "flow_observation_sequence": 0,
        }

        packet_values = ["t", 1, 1, "aa", "bb", "10.0.0.1", "10.0.0.2",
                         6, 123, 5000, 60, "SYN", 0, 0]
        flow_values = ["t", 1, "10.0.0.1", "10.0.0.2", 123, 5000, 6, 10,
                       5, 300, 5, 300, 1, 60, 2, 1, 0, 0, 2.0, 0.0,
                       1, 0, 1.0, 0.0, 0.0, "packetin_window", "aa", "bb"]
        assert monitor._write_packet_feature(packet_values, monitor.dataset_run)
        assert monitor._write_flow_feature_locked(flow_values, monitor.dataset_run)
        assert monitor.dataset_run["packet_observation_sequence"] == 1
        assert monitor.dataset_run["flow_observation_sequence"] == 1
        for handle in (packet_handle, flow_handle):
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()

        with packet_path.open(newline="", encoding="utf-8") as handle:
            packet_rows = list(csv.reader(handle))
        with flow_path.open(newline="", encoding="utf-8") as handle:
            flow_rows = list(csv.reader(handle))
        assert packet_rows[0] == namespace["PACKET_HEADER"]
        assert flow_rows[0] == namespace["FLOW_HEADER"]
        assert packet_rows[1][0] == run_id
        assert packet_rows[1][1] == run_id + "_packet_00000001"
        assert len(packet_rows[1]) == len(packet_rows[0])
        assert flow_rows[1][0] == run_id
        assert flow_rows[1][1] == run_id + "_flow_00000001"
        assert len(flow_rows[1]) == len(flow_rows[0])
        assert flow_rows[0][27] == "source" and flow_rows[1][27] == "packetin_window"
        print("PASS: packet and flow files created separately with current schema fields")
        print("PASS: run_id and unique type-specific observation_id written at capture")
        print("PASS: flow source metadata preserved")

        try:
            monitor._open_run_csvs_locked(run_id)
        except FileExistsError:
            pass
        else:
            raise AssertionError("existing run files were overwritten")

        rescan = make_monitor()
        rescan._initialize_csv_files()
        assert run_id in rescan.used_run_ids
        print("PASS: existing files validated and existing run_id reserved")
        print("PASS: existing run files are not overwritten")

        # Corrupt one row's run_id, then ensure startup fails closed.
        packet_path.write_text(packet_path.read_text(encoding="utf-8").replace(
            run_id + "," + run_id + "_packet_00000001", "wrong," + run_id + "_packet_00000001", 1
        ), encoding="utf-8")
        corrupt = make_monitor()
        try:
            corrupt._initialize_csv_files()
        except ValueError:
            print("PASS: row whose run_id disagrees with its file is rejected")
        else:
            raise AssertionError("mismatched row identity was accepted")


if __name__ == "__main__":
    main()
