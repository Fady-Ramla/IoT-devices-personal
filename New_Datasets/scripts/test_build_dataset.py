#!/usr/bin/env python3
"""Acceptance tests for Step 5; all inputs and outputs live in temporary directories."""
import csv
import json
import tempfile
import uuid
from pathlib import Path

from build_dataset import build


def make_run(run_id, start, end, label="", run_type="normal", attack_type="", category="normal_baseline"):
    return {
        "run_id": run_id, "run_type": run_type, "label": label,
        "attack_type": attack_type, "experiment_category": category,
        "start_time": str(start), "end_time": str(end),
        "status": "completed",
    }


def write_manifest(path, rows):
    fields = ["run_id", "run_type", "label", "attack_type", "experiment_category",
              "start_time", "end_time", "status"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def packet_row(run_id, observation_id, timestamp):
    return {
        "run_id": run_id, "observation_id": observation_id, "timestamp": timestamp,
        "switch_dpid": "1", "in_port": "2", "src_mac": "aa", "dst_mac": "bb",
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        "protocol": "6", "src_port": "1234", "dst_port": "5000",
        "packet_length": "60", "tcp_flags": "SYN", "icmp_type": "0", "arp_operation": "0",
    }


def write_csv(path, rows, fields=None):
    fields = fields or ["run_id", "observation_id", "timestamp", "switch_dpid", "in_port",
                        "src_mac", "dst_mac", "src_ip", "dst_ip", "protocol", "src_port",
                        "dst_port", "packet_length", "tcp_flags", "icmp_type", "arp_operation"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def flow_row(run_id, observation_id, timestamp):
    return {
        "run_id": run_id, "observation_id": observation_id, "timestamp": timestamp,
        "switch_dpid": "1", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        "src_port": "1234", "dst_port": "5000", "protocol": "6", "priority": "10",
        "packet_count": "5", "byte_count": "300", "packet_rate": "5", "byte_rate": "300",
        "duration_sec": "1", "avg_packet_size": "60", "syn_count": "2", "ack_count": "1",
        "rst_count": "0", "fin_count": "0", "syn_ack_ratio": "2", "rst_ratio": "0",
        "unique_dst_ports": "1", "failed_connection_count": "0", "tcp_fraction": "1",
        "udp_fraction": "0", "icmp_fraction": "0", "source": "switch_flow_stats",
        "src_mac": "aa", "dst_mac": "bb",
    }


def main():
    with tempfile.TemporaryDirectory(prefix="step5_builder_") as tmp:
        root = Path(tmp)
        raw = root / "raw" / "packet"
        raw.mkdir(parents=True)
        manifest = root / "run_manifest.csv"
        output = root / "processed" / "packet.csv"
        report_path = root / "processed" / "packet.report.json"
        r1, r2, r3, r4, orphan, wildcard_id = [str(uuid.uuid4()) for _ in range(6)]
        write_manifest(manifest, [
            make_run(r1, 100, 110),
            make_run(r2, 100, 110),
            make_run(r3, 100, 110),
            make_run(r4, 100, 110),
            make_run(wildcard_id, 100, 110),
        ])
        write_csv(raw / f"{r1}.csv", [packet_row(r1, "obs-r1-a", "105")])
        write_csv(raw / f"{r2}.csv", [packet_row(r2, "obs-r2-a", "106")])
        # File name belongs to r3, but its first row claims r1.
        write_csv(raw / f"{r3}.csv", [packet_row(r1, "obs-mismatch", "107")])
        # Duplicate observation IDs inside r4 must reject the entire file.
        write_csv(raw / f"{r4}.csv", [packet_row(r4, "duplicate", "107"),
                                         packet_row(r4, "duplicate", "108")])
        # Orphan ID not declared in manifest.
        write_csv(raw / f"{orphan}.csv", [packet_row(orphan, "obs-orphan", "109")])
        wildcard_packet = packet_row(wildcard_id, "obs-wildcard-port", "109")
        wildcard_packet["src_port"] = ""
        wildcard_packet["dst_port"] = "*"
        wildcard_packet["icmp_type"] = ""
        wildcard_packet["arp_operation"] = ""
        write_csv(raw / f"{wildcard_id}.csv", [wildcard_packet])
        missing_obs_id = str(uuid.uuid4())
        with manifest.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["run_id", "run_type", "label", "attack_type",
                "experiment_category", "start_time", "end_time", "status"])
            writer.writerow(make_run(missing_obs_id, 100, 110))
        write_csv(raw / f"{missing_obs_id}.csv", [{**packet_row(missing_obs_id, "", "109")}])
        zero_byte_id = str(uuid.uuid4())
        with manifest.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["run_id", "run_type", "label", "attack_type",
                "experiment_category", "start_time", "end_time", "status"])
            writer.writerow(make_run(zero_byte_id, 100, 110))
        (raw / f"{zero_byte_id}.csv").write_bytes(b"")
        # Existing completed run with header only is distinguishable from missing.
        empty_id = str(uuid.uuid4())
        with manifest.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["run_id", "run_type", "label", "attack_type",
                "experiment_category", "start_time", "end_time", "status"])
            writer.writerow(make_run(empty_id, 100, 110))
        write_csv(raw / f"{empty_id}.csv", [])

        first = build("packet", raw, output, report_path, manifest)
        assert first["summary"]["accepted_rows"] == 3
        assert first["summary"]["rejected_files"] == 5
        empty_report = next(item for item in first["files"] if item["run_id_from_filename"] == empty_id)
        assert empty_report["status"] == "empty"
        assert any(item.get("reason") == "row_run_id_mismatch: line 2" for item in first["files"])
        assert any(item.get("reason", "").startswith("observation_id_duplicate") for item in first["files"])
        assert any(item.get("reason") == "run_id_not_in_manifest" for item in first["files"])
        assert any(item.get("reason", "").startswith("observation_id_missing") for item in first["files"])
        assert any(item.get("reason") == "file_empty_zero_bytes" for item in first["files"])
        with output.open(newline="", encoding="utf-8") as handle:
            rows1 = list(csv.DictReader(handle))
        assert len(rows1) == 3
        by_run = {row["run_id"]: row for row in rows1}
        assert by_run[r1]["observation_id"] == "obs-r1-a"
        assert by_run[r2]["observation_id"] == "obs-r2-a"
        assert by_run[r1]["label"] == "Normal"
        assert by_run[wildcard_id]["src_port"] == "0"
        assert by_run[wildcard_id]["dst_port"] == "0"
        assert by_run[wildcard_id]["icmp_type"] == "0"
        assert by_run[wildcard_id]["arp_operation"] == "0"

        # Rerun writes the same row set (atomic replace), never appends duplicates.
        second = build("packet", raw, output, report_path, manifest)
        with output.open(newline="", encoding="utf-8") as handle:
            rows2 = list(csv.DictReader(handle))
        assert rows1 == rows2
        assert second["summary"]["output_rows"] == 3
        print("PASS: two run files remain correctly isolated and preserve source observation_ids")
        print("PASS: filename/content mismatch, orphan run, and duplicate observation_id are rejected")
        print("PASS: missing observation_id and zero-byte file are rejected explicitly")
        print("PASS: header-only input is reported as empty, distinct from missing/invalid files")
        print("PASS: labels come from manifest rules; normal empty manifest label becomes Normal")
        print("PASS: rerunning builder atomically replaces output without duplicate rows")

        flow_id = str(uuid.uuid4())
        with manifest.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["run_id", "run_type", "label", "attack_type",
                "experiment_category", "start_time", "end_time", "status"])
            writer.writerow(make_run(flow_id, 100, 110))
        flow_dir = root / "raw" / "flow"
        flow_dir.mkdir()
        flow_values = flow_row(flow_id, "flow-observation-1", "108")
        flow_values["src_port"] = ""
        flow_values["dst_port"] = "*"
        write_csv(flow_dir / f"{flow_id}.csv", [flow_values], list(flow_values))
        flow_output = root / "processed" / "flow.csv"
        flow_report = build("flow", flow_dir, flow_output, root / "processed" / "flow.json", manifest)
        assert flow_report["summary"]["accepted_rows"] == 1
        with flow_output.open(newline="", encoding="utf-8") as handle:
            flow_rows = list(csv.DictReader(handle))
        assert flow_rows[0]["run_id"] == flow_id
        assert flow_rows[0]["observation_id"] == "flow-observation-1"
        assert flow_rows[0]["label"] == "Normal"
        assert flow_rows[0]["src_port"] == "0" and flow_rows[0]["dst_port"] == "0"
        print("PASS: Flow schema and source IDs preserved; blank/'*' ports normalized to 0")
        print("PASS: packet absent ports/ICMP-type/ARP-operation normalized to 0, not rejected")

        # Missing files for completed runs are recorded rather than fabricated.
        missing_dir = root / "raw" / "missing"
        missing_report = build("packet", missing_dir, root / "missing.csv", root / "missing.json", manifest)
        assert missing_report.get("input_directory_status") == "missing"
        assert missing_report.get("fatal_error", "").startswith("input_directory_missing")
        assert not (root / "missing.csv").exists()
        print("PASS: missing input directory is reported explicitly")
        print("PASS: fatal/missing-input path does not create or overwrite dataset output")

        # Invalid timestamps are rejected instead of silently disappearing.
        bad_ts_id = str(uuid.uuid4())
        write_manifest(manifest, [make_run(bad_ts_id, 100, 110)])
        bad_dir = root / "raw" / "bad_ts"
        bad_dir.mkdir()
        write_csv(bad_dir / f"{bad_ts_id}.csv", [packet_row(bad_ts_id, "obs-bad", "NaN")])
        bad_report = build("packet", bad_dir, root / "bad_ts.csv", root / "bad_ts.json", manifest)
        assert bad_report["files"][0]["status"] == "rejected"
        assert bad_report["files"][0]["reason"].startswith("invalid_timestamp")
        print("PASS: invalid timestamp is rejected with an explicit reason")


if __name__ == "__main__":
    main()
