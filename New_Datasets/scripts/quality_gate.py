#!/usr/bin/env python3
"""Run-centric dataset quality gate.

This script is read-only with respect to raw telemetry and the run manifest. It
writes a per-run CSV and JSON summary containing accepted/review/rejected
quality decisions.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

ERROR_PATTERNS = (
    "curl: (28)",
    "connection timeout",
    "connection refused",
    "http error 4",
    "http error 5",
    "traceback",
    "unhandled",
    "command failed",
)

LABELS = {"Normal", "Port_Scan", "SYN_Flood", "Malicious_POST"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        default="New_Datasets/experiments/run_manifest.csv",
    )
    parser.add_argument(
        "--packet-dir",
        default="New_Datasets/raw/packet",
    )
    parser.add_argument(
        "--output-csv",
        default="New_Datasets/reports/quality_gate_report.csv",
    )
    parser.add_argument(
        "--output-json",
        default="New_Datasets/reports/quality_gate_summary.json",
    )
    parser.add_argument(
        "--min-scan-ports",
        type=int,
        default=10,
        help="Minimum observed destination ports for a scan to be accepted.",
    )
    return parser.parse_args()


def truthy(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def contains_error(text: str) -> str:
    lowered = text.lower()
    for pattern in ERROR_PATTERNS:
        if pattern in lowered:
            return pattern
    return ""


def read_packet_stats(path: Path) -> Dict[str, object]:
    if not path.exists():
        return {
            "packet_file_exists": False,
            "packet_rows": 0,
            "tcp_rows": 0,
            "unique_dst_ports": 0,
            "unique_src_ips": 0,
            "unique_dst_ips": 0,
            "syn_flags": 0,
            "rst_flags": 0,
            "packet_error": "missing_packet_file",
        }

    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    protocols = Counter(str(row.get("protocol", "")).strip().lower() for row in rows)
    src_ips = {row.get("src_ip", "").strip() for row in rows if row.get("src_ip", "").strip()}
    dst_ips = {row.get("dst_ip", "").strip() for row in rows if row.get("dst_ip", "").strip()}
    dst_ports = {
        row.get("dst_port", "").strip()
        for row in rows
        if row.get("dst_port", "").strip() and row.get("dst_port", "").strip() not in {"0", "nan"}
    }

    syn_flags = 0
    rst_flags = 0
    tcp_rows = 0
    for row in rows:
        protocol = str(row.get("protocol", "")).strip().lower()
        if protocol in {"6", "6.0", "tcp"}:
            tcp_rows += 1
        flags = str(row.get("tcp_flags", "")).strip()
        if flags in {"2", "2.0"}:
            syn_flags += 1
        if flags in {"4", "4.0"}:
            rst_flags += 1

    return {
        "packet_file_exists": True,
        "packet_rows": len(rows),
        "tcp_rows": tcp_rows,
        "unique_dst_ports": len(dst_ports),
        "unique_src_ips": len(src_ips),
        "unique_dst_ips": len(dst_ips),
        "syn_flags": syn_flags,
        "rst_flags": rst_flags,
        "packet_error": "",
        "protocols": ";".join(f"{key}:{value}" for key, value in sorted(protocols.items())),
    }


def evaluate(row: Dict[str, str], stats: Dict[str, object], min_scan_ports: int) -> Tuple[str, List[str]]:
    reasons: List[str] = []
    label = row.get("label", "").strip()
    status = row.get("status", "").strip().lower()
    notes = row.get("notes", "")
    error_pattern = contains_error(notes)

    if not row.get("run_id", "").strip():
        reasons.append("missing_run_id")
    if label not in LABELS:
        reasons.append("invalid_label")
    if status != "completed":
        reasons.append("status_not_completed")
    if error_pattern:
        reasons.append(f"execution_error:{error_pattern}")
    if not bool(stats["packet_file_exists"]):
        reasons.append("missing_packet_file")
    if int(stats["packet_rows"]) <= 0:
        reasons.append("empty_packet_file")

    if label == "Normal":
        # A successful collection with a failed application control is not a
        # valid Normal control.
        if error_pattern:
            reasons.append("normal_control_failed")
        if int(stats["packet_rows"]) < 10:
            reasons.append("normal_low_visibility")

    elif label == "Port_Scan":
        attack_type = row.get("attack_type", "").strip().lower()
        if attack_type != "port_scan":
            reasons.append("attack_type_mismatch")
        if int(stats["unique_dst_ports"]) < min_scan_ports:
            reasons.append("insufficient_scan_port_visibility")
        try:
            notes_obj = json.loads(notes) if notes.strip().startswith("{") else {}
        except json.JSONDecodeError:
            notes_obj = {}
        operator_notes = notes_obj.get("operator_notes", {})
        if isinstance(operator_notes, str):
            try:
                operator_notes = json.loads(operator_notes)
            except json.JSONDecodeError:
                operator_notes = {}
        if isinstance(operator_notes, dict) and operator_notes.get("full_scan_guaranteed") is False:
            reasons.append("full_scan_not_guaranteed")

    elif label == "SYN_Flood":
        if int(stats["tcp_rows"]) <= 0:
            reasons.append("missing_tcp_telemetry")
        if int(stats["syn_flags"]) <= 0:
            reasons.append("missing_syn_activity")

    elif label == "Malicious_POST":
        # Application-specific success/response checks remain reviewable by
        # the application telemetry gate; packet evidence alone cannot prove
        # the POST semantics.
        if "post" not in (row.get("service_name", "") + " " + notes).lower():
            reasons.append("post_provenance_not_explicit")

    if not reasons:
        return "accepted", reasons

    review_reasons = {"full_scan_not_guaranteed", "normal_low_visibility", "post_provenance_not_explicit"}
    if all(reason in review_reasons for reason in reasons):
        return "review", reasons
    return "rejected", reasons


def main() -> None:
    args = parse_args()
    manifest_path = Path(args.manifest)
    packet_dir = Path(args.packet_dir)
    output_csv = Path(args.output_csv)
    output_json = Path(args.output_json)

    if not manifest_path.exists():
        raise SystemExit(f"Manifest not found: {manifest_path}")

    with manifest_path.open(newline="", encoding="utf-8") as handle:
        manifest_rows = list(csv.DictReader(handle))

    report: List[Dict[str, object]] = []
    for row in manifest_rows:
        run_id = row.get("run_id", "").strip()
        stats = read_packet_stats(packet_dir / f"{run_id}.csv")
        decision, reasons = evaluate(row, stats, args.min_scan_ports)
        report.append({
            "run_id": run_id,
            "label": row.get("label", ""),
            "attack_type": row.get("attack_type", ""),
            "status": row.get("status", ""),
            "decision": decision,
            "reasons": ";".join(reasons),
            **{key: value for key, value in stats.items() if key != "protocols"},
            "protocols": stats.get("protocols", ""),
        })

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    output_json.parent.mkdir(parents=True, exist_ok=True)

    fields = list(report[0].keys()) if report else ["run_id", "decision", "reasons"]
    with output_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(report)

    counts = Counter(str(item["decision"]) for item in report)
    summary = {
        "manifest": str(manifest_path),
        "packet_dir": str(packet_dir),
        "min_scan_ports": args.min_scan_ports,
        "runs": len(report),
        "decisions": dict(sorted(counts.items())),
        "rejected_run_ids": [item["run_id"] for item in report if item["decision"] == "rejected"],
        "review_run_ids": [item["run_id"] for item in report if item["decision"] == "review"],
        "accepted_run_ids": [item["run_id"] for item in report if item["decision"] == "accepted"],
        "report_csv": str(output_csv),
    }
    with output_json.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
        handle.write("\n")

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
