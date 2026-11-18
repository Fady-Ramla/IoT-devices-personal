#!/usr/bin/env python3
"""Build a 4-class offline CSV from completed Packet-In-derived flow windows.

Reads New_Datasets/experiments/run_manifest.csv and New_Datasets/raw/flow/*.csv.
Selects only rows whose source is packetin_window and whose run is completed.
Never modifies raw data or the manifest, never fabricates rows, and refuses to
overwrite the output. Repeated feature vectors are reported, not deleted.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

LABELS = {"Normal", "Port_Scan", "SYN_Flood", "Malicious_POST"}
ATTACK_LABELS = {
    "port_scan": "Port_Scan",
    "syn_flood": "SYN_Flood",
    "malicious_post": "Malicious_POST",
}
FEATURES = [
    "protocol", "src_port", "dst_port", "packet_count", "byte_count",
    "packet_rate", "byte_rate", "duration_sec", "avg_packet_size",
    "syn_count", "ack_count", "rst_count", "fin_count", "syn_ack_ratio",
    "rst_ratio", "unique_dst_ports", "failed_connection_count",
    "tcp_fraction", "udp_fraction", "icmp_fraction",
]
NUMERIC_FEATURES = [name for name in FEATURES if name != "protocol"]
OUTPUT_FIELDS = ["run_id", "observation_id", *FEATURES, "label"]


def run_label(row: dict[str, str]) -> str:
    status = (row.get("status") or "").strip().lower()
    if status != "completed":
        return ""
    run_type = (row.get("run_type") or "").strip().lower()
    if run_type == "normal":
        return "Normal"
    if run_type == "attack":
        label = (row.get("label") or "").strip()
        expected = ATTACK_LABELS.get((row.get("attack_type") or "").strip().lower())
        if expected and label == expected:
            return expected
    return ""


def load_manifest(path: Path) -> dict[str, tuple[str, str]]:
    if not path.is_file():
        raise SystemExit(f"STOP: manifest not found: {path}")
    result: dict[str, tuple[str, str]] = {}
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle, strict=True)
        if not reader.fieldnames or "run_id" not in reader.fieldnames:
            raise SystemExit("STOP: manifest is missing run_id column")
        for line, row in enumerate(reader, 2):
            run_id = (row.get("run_id") or "").strip()
            if not run_id:
                raise SystemExit(f"STOP: blank run_id in manifest line {line}")
            if run_id in result:
                raise SystemExit(f"STOP: duplicate manifest run_id: {run_id}")
            result[run_id] = ((row.get("status") or "").strip().lower(), run_label(row))
    return result


def normalize_row(raw: dict[str, str], run_id: str, label: str,
                  path: Path, line: int) -> dict[str, str]:
    missing = [name for name in FEATURES if name not in raw]
    if missing:
        raise ValueError(f"{path.name}:{line}: missing feature columns {missing}")
    out = {"run_id": run_id, "observation_id": (raw.get("observation_id") or "").strip()}
    if not out["observation_id"]:
        raise ValueError(f"{path.name}:{line}: blank observation_id")
    protocol = (raw.get("protocol") or "").strip().lower()
    if not protocol:
        raise ValueError(f"{path.name}:{line}: blank protocol")
    out["protocol"] = protocol
    for name in NUMERIC_FEATURES:
        text = (raw.get(name) or "").strip()
        # Empty transport ports are expected when a 10-second window observed
        # multiple ports or a non-TCP/UDP protocol; represent them as zero.
        if name in {"src_port", "dst_port"} and text in {"", "*"}:
            text = "0"
        if not text:
            raise ValueError(f"{path.name}:{line}: blank model feature {name}")
        try:
            number = float(text)
        except ValueError as exc:
            raise ValueError(f"{path.name}:{line}: nonnumeric {name}={text!r}") from exc
        if not math.isfinite(number):
            raise ValueError(f"{path.name}:{line}: non-finite {name}={text!r}")
        out[name] = str(int(number)) if number.is_integer() else format(number, ".12g")
    out["label"] = label
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("New_Datasets"))
    parser.add_argument(
        "--output", type=Path,
        default=Path("New_Datasets/AI_OFFLINE_LEARNING_V2/packetin_window_4class.csv"),
    )
    args = parser.parse_args()
    root = args.root
    manifest_path = root / "experiments" / "run_manifest.csv"
    flow_dir = root / "raw" / "flow"
    manifest = load_manifest(manifest_path)
    if not flow_dir.is_dir():
        raise SystemExit(f"STOP: raw flow directory not found: {flow_dir}")
    if args.output.exists():
        raise SystemExit(f"STOP: output already exists; refusing to overwrite: {args.output}")

    rows: list[dict[str, str]] = []
    seen_packetin_ids: set[str] = set()
    batch_rows = Counter()
    run_ids_by_label: dict[str, set[str]] = defaultdict(set)
    raw_packetin_rows = 0
    skipped_incomplete = 0
    skipped_unknown_run = 0
    feature_vectors: dict[tuple[str, ...], set[str]] = defaultdict(set)

    files = sorted(flow_dir.glob("*.csv"))
    if not files:
        raise SystemExit(f"STOP: no per-run CSVs found under {flow_dir}")

    for path in files:
        file_run_id = path.stem
        with path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle, strict=True)
            if not reader.fieldnames or "source" not in reader.fieldnames:
                raise SystemExit(f"STOP: source column missing in {path}")
            for line, raw in enumerate(reader, 2):
                if (raw.get("source") or "").strip() != "packetin_window":
                    continue
                raw_packetin_rows += 1
                run_id = (raw.get("run_id") or "").strip()
                observation_id = (raw.get("observation_id") or "").strip()
                if not run_id or not observation_id:
                    raise SystemExit(f"STOP: missing identity in {path.name}:{line}")
                if run_id != file_run_id:
                    raise SystemExit(
                        f"STOP: filename/run_id mismatch at {path.name}:{line}: {run_id}"
                    )
                if observation_id in seen_packetin_ids:
                    raise SystemExit(f"STOP: duplicate Packet-In observation_id: {observation_id}")
                seen_packetin_ids.add(observation_id)
                meta = manifest.get(run_id)
                if meta is None:
                    skipped_unknown_run += 1
                    continue
                status, label = meta
                if status != "completed" or label not in LABELS:
                    skipped_incomplete += 1
                    continue
                try:
                    row = normalize_row(raw, run_id, label, path, line)
                except ValueError as exc:
                    raise SystemExit(f"STOP: {exc}") from exc
                rows.append(row)
                batch_rows[label] += 1
                run_ids_by_label[label].add(run_id)
                vector = tuple(row[name] for name in FEATURES)
                feature_vectors[vector].add(label)

    if not rows:
        raise SystemExit("STOP: no eligible Packet-In window rows found")
    missing_classes = LABELS - set(batch_rows)
    if missing_classes:
        raise SystemExit(f"STOP: one or more classes absent: {sorted(missing_classes)}")

    repeated_vectors = sum(1 for labels in feature_vectors.values() if len(labels) >= 1)
    conflicting_vectors = sum(1 for labels in feature_vectors.values() if len(labels) > 1)
    report = {
        "source": "completed manifest runs; raw flow rows with source=packetin_window",
        "output_rows": len(rows),
        "raw_packetin_window_rows": raw_packetin_rows,
        "skipped_incomplete_or_invalid_label": skipped_incomplete,
        "skipped_unknown_manifest_run": skipped_unknown_run,
        "duplicate_observation_ids": 0,
        "blank_model_features": 0,
        "rows_by_label": {label: batch_rows[label] for label in sorted(LABELS)},
        "runs_by_label": {label: len(run_ids_by_label[label]) for label in sorted(LABELS)},
        "unique_feature_vectors": len(feature_vectors),
        "feature_vectors_with_multiple_observations": len(rows) - len(feature_vectors),
        "feature_vectors_seen_with_conflicting_labels": conflicting_vectors,
        "model_features": FEATURES,
        "identifiers_retained_for_audit_not_model_input": ["run_id", "observation_id"],
    }

    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", newline="", encoding="utf-8", dir=output.parent,
            prefix="." + output.name + ".", delete=False,
        ) as handle:
            tmp_name = handle.name
            writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS, extrasaction="raise")
            writer.writeheader()
            writer.writerows(rows)
            handle.flush()
            os.fsync(handle.fileno())
        # Hard-link creation fails if output appeared concurrently; no overwrite.
        os.link(tmp_name, output)
        os.unlink(tmp_name)
        tmp_name = None
    finally:
        if tmp_name and os.path.exists(tmp_name):
            os.unlink(tmp_name)

    report["output_file"] = str(output)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print("\nBUILD PASS: source files and manifest were read-only; no rows were fabricated or deduplicated by feature values.")
    print("Next: split whole run_id groups; never random-split individual rows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
