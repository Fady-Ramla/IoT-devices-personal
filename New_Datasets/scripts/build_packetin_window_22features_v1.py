#!/usr/bin/env python3
"""Build the 4-class Packet-In Flow dataset using the exact 22-feature contract.

Reads completed runs from New_Datasets/experiments/run_manifest.csv and raw
per-run flow CSVs. Keeps source=packetin_window only, preserves the 22 Ryu
predictors including priority and source, excludes frozen holdout generations
550-709, never modifies source files, and refuses to overwrite output.
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
from typing import Dict, Tuple

LABELS = {"Normal", "Port_Scan", "SYN_Flood", "Malicious_POST"}
ATTACK_LABELS = {
    "port_scan": "Port_Scan",
    "syn_flood": "SYN_Flood",
    "malicious_post": "Malicious_POST",
}
HOLDOUT_GENERATION_START = 550
HOLDOUT_GENERATION_END = 709
FEATURES = [
    "protocol", "src_port", "dst_port", "priority", "packet_count",
    "byte_count", "packet_rate", "byte_rate", "duration_sec",
    "avg_packet_size", "syn_count", "ack_count", "rst_count", "fin_count",
    "syn_ack_ratio", "rst_ratio", "unique_dst_ports",
    "failed_connection_count", "tcp_fraction", "udp_fraction",
    "icmp_fraction", "source",
]
NUMERIC_FEATURES = [name for name in FEATURES if name not in {"protocol", "source"}]
OUTPUT_FIELDS = ["run_id", "observation_id", *FEATURES, "label"]


def run_label(row: Dict[str, str]) -> str:
    if (row.get("status") or "").strip().lower() != "completed":
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


def load_manifest(path: Path) -> Dict[str, Tuple[str, str, int]]:
    if not path.is_file():
        raise SystemExit(f"STOP: manifest not found: {path}")
    result: Dict[str, Tuple[str, str, int]] = {}
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle, strict=True)
        required = {"run_id", "generation", "status", "run_type", "label", "attack_type"}
        missing = sorted(required - set(reader.fieldnames or []))
        if missing:
            raise SystemExit(f"STOP: manifest is missing required columns: {missing}")
        for line, row in enumerate(reader, 2):
            run_id = (row.get("run_id") or "").strip()
            if not run_id:
                raise SystemExit(f"STOP: blank run_id in manifest line {line}")
            if run_id in result:
                raise SystemExit(f"STOP: duplicate manifest run_id: {run_id}")
            try:
                generation = int((row.get("generation") or "").strip())
            except ValueError as exc:
                raise SystemExit(f"STOP: invalid generation in manifest line {line}") from exc
            result[run_id] = (
                (row.get("status") or "").strip().lower(),
                run_label(row),
                generation,
            )
    return result


def normalize_row(raw: Dict[str, str], run_id: str, label: str,
                  path: Path, line: int) -> Dict[str, str]:
    missing = [name for name in FEATURES if name not in raw]
    if missing:
        raise ValueError(f"{path.name}:{line}: missing feature columns {missing}")
    observation_id = (raw.get("observation_id") or "").strip()
    if not observation_id:
        raise ValueError(f"{path.name}:{line}: blank observation_id")
    protocol = (raw.get("protocol") or "").strip().lower()
    if not protocol:
        raise ValueError(f"{path.name}:{line}: blank protocol")
    source = (raw.get("source") or "").strip()
    if source != "packetin_window":
        raise ValueError(f"{path.name}:{line}: expected source=packetin_window, got {source!r}")

    out = {"run_id": run_id, "observation_id": observation_id, "protocol": protocol}
    for name in NUMERIC_FEATURES:
        text = (raw.get(name) or "").strip()
        # Ryu may leave transport ports empty for mixed-protocol/multi-port windows;
        # preserve the existing dataset convention of representing these as zero.
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
    out["source"] = source
    out["label"] = label
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("New_Datasets"),
                        help="New_Datasets directory containing experiments/ and raw/")
    parser.add_argument(
        "--output", type=Path,
        default=Path("New_Datasets/AI_OFFLINE_LEARNING_V3/packetin_window_4class_22features.csv"),
    )
    args = parser.parse_args()
    root = args.root
    manifest = load_manifest(root / "experiments" / "run_manifest.csv")
    flow_dir = root / "raw" / "flow"
    if not flow_dir.is_dir():
        raise SystemExit(f"STOP: raw flow directory not found: {flow_dir}")
    if args.output.exists():
        raise SystemExit(f"STOP: output already exists; refusing to overwrite: {args.output}")
    files = sorted(flow_dir.glob("*.csv"))
    if not files:
        raise SystemExit(f"STOP: no per-run CSVs found under {flow_dir}")

    rows = []
    seen_ids = set()
    row_counts = Counter()
    runs_by_label = defaultdict(set)
    feature_vector_labels = defaultdict(set)
    raw_packetin_rows = 0
    skipped_incomplete = 0
    skipped_unknown_run = 0
    excluded_holdout_rows = 0
    excluded_holdout_runs = set()

    for path in files:
        file_run_id = path.stem
        with path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle, strict=True)
            missing_columns = sorted(set(FEATURES + ["run_id", "observation_id"]) - set(reader.fieldnames or []))
            if missing_columns:
                raise SystemExit(f"STOP: {path.name} is missing required raw columns: {missing_columns}")
            for line, raw in enumerate(reader, 2):
                if (raw.get("source") or "").strip() != "packetin_window":
                    continue
                raw_packetin_rows += 1
                run_id = (raw.get("run_id") or "").strip()
                if not run_id:
                    raise SystemExit(f"STOP: blank run_id in {path.name}:{line}")
                if run_id != file_run_id:
                    raise SystemExit(f"STOP: filename/run_id mismatch at {path.name}:{line}: {run_id}")
                meta = manifest.get(run_id)
                if meta is None:
                    skipped_unknown_run += 1
                    continue
                status, label, generation = meta
                if HOLDOUT_GENERATION_START <= generation <= HOLDOUT_GENERATION_END:
                    excluded_holdout_rows += 1
                    excluded_holdout_runs.add(run_id)
                    continue
                if status != "completed" or label not in LABELS:
                    skipped_incomplete += 1
                    continue
                try:
                    row = normalize_row(raw, run_id, label, path, line)
                except ValueError as exc:
                    raise SystemExit(f"STOP: {exc}") from exc
                observation_id = row["observation_id"]
                if observation_id in seen_ids:
                    raise SystemExit(f"STOP: duplicate Packet-In observation_id: {observation_id}")
                seen_ids.add(observation_id)
                rows.append(row)
                row_counts[label] += 1
                runs_by_label[label].add(run_id)
                vector = tuple(row[name] for name in FEATURES)
                feature_vector_labels[vector].add(label)

    if not rows:
        raise SystemExit("STOP: no eligible Packet-In rows outside the frozen holdout")
    missing_labels = LABELS - set(row_counts)
    if missing_labels:
        raise SystemExit(f"STOP: class(es) absent after holdout exclusion: {sorted(missing_labels)}")

    report = {
        "source_filter": "source=packetin_window",
        "model_features": FEATURES,
        "output_rows": len(rows),
        "raw_packetin_window_rows_seen": raw_packetin_rows,
        "excluded_holdout_generation_range": [HOLDOUT_GENERATION_START, HOLDOUT_GENERATION_END],
        "excluded_holdout_runs": len(excluded_holdout_runs),
        "excluded_holdout_rows": excluded_holdout_rows,
        "skipped_incomplete_or_invalid_label": skipped_incomplete,
        "skipped_unknown_manifest_run": skipped_unknown_run,
        "duplicate_observation_ids": 0,
        "blank_model_features": 0,
        "rows_by_label": {label: row_counts[label] for label in sorted(LABELS)},
        "runs_by_label": {label: len(runs_by_label[label]) for label in sorted(LABELS)},
        "unique_feature_vectors": len(feature_vector_labels),
        "rows_beyond_one_per_feature_vector": len(rows) - len(feature_vector_labels),
        "feature_vectors_with_conflicting_labels": sum(
            1 for labels in feature_vector_labels.values() if len(labels) > 1
        ),
        "identifiers_retained_for_audit_not_model_input": ["run_id", "observation_id"],
    }

    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", newline="", encoding="utf-8", dir=output.parent,
            prefix="." + output.name + ".", delete=False,
        ) as handle:
            temp_path = handle.name
            writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS, extrasaction="raise")
            writer.writeheader()
            writer.writerows(rows)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temp_path, output)
        os.unlink(temp_path)
        temp_path = None
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)

    report["output_file"] = str(output)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print("\nBUILD PASS: raw data and manifest were read-only; 22 Ryu features preserved; holdout generations excluded.")
    print("Next: split by run_id; keep the 550-709 holdout generation range excluded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
