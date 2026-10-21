#!/usr/bin/env python3
"""Build packet/flow datasets from isolated per-run raw CSVs with validation reports."""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
import tempfile
import uuid
from pathlib import Path
from typing import Any

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "experiments" / "run_manifest.csv"
PROCESSED = ROOT / "processed"
LABELS = {"Normal", "Malicious_POST", "Port_Scan", "SYN_Flood"}
ATTACK_LABELS = {
    "malicious_post": "Malicious_POST",
    "port_scan": "Port_Scan",
    "syn_flood": "SYN_Flood",
}
IDENTITY_COLUMNS = ["run_id", "observation_id", "timestamp"]
PACKET_REQUIRED_COLUMNS = IDENTITY_COLUMNS + [
    "switch_dpid", "in_port", "src_mac", "dst_mac", "src_ip", "dst_ip",
    "protocol", "src_port", "dst_port", "packet_length", "tcp_flags",
    "icmp_type", "arp_operation",
]
FLOW_REQUIRED_COLUMNS = IDENTITY_COLUMNS + [
    "switch_dpid", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "priority", "packet_count", "byte_count", "packet_rate", "byte_rate",
    "duration_sec", "avg_packet_size", "syn_count", "ack_count", "rst_count",
    "fin_count", "syn_ack_ratio", "rst_ratio", "unique_dst_ports",
    "failed_connection_count", "tcp_fraction", "udp_fraction", "icmp_fraction",
    "source", "src_mac", "dst_mac",
]


def read_manifest(path: Path) -> tuple[dict[str, dict[str, str]], list[str]]:
    if not path.exists():
        raise ValueError(f"manifest_missing: {path}")
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle, strict=True)
        fields = reader.fieldnames or []
        if "run_id" not in fields:
            raise ValueError("manifest_invalid: run_id column missing")
        rows = list(reader)
    if not rows:
        raise ValueError("manifest_empty: no run records")
    by_id: dict[str, dict[str, str]] = {}
    for line_number, row in enumerate(rows, 2):
        run_id = (row.get("run_id") or "").strip()
        if not run_id:
            raise ValueError(f"manifest_invalid: empty run_id at row {line_number}")
        try:
            if str(uuid.UUID(run_id)) != run_id:
                raise ValueError
        except (ValueError, AttributeError, TypeError):
            raise ValueError(f"manifest_invalid: noncanonical run_id {run_id!r} at row {line_number}")
        if run_id in by_id:
            raise ValueError(f"manifest_duplicate_run_id: {run_id}")
        by_id[run_id] = row
    return by_id, fields


def label_for_run(run: dict[str, str]) -> str:
    if run.get("status") != "completed":
        raise ValueError(f"run_status_not_completed: {run.get('status')!r}")
    if run.get("run_type") == "normal":
        if run.get("label") not in (None, "", "Normal") or run.get("attack_type"):
            raise ValueError("manifest_label_mismatch: normal run must not have an attack label/type")
        if run.get("experiment_category") not in ("", "normal_baseline"):
            raise ValueError("normal_run_not_baseline: category is not normal_baseline")
        # Existing manifest schema stores normal label as empty; target label is Normal.
        return "Normal"
    if run.get("run_type") == "attack":
        expected = ATTACK_LABELS.get((run.get("attack_type") or "").strip().lower())
        if not expected or run.get("label") != expected:
            raise ValueError("manifest_label_mismatch: attack_type and label disagree")
        return expected
    raise ValueError(f"manifest_invalid_run_type: {run.get('run_type')!r}")


def validate_run_window(df: pd.DataFrame, run: dict[str, str], grace_sec: float) -> pd.DataFrame:
    try:
        start = float(run.get("start_time", ""))
        end = float(run.get("end_time", ""))
    except (TypeError, ValueError):
        raise ValueError("manifest_invalid_time_window")
    if not math.isfinite(start) or not math.isfinite(end) or start <= 0 or end < start:
        raise ValueError("manifest_invalid_time_window")
    ts = pd.to_numeric(df["timestamp"], errors="coerce")
    if ts.isna().any() or not ts.map(math.isfinite).all():
        raise ValueError("invalid_timestamp: rows must contain finite numeric timestamps")
    mask = (ts >= start) & (ts <= end + grace_sec)
    return df.loc[mask].copy()


def protocol_name(value: object) -> str:
    text = str(value).strip().lower()
    if text.endswith(".0"):
        text = text[:-2]
    return {
        "6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6",
        "0": "other", "2": "igmp", "tcp": "tcp", "udp": "udp",
        "icmp": "icmp", "unknown": "unknown",
    }.get(text, "other")


def flag_has(flags: object, name: str) -> int:
    text = str(flags).upper()
    if not text or text in {"NAN", "NONE"}:
        return 0
    bits = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "ACK": 0x10}
    try:
        return int(int(float(text)) & bits[name] != 0)
    except (ValueError, OverflowError):
        return int(bool(re.search(rf"\b{name}\b|{name[0]}", text)))


def numeric(df: pd.DataFrame, columns: list[str]) -> None:
    for column in columns:
        if column not in df.columns:
            continue
        source = df[column]
        if column in {"src_port", "dst_port"}:
            # Non-TCP/UDP observations legitimately have no transport port;
            # the collector serializes that as an empty string (or '*').
            source = source.map(
                lambda value: 0 if value is None or str(value).strip() in {"", "*"} else value
            )
        values = pd.to_numeric(source, errors="coerce")
        if values.isna().any() or not values.map(math.isfinite).all():
            raise ValueError(f"invalid_numeric_feature: {column}")
        df[column] = values


def build_packet(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for col in ["protocol", "src_port", "dst_port", "packet_length", "icmp_type", "arp_operation"]:
        if col not in df.columns:
            df[col] = "" if col == "protocol" else 0
    df["protocol"] = df["protocol"].fillna("unknown").map(protocol_name)
    # These protocol-specific fields are legitimately absent outside their
    # matching protocol (ICMP type for non-ICMP, ARP operation for non-ARP).
    for column in ("icmp_type", "arp_operation"):
        df[column] = df[column].map(
            lambda value: 0 if value is None or str(value).strip().lower() in {"", "none", "nan", "null"} else value
        )
    numeric(df, ["src_port", "dst_port", "packet_length", "icmp_type", "arp_operation"])
    flags = df["tcp_flags"] if "tcp_flags" in df else pd.Series("", index=df.index)
    for name in ["syn", "ack", "rst", "fin"]:
        df[f"tcp_{name}"] = flags.map(lambda x, n=name.upper(): flag_has(x, n)).astype("int8")
    keep = ["protocol", "src_port", "dst_port", "packet_length", "tcp_syn", "tcp_ack",
            "tcp_rst", "tcp_fin", "icmp_type", "arp_operation"]
    return df[keep]


def build_flow(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for col in ["protocol", "src_port", "dst_port", "packet_count", "byte_count",
                "packet_rate", "byte_rate", "duration_sec"]:
        if col not in df.columns:
            df[col] = "" if col == "protocol" else 0
    df["protocol"] = df["protocol"].fillna("unknown").map(protocol_name)
    numeric(df, ["src_port", "dst_port", "packet_count", "byte_count", "packet_rate", "byte_rate", "duration_sec"])
    if "avg_packet_size" not in df:
        df["avg_packet_size"] = (df["byte_count"] / df["packet_count"].clip(lower=1)).fillna(0)
    for col in ["syn_count", "ack_count", "rst_count", "fin_count", "unique_dst_ports", "failed_connection_count"]:
        if col not in df:
            df[col] = 0
    for col in ["syn_ack_ratio", "rst_ratio"]:
        if col not in df:
            df[col] = 0.0
    numeric(df, ["avg_packet_size", "syn_count", "ack_count", "rst_count", "fin_count",
                 "syn_ack_ratio", "rst_ratio", "unique_dst_ports", "failed_connection_count"])
    df["tcp_fraction"] = (df["protocol"] == "tcp").astype(float)
    df["udp_fraction"] = (df["protocol"] == "udp").astype(float)
    df["icmp_fraction"] = (df["protocol"] == "icmp").astype(float)
    keep = ["protocol", "src_port", "dst_port", "packet_count", "byte_count", "packet_rate",
            "byte_rate", "duration_sec", "avg_packet_size", "syn_count", "ack_count", "rst_count",
            "fin_count", "syn_ack_ratio", "rst_ratio", "unique_dst_ports",
            "failed_connection_count", "tcp_fraction", "udp_fraction", "icmp_fraction"]
    return df[keep]


def read_raw_file(path: Path, run_id: str, seen_observation_ids: set[str],
                  level: str) -> tuple[pd.DataFrame, int]:
    if path.stat().st_size == 0:
        raise ValueError("file_empty_zero_bytes")
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle, strict=True)
        fields = reader.fieldnames or []
        required = PACKET_REQUIRED_COLUMNS if level == "packet" else FLOW_REQUIRED_COLUMNS
        missing = [column for column in required if column not in fields]
        if missing:
            raise ValueError("raw_schema_missing_columns: " + ",".join(missing))
        rows = list(reader)
    if not rows:
        return pd.DataFrame(columns=fields), 0
    local_ids = set()
    for index, row in enumerate(rows, 2):
        if None in row or any(value is None for value in row.values()):
            raise ValueError(f"malformed_csv_row: line {index}")
        if row.get("run_id") != run_id:
            raise ValueError(f"row_run_id_mismatch: line {index}")
        observation_id = (row.get("observation_id") or "").strip()
        if not observation_id:
            raise ValueError(f"observation_id_missing: line {index}")
        if observation_id in local_ids or observation_id in seen_observation_ids:
            raise ValueError(f"observation_id_duplicate: {observation_id}")
        local_ids.add(observation_id)
    seen_observation_ids.update(local_ids)
    return pd.DataFrame(rows, columns=fields), len(rows)


def atomic_to_csv(df: pd.DataFrame, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", newline="", encoding="utf-8", dir=output.parent,
                                         prefix="." + output.name + ".", delete=False) as handle:
            temporary = Path(handle.name)
            df.to_csv(handle, index=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
        fd = os.open(str(output.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def build(level: str, input_dir: Path, output: Path, report_path: Path,
          manifest_path: Path = MANIFEST, grace_sec: float = 5.0) -> dict[str, Any]:
    report: dict[str, Any] = {
        "level": level, "input_dir": str(input_dir), "output": str(output),
        "manifest": str(manifest_path), "files": [], "missing_files": [],
        "summary": {"accepted_files": 0, "rejected_files": 0,
                    "empty_files": 0, "accepted_rows": 0, "rejected_rows": 0},
    }
    frames: list[pd.DataFrame] = []
    try:
        manifest, _ = read_manifest(manifest_path)
    except Exception as exc:
        report["fatal_error"] = str(exc)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return report

    if not input_dir.is_dir():
        report["input_directory_status"] = "missing"
        report["fatal_error"] = f"input_directory_missing: {input_dir}"
    else:
        discovered = sorted(input_dir.glob("*.csv"))
        discovered_ids = {path.stem for path in discovered}
        report["input_directory_status"] = "present"
        report["discovered_csv_files"] = len(discovered)
        for run_id, run in manifest.items():
            if run.get("status") == "completed" and run_id not in discovered_ids:
                report["missing_files"].append({"run_id": run_id, "status": "missing",
                                                 "reason": "completed_run_file_not_found"})
        seen_observation_ids: set[str] = set()
        for path in discovered:
            entry: dict[str, Any] = {"file": path.name, "run_id_from_filename": path.stem}
            try:
                run_id = path.stem
                try:
                    if str(uuid.UUID(run_id)) != run_id:
                        raise ValueError
                except (ValueError, AttributeError, TypeError):
                    raise ValueError("filename_run_id_invalid")
                if run_id not in manifest:
                    raise ValueError("run_id_not_in_manifest")
                run = manifest[run_id]
                label = label_for_run(run)
                df, raw_count = read_raw_file(path, run_id, seen_observation_ids, level)
                entry["raw_rows"] = raw_count
                if raw_count == 0:
                    entry["status"] = "empty"
                    entry["reason"] = "header_only_no_observations"
                    report["summary"]["empty_files"] += 1
                    report["files"].append(entry)
                    continue
                df = validate_run_window(df, run, grace_sec)
                source_ids = df["observation_id"].astype(str).tolist()
                built = build_packet(df) if level == "packet" else build_flow(df)
                built.insert(0, "observation_id", source_ids)
                built.insert(0, "run_id", run_id)
                built["label"] = label
                built["label_status"] = "matched"
                frames.append(built)
                entry.update({"status": "accepted", "accepted_rows": len(built), "label": label})
                if not len(built):
                    entry["status"] = "accepted_empty_window"
                    entry["reason"] = "no_rows_in_manifest_time_window"
                    report["summary"]["empty_files"] += 1
                else:
                    report["summary"]["accepted_files"] += 1
                    report["summary"]["accepted_rows"] += len(built)
            except Exception as exc:
                entry["status"] = "rejected"
                entry["reason"] = str(exc)
                report["summary"]["rejected_files"] += 1
                report["summary"]["rejected_rows"] += int(entry.get("raw_rows", 0))
            report["files"].append(entry)

    if frames:
        result = pd.concat(frames, ignore_index=True)
        # Deterministic stable output; every invocation replaces, never appends.
        atomic_to_csv(result, output)
        report["output_status"] = "written"
    else:
        result = pd.DataFrame(columns=["run_id", "observation_id", "label", "label_status"])
        # Do not overwrite a prior successful dataset with an empty file when
        # all inputs are missing, empty, or rejected.
        report["output_status"] = "unchanged_no_accepted_rows"
    report["summary"]["output_rows"] = len(result)
    report["summary"]["output_run_count"] = int(result["run_id"].nunique()) if "run_id" in result else 0
    report["summary"]["status"] = "completed_with_rejections" if report["summary"]["rejected_files"] or report["missing_files"] or report.get("fatal_error") else "completed"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--level", choices=["packet", "flow"], required=True)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--grace-sec", type=float, default=5.0)
    args = parser.parse_args()
    report_path = args.report or args.output.with_suffix(args.output.suffix + ".report.json")
    report = build(args.level, args.input_dir, args.output, report_path, args.manifest, args.grace_sec)
    print(json.dumps(report["summary"], ensure_ascii=False, sort_keys=True))
    return 1 if report.get("fatal_error") else 0


if __name__ == "__main__":
    raise SystemExit(main())
