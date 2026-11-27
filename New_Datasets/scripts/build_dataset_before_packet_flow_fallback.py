#!/usr/bin/env python3
"""Build leakage-safe offline packet or flow datasets from per-run raw CSV files.

Expected input layout:
  raw/flow/<run_id>.csv
  raw/packet/<run_id>.csv

The filename stem is the run_id. Labels are read from experiments/run_manifest.csv;
no label is inferred from traffic values.
"""
from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "experiments" / "run_manifest.csv"
OUT = ROOT / "processed"


def read_manifest() -> dict[str, dict[str, str]]:
    if not MANIFEST.exists():
        raise SystemExit(f"missing manifest: {MANIFEST}")
    with MANIFEST.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    result = {r["run_id"]: r for r in rows if r.get("run_id")}
    if not result:
        raise SystemExit("run_manifest.csv is empty; register runs before building")
    return result


def protocol_name(value: object) -> str:
    text = str(value).strip().lower()
    return {"6": "tcp", "17": "udp", "1": "icmp"}.get(text, text or "unknown")


def flag_has(flags: object, name: str) -> int:
    text = str(flags).upper()
    if not text or text in {"NAN", "NONE"}:
        return 0
    # Ryu may emit numeric bitmasks or textual flag representations.
    bits = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "ACK": 0x10}
    try:
        return int(int(float(text)) & bits[name] != 0)
    except ValueError:
        return int(bool(re.search(rf"\\b{name}\\b|{name[0]}", text)))


def numeric(df: pd.DataFrame, columns: list[str]) -> None:
    for col in columns:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)


def build_packet(df: pd.DataFrame) -> pd.DataFrame:
    rename = {"protocol": "protocol"}
    df = df.rename(columns=rename).copy()
    for col in ["protocol", "src_port", "dst_port", "packet_length", "icmp_type", "arp_operation"]:
        if col not in df:
            df[col] = "" if col == "protocol" else 0
    df["protocol"] = df["protocol"].map(protocol_name)
    numeric(df, ["src_port", "dst_port", "packet_length", "icmp_type", "arp_operation"])
    flags = df.get("tcp_flags", pd.Series(index=df.index, dtype="object"))
    for name in ["syn", "ack", "rst", "fin"]:
        df[f"tcp_{name}"] = flags.map(lambda x, n=name.upper(): flag_has(x, n)).astype("int8")
    keep = ["protocol", "src_port", "dst_port", "packet_length", "tcp_syn", "tcp_ack", "tcp_rst", "tcp_fin", "icmp_type", "arp_operation"]
    return df[keep]


def build_flow(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for col in ["protocol", "src_port", "dst_port", "packet_count", "byte_count", "packet_rate", "byte_rate", "duration_sec"]:
        if col not in df:
            df[col] = "" if col == "protocol" else 0
    df["protocol"] = df["protocol"].map(protocol_name)
    numeric(df, ["src_port", "dst_port", "packet_count", "byte_count", "packet_rate", "byte_rate", "duration_sec"])
    df["avg_packet_size"] = (df["byte_count"] / df["packet_count"].clip(lower=1)).fillna(0)
    # FlowStats does not contain TCP flags. These remain zero until packet-window
    # aggregation is joined explicitly in a later version.
    for col in ["syn_count", "ack_count", "rst_count", "fin_count", "unique_dst_ports", "failed_connection_count"]:
        df[col] = 0
    df["syn_ack_ratio"] = 0.0
    df["rst_ratio"] = 0.0
    df["tcp_fraction"] = (df["protocol"] == "tcp").astype(float)
    df["udp_fraction"] = (df["protocol"] == "udp").astype(float)
    df["icmp_fraction"] = (df["protocol"] == "icmp").astype(float)
    keep = ["protocol", "src_port", "dst_port", "packet_count", "byte_count", "packet_rate", "byte_rate", "duration_sec", "avg_packet_size", "syn_count", "ack_count", "rst_count", "fin_count", "syn_ack_ratio", "rst_ratio", "unique_dst_ports", "failed_connection_count", "tcp_fraction", "udp_fraction", "icmp_fraction"]
    return df[keep]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--level", choices=["packet", "flow"], required=True)
    p.add_argument("--input-dir", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    manifest = read_manifest()
    frames = []
    for path in sorted(args.input_dir.glob("*.csv")):
        run_id = path.stem
        if run_id not in manifest:
            raise SystemExit(f"{path.name}: run_id {run_id!r} is not in run_manifest.csv")
        run = manifest[run_id]
        if run.get("status") != "completed":
            raise SystemExit(f"{run_id}: status must be completed before dataset build")
        label = run.get("label") or "Normal"
        if label not in {"Normal", "Malicious_POST", "Port_Scan", "SYN_Flood"}:
            raise SystemExit(f"{run_id}: invalid label {label!r}")
        df = pd.read_csv(path)
        out = build_packet(df) if args.level == "packet" else build_flow(df)
        out.insert(0, "observation_id", [f"{run_id}_{i:08d}" for i in range(len(out))])
        out.insert(0, "run_id", run_id)
        out["label"] = label
        out["label_status"] = "matched"
        frames.append(out)
    if not frames:
        raise SystemExit(f"no CSV files found in {args.input_dir}")
    result = pd.concat(frames, ignore_index=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(args.output, index=False)
    print(f"wrote {len(result)} rows from {result['run_id'].nunique()} runs to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
