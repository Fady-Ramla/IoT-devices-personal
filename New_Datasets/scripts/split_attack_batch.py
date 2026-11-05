#!/usr/bin/env python3
"""Split cumulative telemetry into run-centric raw files from attack metadata."""
from __future__ import annotations

import argparse
import csv
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "experiments" / "run_manifest.csv"
LABELS = {"normal": "Normal", "syn_flood": "SYN_Flood", "port_scan": "Port_Scan", "malicious_post": "Malicious_POST"}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--packet-csv", type=Path, required=True)
    p.add_argument("--flow-csv", type=Path, required=True)
    p.add_argument("--metadata-csv", type=Path, required=True)
    p.add_argument("--grace-sec", type=float, default=5.0)
    args = p.parse_args()

    packets = pd.read_csv(args.packet_csv)
    flows = pd.read_csv(args.flow_csv)
    packets["timestamp"] = pd.to_numeric(packets["timestamp"], errors="coerce")
    flows["timestamp"] = pd.to_numeric(flows["timestamp"], errors="coerce")

    with args.metadata_csv.open(newline="", encoding="utf-8") as f:
        metadata = list(csv.DictReader(f))
    existing = []
    if MANIFEST.exists():
        with MANIFEST.open(newline="", encoding="utf-8") as f:
            existing = list(csv.DictReader(f))
    existing_ids = {r.get("run_id") for r in existing}

    packet_dir = ROOT / "raw" / "packet"
    flow_dir = ROOT / "raw" / "flow"
    packet_dir.mkdir(parents=True, exist_ok=True)
    flow_dir.mkdir(parents=True, exist_ok=True)
    new_rows = []
    imported = 0
    for row in metadata:
        run_id = row.get("run_id", "").strip()
        attack_type = row.get("attack_type", "").strip().lower()
        if not run_id or attack_type not in LABELS:
            continue
        try:
            start = float(row["start_timestamp"])
            end = float(row["end_timestamp"])
        except (KeyError, TypeError, ValueError):
            continue
        mask_p = (packets["timestamp"] >= start) & (packets["timestamp"] <= end + args.grace_sec)
        mask_f = (flows["timestamp"] >= start) & (flows["timestamp"] <= end + args.grace_sec)
        packet_part = packets.loc[mask_p].copy()
        flow_part = flows.loc[mask_f].copy()
        if packet_part.empty and flow_part.empty:
            continue
        packet_path = packet_dir / f"{run_id}.csv"
        flow_path = flow_dir / f"{run_id}.csv"
        if not packet_part.empty:
            packet_part.to_csv(packet_path, index=False)
        if not flow_part.empty:
            flow_part.to_csv(flow_path, index=False)
        if run_id not in existing_ids:
            dst_port = row.get("dst_port", "")
            service = {"22": "ssh", "443": "https", "5000": "http_api"}.get(dst_port, "multi_port_probe" if dst_port == "*" else "unknown")
            new_rows.append({
                "run_id": run_id,
                "run_type": "normal" if attack_type == "normal" else "attack",
                "label": LABELS[attack_type],
                "attack_type": "" if attack_type == "normal" else LABELS[attack_type],
                "experiment_category": "normal_baseline" if attack_type == "normal" else "allowed_attack_delivery",
                "start_time": row.get("start_timestamp", ""),
                "end_time": row.get("end_timestamp", ""),
                "attacker_host": "",
                "attacker_ip": row.get("src_ip", ""),
                "target_host": "",
                "target_ip": row.get("dst_ip", ""),
                "service_name": service,
                "protocol": row.get("protocol", ""),
                "dst_port": dst_port,
                "rate_value": "imported_from_attack_manager",
                "duration_sec": f"{end - start:.6f}",
                "status": "completed",
                "notes": "Imported and split from cumulative telemetry by attack_metadata timestamp window",
            })
            existing_ids.add(run_id)
        imported += 1

    fields = ["run_id", "run_type", "label", "attack_type", "experiment_category", "start_time", "end_time", "attacker_host", "attacker_ip", "target_host", "target_ip", "service_name", "protocol", "dst_port", "rate_value", "duration_sec", "status", "notes"]
    with MANIFEST.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(existing)
        writer.writerows(new_rows)
    print(f"imported {imported} runs; added {len(new_rows)} manifest rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
