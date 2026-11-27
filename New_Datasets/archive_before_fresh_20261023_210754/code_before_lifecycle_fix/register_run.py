#!/usr/bin/env python3
"""Append one validated Normal/Attack run to experiments/run_manifest.csv."""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "experiments" / "run_manifest.csv"
FIELDS = [
    "run_id", "run_type", "label", "attack_type", "experiment_category",
    "start_time", "end_time", "attacker_host", "attacker_ip", "target_host",
    "target_ip", "service_name", "protocol", "dst_port", "rate_value",
    "duration_sec", "status", "notes",
]
LABELS = {"", "Normal", "Malicious_POST", "Port_Scan", "SYN_Flood"}
RUN_TYPES = {"normal", "attack"}
STATUSES = {"planned", "running", "completed", "failed"}
CATEGORIES = {
    "normal_baseline", "allowed_attack_delivery", "firewall_blocked_attack_attempt",
    "service_unavailable_control", "failed_experiment", "",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--run-id", required=True)
    p.add_argument("--run-type", required=True, choices=sorted(RUN_TYPES))
    p.add_argument("--label", default="")
    p.add_argument("--attack-type", default="")
    p.add_argument("--experiment-category", default="")
    p.add_argument("--start-time", required=True)
    p.add_argument("--end-time", required=True)
    p.add_argument("--attacker-host", default="")
    p.add_argument("--attacker-ip", default="")
    p.add_argument("--target-host", default="")
    p.add_argument("--target-ip", default="")
    p.add_argument("--service-name", default="")
    p.add_argument("--protocol", default="")
    p.add_argument("--dst-port", default="")
    p.add_argument("--rate-value", default="")
    p.add_argument("--duration-sec", default="")
    p.add_argument("--status", required=True, choices=sorted(STATUSES))
    p.add_argument("--notes", default="")
    return p.parse_args()


def main() -> int:
    a = parse_args()
    if a.label not in LABELS:
        raise SystemExit(f"invalid label: {a.label}")
    if a.experiment_category not in CATEGORIES:
        raise SystemExit(f"invalid experiment category: {a.experiment_category}")
    if a.run_type == "normal" and (a.label or a.attack_type):
        raise SystemExit("normal runs cannot have attack label or attack_type")
    if a.run_type == "attack" and not a.label:
        raise SystemExit("attack runs require --label")

    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    if MANIFEST.exists():
        with MANIFEST.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
    if any(r.get("run_id") == a.run_id for r in rows):
        raise SystemExit(f"duplicate run_id: {a.run_id}")

    row = {field: getattr(a, field) for field in FIELDS}
    with MANIFEST.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
        writer.writerow(row)
    print(f"registered run_id={a.run_id} in {MANIFEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
