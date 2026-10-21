#!/usr/bin/env bash
set -Eeuo pipefail

# Generate a deterministic, balanced experiment PLAN only.
# This script does NOT start Mininet, Ryu, or any attack.
# Usage from the project root:
#   bash person2_generate_collection_plan.sh [20|30]

RUNS_PER_CLASS="${1:-20}"
if [[ "$RUNS_PER_CLASS" != "20" && "$RUNS_PER_CLASS" != "30" ]]; then
  echo "Usage: bash person2_generate_collection_plan.sh [20|30]" >&2
  echo "Choose 20 or 30 independent planned runs per class." >&2
  exit 2
fi

ROOT="${SECUREIOT_PROJECT_ROOT:-$PWD}"
if [[ ! -f "$ROOT/mininet/Real_network_topology.py" || ! -f "$ROOT/mininet/attack_manager.py" ]]; then
  echo "Run this from the IoT-devices project root, or set SECUREIOT_PROJECT_ROOT." >&2
  exit 2
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$ROOT/New_Datasets/plans/person2_${RUNS_PER_CLASS}_per_class_${STAMP}"
mkdir -p "$OUT_DIR"

python3 - "$OUT_DIR" "$RUNS_PER_CLASS" <<'PY'
import csv
import random
import sys
from collections import Counter
from pathlib import Path

out_dir = Path(sys.argv[1])
runs_per_class = int(sys.argv[2])
seed = 20261019
rng = random.Random(seed)

# Hosts and services are taken from the submitted Real_network_topology.py.
# No arbitrary IP/hostname target is accepted in this plan.
attackers = ["h5", "h6", "h7", "h9"]
service_targets = [
    ("h2", "http_api", "5000"),
    ("h3", "https", "443"),
    ("h4", "ssh", "22"),
    ("h8", "http_api_backup", "5000"),
    ("h8", "https_backup", "443"),
    ("h11", "load_balancer", "5000"),
    ("h11", "load_balancer", "443"),
]

port_ranges = {
    "22": ["20-24", "18-26", "1-32", "21-30", "20-30"],
    "443": ["440-446", "430-450", "400-480", "442-448", "420-460"],
    "5000": ["4996-5004", "4980-5020", "4900-5100", "4990-5010", "4800-5200"],
}
scan_delays_ms = [25, 50, 100, 200, 400]
syn_rates_pps = [10, 25, 50, 100, 200]
syn_durations_sec = [5, 8, 10, 15, 20]
normal_clients = attackers
normal_services = [
    ("http_api", "h2", "5000"),
    ("http_api", "h8", "5000"),
    ("https", "h3", "443"),
    ("https", "h8", "443"),
    ("load_balancer", "h11", "5000"),
]
normal_durations_sec = [10, 15, 20, 30, 45]
pause_after_sec = 10

# Exact pilot configurations already executed; never count them as new runs.
pilot_commands = {
    "attack h5 syn_flood h2 5000 10 5",
    "normal h5 http_api h2 5",
    "attack h5 port_scan h2 4998-5002 400",
}


def balanced_pick(candidates, n, balance_fields):
    """Pick unique configurations while round-balancing selected dimensions."""
    if len(candidates) < n:
        raise RuntimeError(f"only {len(candidates)} candidates available for {n} runs")
    rng.shuffle(candidates)
    counters = {field: Counter() for field in balance_fields}
    chosen = []
    remaining = list(candidates)
    while len(chosen) < n:
        # The randomized initial order breaks ties reproducibly via the seed.
        best_i = min(
            range(len(remaining)),
            key=lambda i: tuple(
                counters[field][remaining[i][field]] for field in balance_fields
            ),
        )
        item = remaining.pop(best_i)
        chosen.append(item)
        for field in balance_fields:
            counters[field][item[field]] += 1
    return chosen


planned = []

# Port scans: vary source host, service/target, range, and scan delay.
scan_candidates = []
for attacker in attackers:
    for target, service, dst_port in service_targets:
        for port_range in port_ranges[dst_port]:
            for delay_ms in scan_delays_ms:
                cmd = f"attack {attacker} port_scan {target} {port_range} {delay_ms}"
                scan_candidates.append({
                    "label": "Port_Scan",
                    "attack_type": "port_scan",
                    "attacker_host": attacker,
                    "target_host": target,
                    "service_name": service,
                    "dst_port": dst_port,
                    "rate_value": f"scan_delay_ms={delay_ms}",
                    "duration_sec": "variable_from_range_and_delay",
                    "port_range": port_range,
                    "scan_delay_ms": delay_ms,
                    "syn_rate_pps": "",
                    "normal_interval_sec": "",
                    "command": cmd,
                })
scan_candidates = [row for row in scan_candidates if row["command"] not in pilot_commands]
scan_chosen = balanced_pick(
    scan_candidates, runs_per_class,
    ["attacker_host", "target_host", "service_name", "port_range", "scan_delay_ms"],
)
for i, row in enumerate(scan_chosen, 1):
    row["planned_run_key"] = f"plan_portscan_{i:03d}"
    row["pause_after_sec"] = pause_after_sec
    planned.append(row)

# SYN runs: rate-limited command builder; actual observed rate may vary from requested rate.
syn_candidates = []
for attacker in attackers:
    for target, service, dst_port in service_targets:
        for rate in syn_rates_pps:
            for duration in syn_durations_sec:
                cmd = f"attack {attacker} syn_flood {target} {dst_port} {rate} {duration}"
                syn_candidates.append({
                    "label": "SYN_Flood",
                    "attack_type": "syn_flood",
                    "attacker_host": attacker,
                    "target_host": target,
                    "service_name": service,
                    "dst_port": dst_port,
                    "rate_value": rate,
                    "duration_sec": duration,
                    "port_range": "",
                    "scan_delay_ms": "",
                    "syn_rate_pps": rate,
                    "normal_interval_sec": "",
                    "command": cmd,
                })
syn_candidates = [row for row in syn_candidates if row["command"] not in pilot_commands]
syn_chosen = balanced_pick(
    syn_candidates, runs_per_class,
    ["attacker_host", "target_host", "service_name", "syn_rate_pps", "duration_sec"],
)
for i, row in enumerate(syn_chosen, 1):
    row["planned_run_key"] = f"plan_synflood_{i:03d}"
    row["pause_after_sec"] = pause_after_sec
    planned.append(row)

# Normal traffic: vary source, valid service/target pair and duration.
# Current topology supports one request approximately every second; it does not
# yet accept a per-run normal request-rate parameter, so this plan records that.
normal_candidates = []
for client in normal_clients:
    for service, target, dst_port in normal_services:
        for duration in normal_durations_sec:
            cmd = f"normal {client} {service} {target} {duration}"
            normal_candidates.append({
                "label": "Normal",
                "attack_type": "",
                "attacker_host": client,
                "target_host": target,
                "service_name": service,
                "dst_port": dst_port,
                "rate_value": "approximately 1 request/sec (current generator)",
                "duration_sec": duration,
                "port_range": "",
                "scan_delay_ms": "",
                "syn_rate_pps": "",
                "normal_interval_sec": 1,
                "command": cmd,
            })
normal_candidates = [row for row in normal_candidates if row["command"] not in pilot_commands]
normal_chosen = balanced_pick(
    normal_candidates, runs_per_class,
    ["attacker_host", "target_host", "service_name", "duration_sec"],
)
for i, row in enumerate(normal_chosen, 1):
    row["planned_run_key"] = f"plan_normal_{i:03d}"
    row["pause_after_sec"] = pause_after_sec
    planned.append(row)

# Make the execution plan order reproducibly interleaved by class to reduce
# long same-class blocks. This balances runs, not raw row counts.
class_order = {"Port_Scan": 0, "SYN_Flood": 1, "Normal": 2}
within = Counter()
for row in planned:
    within[row["label"]] += 1
rng.shuffle(planned)
planned.sort(key=lambda r: (int(r["planned_run_key"].rsplit("_", 1)[1]), class_order[r["label"]]))

plan_path = out_dir / "collection_plan.csv"
matrix_path = out_dir / "collection_matrix.csv"
failed_path = out_dir / "failed_runs_report.csv"
fields = [
    "planned_run_key", "label", "attack_type", "attacker_host", "target_host",
    "service_name", "dst_port", "rate_value", "duration_sec", "port_range",
    "scan_delay_ms", "syn_rate_pps", "normal_interval_sec", "command",
    "pause_after_sec",
]

commands = [row["command"] for row in planned]
if len(commands) != len(set(commands)):
    raise RuntimeError("internal error: duplicate commands were generated")
if len({row["planned_run_key"] for row in planned}) != len(planned):
    raise RuntimeError("internal error: duplicate planned_run_key was generated")

with plan_path.open("x", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["command", "pause_after_sec"])
    writer.writeheader()
    writer.writerows({"command": row["command"], "pause_after_sec": pause_after_sec} for row in planned)

with matrix_path.open("x", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(planned)

failure_fields = [
    "run_id", "generation", "run_type", "label", "attack_type", "status",
    "start_time", "end_time", "attacker_host", "attacker_ip", "target_host",
    "target_ip", "service_name", "protocol", "src_port", "dst_port",
    "rate_value", "duration_sec", "notes",
]
with failed_path.open("x", newline="", encoding="utf-8") as f:
    csv.writer(f).writerow(failure_fields)  # empty template, filled after collection

readme = out_dir / "PLAN_ONLY_README.txt"
readme.write_text(
    "PLAN ONLY — this script did not start Mininet, Ryu, or any traffic.\n"
    f"Seed: {seed}\nRuns per class: {runs_per_class}\nTotal planned runs: {len(planned)}\n"
    f"Excluded already completed pilot commands: {len(pilot_commands)}\n\n"
    "This plan is for the current run_id-enabled capture code. It contains unique commands and excludes the exact pilot configurations.\n"
    "Start Ryu from a NEW, empty raw-data directory with the current packet/flow CSV schema; keep the six-switch topology connected.\n"
    "SYN PPS and scan completion are bounded requests/caps; actual timing/rates may differ. Port scans have a 20-second maximum wall-clock cap.\n"
    "Normal traffic is approximately one HTTP(S) request per second; this plan varies client/service/target/duration, not its request rate.\n"
    "The plan balances run configurations, not row counts. Do not oversample or edit raw CSVs; Person 3 should review run-level distribution before any split.\n"
    "After collection, run build_failed_runs_report.py to fill failed_runs_report.csv from failed entries in the manifest.\n",
    encoding="utf-8",
)

print(f"Plan generated (not executed): {out_dir}")
print(f"Runs per class: {runs_per_class}; total: {len(planned)}")
print(f"Plan: {plan_path}")
print(f"Matrix: {matrix_path}")
print(f"Failed-run report template: {failed_path}")
print(f"Notes: {readme}")
print("Duplicate command check: passed")
PY
