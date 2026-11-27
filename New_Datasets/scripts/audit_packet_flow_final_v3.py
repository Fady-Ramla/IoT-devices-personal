#!/usr/bin/env python3
"""Read-only audit for the 160-run Packet/Flow final collection.

Checks the fixed collection generations (191..353), keeps failed runs out,
validates the predeclared run split, and validates paired raw packet/flow CSVs.
Does not edit files or rewrite the manifest.
"""
from __future__ import annotations
import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from urllib.request import urlopen

EXPECTED_FAILED = {
    200: "571f26c1-e308-400a-82f3-cb60fc493fd8",
    339: "6dd4cb11-20c6-4535-bde2-a5f72da39cc5",
    341: "f0f5b15c-beed-490f-a91f-cca60b90258c",
}
EXPECTED_LABELS = ("Normal", "Malicious_POST", "Port_Scan", "SYN_Flood")
EXPECTED_SPLITS = ("train", "validation", "final_test")


def generation_to_plan(g: int) -> int | None:
    if 191 <= g <= 199:
        return g - 190                 # initial plan rows 1..9
    if 201 <= g <= 338:
        return g - 191                 # resumed original rows 10..147
    if g == 340:
        return 148                     # replacement SYN039R
    if g == 342:
        return 149                     # replacement SYN033R
    if 343 <= g <= 353:
        return g - 193                 # original rows 150..160
    return None


def read_csv(path: Path):
    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "run_id" not in reader.fieldnames or "observation_id" not in reader.fieldnames:
            raise ValueError(f"Missing required run/observation ID columns: {path}")
        rows = list(reader)
        header = reader.fieldnames
    return header, rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = args.project_root.resolve()

    manifest_path = root / "New_Datasets/experiments/run_manifest.csv"
    plan_path = root / "New_Datasets/scripts/collection_plan_packet_flow_final_v3_160runs.csv"
    latch_path = root / "New_Datasets/experiments/run_manifest.csv.in_flight.json"
    if not manifest_path.is_file() or not plan_path.is_file():
        raise SystemExit("STOP: expected manifest or original plan file is missing.")
    if latch_path.exists():
        raise SystemExit(f"STOP: active in-flight latch exists: {latch_path}")

    with manifest_path.open("r", newline="", encoding="utf-8") as f:
        manifest = list(csv.DictReader(f))
    with plan_path.open("r", newline="", encoding="utf-8") as f:
        plan_rows = list(csv.DictReader(f))
    if len(plan_rows) != 160:
        raise SystemExit(f"STOP: original plan has {len(plan_rows)} rows, expected 160.")
    plan = {int(r["plan_index"]): r for r in plan_rows}
    if len(plan) != 160:
        raise SystemExit("STOP: original plan indexes are not unique.")

    cohort = []
    for r in manifest:
        try:
            g = int(r.get("generation") or 0)
        except ValueError:
            continue
        if 191 <= g <= 353:
            cohort.append((g, r))
    if len(cohort) != 163:
        raise SystemExit(f"STOP: found {len(cohort)} campaign manifest rows for generations 191..353; expected 163.")
    by_generation = {}
    for g, r in cohort:
        if g in by_generation:
            raise SystemExit(f"STOP: duplicate manifest generation {g}.")
        by_generation[g] = r
    if set(by_generation) != set(range(191, 354)):
        missing = sorted(set(range(191, 354)) - set(by_generation))
        raise SystemExit(f"STOP: missing campaign generations: {missing}")

    for g, expected_id in EXPECTED_FAILED.items():
        r = by_generation[g]
        if r.get("run_id") != expected_id or r.get("status") != "failed":
            raise SystemExit(f"STOP: expected generation {g} to be failed run {expected_id}; got {r}")
    completed = [(g, r) for g, r in cohort if r.get("status") == "completed"]
    failed = [(g, r) for g, r in cohort if r.get("status") == "failed"]
    other = [(g, r) for g, r in cohort if r.get("status") not in ("completed", "failed")]
    if len(completed) != 160 or len(failed) != 3 or other:
        raise SystemExit(f"STOP: campaign statuses do not reconcile: completed={len(completed)}, failed={len(failed)}, other={[(g,r.get('status')) for g,r in other]}")
    if len({r.get("run_id") for _, r in cohort}) != 163:
        raise SystemExit("STOP: duplicate run IDs in campaign manifest.")

    split_by_label = {s: Counter() for s in EXPECTED_SPLITS}
    label_counts = Counter()
    profile_ids = set()
    successful_runs = set()
    for g, r in completed:
        pi = generation_to_plan(g)
        if pi is None or pi not in plan:
            raise SystemExit(f"STOP: no planned split mapping for completed generation {g}.")
        planned = plan[pi]
        label = r.get("label")
        if label != planned.get("expected_label"):
            raise SystemExit(f"STOP: generation {g} label {label} differs from planned {planned.get('expected_label')} (row {pi}).")
        split = planned.get("planned_split")
        if split not in split_by_label:
            raise SystemExit(f"STOP: invalid planned split {split!r} for row {pi}.")
        split_by_label[split][label] += 1
        label_counts[label] += 1
        profile = planned["profile_id"]
        if g == 340:
            profile = "SYN039R"
        elif g == 342:
            profile = "SYN033R"
        if profile in profile_ids:
            raise SystemExit(f"STOP: duplicated successful profile ID {profile}.")
        profile_ids.add(profile)
        successful_runs.add(r["run_id"])

    if label_counts != Counter({label: 40 for label in EXPECTED_LABELS}):
        raise SystemExit(f"STOP: completed label balance is {dict(label_counts)}.")
    for label in EXPECTED_LABELS:
        counts = {split: split_by_label[split][label] for split in EXPECTED_SPLITS}
        if counts != {"train": 16, "validation": 4, "final_test": 20}:
            raise SystemExit(f"STOP: split counts for {label} are {counts}.")
    if len(profile_ids) != 160:
        raise SystemExit(f"STOP: expected 160 unique successful profiles, got {len(profile_ids)}.")

    seen_obs = {"packet": set(), "flow": set()}
    seen_exact = {"packet": set(), "flow": set()}
    total_rows = Counter()
    for _, r in completed:
        rid = r["run_id"]
        for kind in ("packet", "flow"):
            p = root / "New_Datasets/raw" / kind / f"{rid}.csv"
            if not p.is_file() or p.stat().st_size == 0:
                raise SystemExit(f"STOP: missing/empty {kind} CSV for completed run {rid}: {p}")
            header, rows = read_csv(p)
            if not rows:
                raise SystemExit(f"STOP: {kind} CSV has header only for completed run {rid}.")
            for row in rows:
                if None in row or any(value is None for value in row.values()):
                    raise SystemExit(f"STOP: malformed CSV row in {p}")
                if row.get("run_id") != rid:
                    raise SystemExit(f"STOP: row run_id mismatch in {p}")
                obs = row.get("observation_id")
                if not obs or obs in seen_obs[kind]:
                    raise SystemExit(f"STOP: missing/duplicate {kind} observation_id {obs!r} in {p}")
                seen_obs[kind].add(obs)
                signature = tuple(row.get(k, "") for k in header)
                if signature in seen_exact[kind]:
                    raise SystemExit(f"STOP: exact duplicate {kind} row found in {p}")
                seen_exact[kind].add(signature)
            total_rows[kind] += len(rows)

    print("AUDIT PASS (read-only)")
    print("Campaign rows: 163 total; 160 completed; 3 failed and excluded.")
    print("Completed runs per class:", dict(label_counts))
    for label in EXPECTED_LABELS:
        print(label + " split counts:", {s: split_by_label[s][label] for s in EXPECTED_SPLITS})
    print("Unique successful profile IDs:", len(profile_ids))
    print("Packet rows:", total_rows["packet"], "| unique observation IDs:", len(seen_obs["packet"]), "| exact duplicates: 0")
    print("Flow rows:", total_rows["flow"], "| unique observation IDs:", len(seen_obs["flow"]), "| exact duplicates: 0")
    try:
        with urlopen("http://127.0.0.1:8080/dataset/run/status", timeout=2) as response:
            status = json.loads(response.read().decode("utf-8"))
        print("Collector status:", status.get("state"), "generation:", status.get("generation"), "durable:", status.get("durable"), "error:", status.get("error"))
    except Exception as exc:
        print("Collector status unavailable (files were still audited):", type(exc).__name__, str(exc))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"AUDIT STOP: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise
