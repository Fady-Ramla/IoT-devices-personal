#!/usr/bin/env python3
"""Build final offline Packet and Flow split CSVs from the audited V3 collection.

Read-only inputs; writes a new package directory only. Failed captures are excluded.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import os
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path
from urllib.request import urlopen

EXPECTED_FAILED = {
    200: "571f26c1-e308-400a-82f3-cb60fc493fd8",
    339: "6dd4cb11-20c6-4535-bde2-a5f72da39cc5",
    341: "f0f5b15c-beed-490f-a91f-cca60b90258c",
}
LABELS = ("Normal", "Malicious_POST", "Port_Scan", "SYN_Flood")
SPLITS = ("train", "validation", "final_test")
PROTO = {"1": "icmp", "6": "tcp", "17": "udp", "41": "ipv6", "58": "icmpv6"}


def generation_to_plan(g: int) -> int | None:
    if 191 <= g <= 199:
        return g - 190
    if 201 <= g <= 338:
        return g - 191
    if g == 340:
        return 148
    if g == 342:
        return 149
    if 343 <= g <= 353:
        return g - 193
    return None


def protocol_name(value: str) -> str:
    value = (value or "").strip()
    try:
        key = str(int(float(value)))
    except (ValueError, TypeError):
        return value.lower() or "unknown"
    return PROTO.get(key, "ip_proto_" + key)


def numeric(value: str, *, integer: bool = False) -> str:
    value = (value or "").strip()
    if not value:
        return "0"
    x = float(value)
    if not (x == x and abs(x) != float("inf")):
        raise ValueError(f"non-finite numeric value: {value!r}")
    if integer:
        return str(int(x))
    return format(x, ".12g")


def load_records(path: Path):
    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError(f"CSV has no header: {path}")
        if "run_id" not in reader.fieldnames or "observation_id" not in reader.fieldnames:
            raise ValueError(f"CSV lacks run_id/observation_id columns: {path}")
        return reader.fieldnames, list(reader)


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def packet_values(row: dict[str, str], features: list[str]) -> dict[str, str]:
    flags = int(float(row.get("tcp_flags") or 0))
    derived = {
        "protocol": protocol_name(row.get("protocol", "")),
        "src_port": numeric(row.get("src_port", "")),
        "dst_port": numeric(row.get("dst_port", "")),
        "packet_length": numeric(row.get("packet_length", ""), integer=True),
        "tcp_syn": str(1 if flags & 0x02 else 0),
        "tcp_ack": str(1 if flags & 0x10 else 0),
        "tcp_rst": str(1 if flags & 0x04 else 0),
        "tcp_fin": str(1 if flags & 0x01 else 0),
        "icmp_type": numeric(row.get("icmp_type", ""), integer=True),
        "arp_operation": numeric(row.get("arp_operation", ""), integer=True),
    }
    missing = [f for f in features if f not in derived]
    if missing:
        raise ValueError(f"Unsupported packet feature(s) in model config: {missing}")
    return {f: derived[f] for f in features}


def flow_values(row: dict[str, str], features: list[str]) -> dict[str, str]:
    derived = dict(row)
    derived["protocol"] = protocol_name(row.get("protocol", ""))
    missing = [f for f in features if f not in derived]
    if missing:
        raise ValueError(f"Flow raw data missing configured feature(s): {missing}")
    result = {}
    integer_fields = {"src_port", "dst_port", "packet_count", "byte_count", "syn_count",
                      "ack_count", "rst_count", "fin_count", "unique_dst_ports",
                      "failed_connection_count"}
    for f in features:
        if f == "protocol":
            result[f] = derived[f]
        else:
            result[f] = numeric(derived[f], integer=(f in integer_fields))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path,
                        default=Path("New_Datasets/AI_OFFLINE_LEARNING_FINAL_V3_20261025"))
    args = parser.parse_args()
    root = args.project_root.resolve()
    output = args.output if args.output.is_absolute() else root / args.output
    output = output.resolve()
    if output.exists():
        raise SystemExit(f"STOP: output already exists; refusing to overwrite: {output}")

    base = root / "New_Datasets"
    manifest_path = base / "experiments/run_manifest.csv"
    plan_path = base / "scripts/collection_plan_packet_flow_final_v3_160runs.csv"
    config_path = base / "AI_OFFLINE_LEARNING_V2_FINAL/config/model_features.json"
    latch_path = base / "experiments/run_manifest.csv.in_flight.json"
    for path in (manifest_path, plan_path, config_path):
        if not path.is_file():
            raise SystemExit(f"STOP: required input is missing: {path}")
    if latch_path.exists():
        raise SystemExit(f"STOP: unresolved in-flight latch exists: {latch_path}")

    config = json.loads(config_path.read_text(encoding="utf-8"))
    packet_features = list(config["packet_features"])
    flow_features = list(config["flow_features"])
    with manifest_path.open("r", newline="", encoding="utf-8") as f:
        manifest = list(csv.DictReader(f))
    with plan_path.open("r", newline="", encoding="utf-8") as f:
        original_plan = list(csv.DictReader(f))
    plan = {int(r["plan_index"]): r for r in original_plan}
    if len(original_plan) != 160 or len(plan) != 160:
        raise SystemExit("STOP: original run plan must contain 160 unique plan indices.")

    cohort = []
    for row in manifest:
        try:
            generation = int(row.get("generation") or 0)
        except ValueError:
            continue
        if 191 <= generation <= 353:
            cohort.append((generation, row))
    by_generation = {g: r for g, r in cohort}
    if len(cohort) != 163 or len(by_generation) != 163 or set(by_generation) != set(range(191, 354)):
        raise SystemExit("STOP: campaign generations 191..353 do not reconcile to 163 unique records.")
    for g, rid in EXPECTED_FAILED.items():
        r = by_generation[g]
        if r.get("run_id") != rid or r.get("status") != "failed":
            raise SystemExit(f"STOP: failed record at generation {g} differs from expected; found {r}")
    completed = [(g, r) for g, r in cohort if r.get("status") == "completed"]
    failed = [(g, r) for g, r in cohort if r.get("status") == "failed"]
    if len(completed) != 160 or len(failed) != 3:
        raise SystemExit(f"STOP: expected 160 completed/3 failed; found {len(completed)}/{len(failed)}")

    successful = []
    split_counts = {s: Counter() for s in SPLITS}
    profile_ids = set()
    run_to_assignment = {}
    for g, r in completed:
        pi = generation_to_plan(g)
        if pi not in plan:
            raise SystemExit(f"STOP: no planned assignment for completed generation {g}")
        p = plan[pi]
        if r.get("label") != p.get("expected_label"):
            raise SystemExit(f"STOP: label mismatch at generation {g}: {r.get('label')} vs {p.get('expected_label')}")
        split = p["planned_split"]
        if split not in SPLITS:
            raise SystemExit(f"STOP: invalid split {split!r} at plan row {pi}")
        profile = p["profile_id"]
        if g == 340:
            profile = "SYN039R"
        elif g == 342:
            profile = "SYN033R"
        if profile in profile_ids:
            raise SystemExit(f"STOP: duplicate successful profile {profile}")
        profile_ids.add(profile)
        split_counts[split][r["label"]] += 1
        run_to_assignment[r["run_id"]] = {"generation": g, "plan_index": pi,
                                           "profile_id": profile, "label": r["label"],
                                           "split": split}
        successful.append((g, r, pi, p, profile, split))
    if len(profile_ids) != 160:
        raise SystemExit("STOP: successful run profile IDs are not unique.")
    for label in LABELS:
        expected = {"train": 16, "validation": 4, "final_test": 20}
        got = {s: split_counts[s][label] for s in SPLITS}
        if got != expected:
            raise SystemExit(f"STOP: planned split counts for {label} are {got}, expected {expected}")

    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=str(output.parent)))
    writers = {}
    handles = []
    row_counts = {"packet": Counter(), "flow": Counter()}
    seen_obs = {"packet": set(), "flow": set()}
    exact_rows = {"packet": set(), "flow": set()}
    try:
        for level in ("packet", "flow"):
            features = packet_features if level == "packet" else flow_features
            directory = staging / f"{level}_splits"
            directory.mkdir(parents=True, exist_ok=True)
            for split in SPLITS:
                file_split = "test" if split == "final_test" else split
                path = directory / f"{file_split}.csv"
                handle = path.open("w", newline="", encoding="utf-8")
                handles.append(handle)
                writer = csv.DictWriter(handle, fieldnames=["run_id", "observation_id", *features, "label", "label_status"])
                writer.writeheader()
                writers[(level, split)] = writer

        split_manifest_path = staging / "run_split_manifest.csv"
        with split_manifest_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["generation", "run_id", "label", "plan_index", "profile_id", "planned_split"])
            writer.writeheader()
            for g, r, pi, p, profile, split in sorted(successful):
                writer.writerow({"generation": g, "run_id": r["run_id"], "label": r["label"],
                                 "plan_index": pi, "profile_id": profile, "planned_split": split})

        excluded_path = staging / "excluded_failed_runs.csv"
        with excluded_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["generation", "run_id", "label", "status", "reason"])
            writer.writeheader()
            for g, r in sorted(failed):
                writer.writerow({"generation": g, "run_id": r["run_id"], "label": r.get("label"),
                                 "status": r.get("status"), "reason": "manifest status is failed; excluded from all splits"})

        for g, r, pi, p, profile, split in sorted(successful):
            rid, label = r["run_id"], r["label"]
            for level in ("packet", "flow"):
                source = base / "raw" / level / f"{rid}.csv"
                if not source.is_file() or source.stat().st_size == 0:
                    raise ValueError(f"Missing/empty {level} raw CSV for completed run {rid}")
                header, rows = load_records(source)
                if not rows:
                    raise ValueError(f"Header-only {level} raw CSV for completed run {rid}")
                features = packet_features if level == "packet" else flow_features
                converter = packet_values if level == "packet" else flow_values
                writer = writers[(level, split)]
                for raw in rows:
                    if None in raw or any(v is None for v in raw.values()):
                        raise ValueError(f"Malformed CSV row in {source}")
                    if raw.get("run_id") != rid:
                        raise ValueError(f"run_id mismatch in {source}")
                    obs = raw.get("observation_id", "")
                    if not obs or obs in seen_obs[level]:
                        raise ValueError(f"Missing/duplicate {level} observation_id {obs!r} in {source}")
                    seen_obs[level].add(obs)
                    features_row = converter(raw, features)
                    output_row = {"run_id": rid, "observation_id": obs, **features_row,
                                  "label": label, "label_status": "matched"}
                    signature = tuple(output_row[k] for k in output_row)
                    if signature in exact_rows[level]:
                        raise ValueError(f"Exact duplicate transformed {level} row: {source}")
                    exact_rows[level].add(signature)
                    writer.writerow(output_row)
                    row_counts[level][split] += 1

        for handle in handles:
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
        handles.clear()

        (staging / "config").mkdir()
        shutil.copy2(config_path, staging / "config/model_features.json")
        report = {
            "campaign_generations": "191-353",
            "completed_runs": len(completed),
            "failed_runs_excluded": len(failed),
            "classes": list(LABELS),
            "runs_per_class": {label: 40 for label in LABELS},
            "run_split_counts_per_class": {label: {s: split_counts[s][label] for s in SPLITS} for label in LABELS},
            "packet_rows_per_split": dict(row_counts["packet"]),
            "flow_rows_per_split": dict(row_counts["flow"]),
            "packet_unique_observation_ids": len(seen_obs["packet"]),
            "flow_unique_observation_ids": len(seen_obs["flow"]),
            "exact_duplicate_packet_rows": 0,
            "exact_duplicate_flow_rows": 0,
            "profile_ids_unique_across_splits": True,
            "failed_capture_ids_excluded": [r["run_id"] for _, r in sorted(failed)],
            "note": "Repeated feature vectors may occur naturally in packet telemetry; none were synthetically duplicated or removed.",
        }
        (staging / "qc_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        readme = (
            "# Final offline Packet/Flow datasets (V3)\n\n"
            "Generated from 160 completed independent Mininet runs: 40 per class. "
            "Train/validation/final-test are split by run/profile (16/4/20 per class), "
            "so no run or profile crosses splits. Packet and flow records share the same run-level split.\n\n"
            "Three manifest-failed captures are preserved in the source raw folders and listed in "
            "`excluded_failed_runs.csv`; they are excluded from every split. No oversampling, synthetic rows, "
            "or exact-row duplication was used. Naturally repeated feature vectors in packet telemetry are retained.\n\n"
            "Use `packet_splits/` or `flow_splits/` with the existing `train_models.py`. Keep `test.csv` "
            "untouched until final evaluation; do not use it for feature or model selection.\n"
        )
        (staging / "README.md").write_text(readme, encoding="utf-8")
        files = sorted(p for p in staging.rglob("*") if p.is_file() and p.name != "SHA256SUMS.txt")
        sums = "".join(f"{file_sha256(p)}  {p.relative_to(staging).as_posix()}\n" for p in files)
        (staging / "SHA256SUMS.txt").write_text(sums, encoding="utf-8")
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists():
            raise FileExistsError(f"Output appeared during build; refusing overwrite: {output}")
        staging.rename(output)
    except BaseException:
        for handle in handles:
            try:
                handle.close()
            except Exception:
                pass
        shutil.rmtree(staging, ignore_errors=True)
        raise

    print("FINAL PACKAGE CREATED:", output)
    print("Completed runs:", len(completed), "(40/class); failed runs excluded:", len(failed))
    print("Run split per class: train=16, validation=4, final_test=20")
    print("Packet rows:", dict(row_counts["packet"]))
    print("Flow rows:", dict(row_counts["flow"]))
    print("Exact duplicate rows: packet=0, flow=0; duplicate observation IDs: packet=0, flow=0")
    print("Verify with: cd", output, "&& sha256sum -c SHA256SUMS.txt")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"BUILD STOP: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise
