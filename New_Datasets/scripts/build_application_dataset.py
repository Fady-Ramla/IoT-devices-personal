#!/usr/bin/env python3
"""Build a privacy-preserving HTTP request dataset from active-run telemetry.

This is a binary application-layer branch for Normal vs Malicious_POST, not a
replacement for the four-class packet/flow model. Labels come only from the
run manifest. Request bodies, credentials, URL paths, and HTTP headers are
forbidden inputs. Split by run_id before training.
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path
import sys

import pandas as pd

DATASET_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = DATASET_ROOT.parent
MANIFEST_PATH = DATASET_ROOT / "experiments" / "run_manifest.csv"
ALLOWED_LABELS = {"Normal", "Malicious_POST"}
REQUIRED_COLUMNS = {
    "run_id", "generation", "application_observation_id", "timestamp",
    "src_ip", "src_port", "dst_ip", "dst_port", "http_method",
    "route_category", "response_status",
}
FORBIDDEN_TOKENS = {"body", "payload", "password", "authorization", "cookie", "query", "headers", "raw_url"}
OUTPUT_COLUMNS = [
    "run_id", "observation_id", "timestamp", "http_method",
    "route_category", "response_status", "label", "label_status",
]


def read_manifest(path: Path) -> dict[str, dict[str, str]]:
    if not path.is_file():
        raise SystemExit(f"manifest not found: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    result = {row.get("run_id", ""): row for row in rows if row.get("run_id")}
    if not result:
        raise SystemExit("manifest has no run rows")
    return result


def validate_columns(path: Path, manifest: dict[str, dict[str, str]]) -> None:
    with path.open(newline="", encoding="utf-8") as handle:
        header = next(csv.reader(handle), [])
    missing = sorted(REQUIRED_COLUMNS - set(header))
    forbidden = sorted(col for col in header if any(token in col.lower() for token in FORBIDDEN_TOKENS))
    if missing:
        raise SystemExit(f"{path.name}: required telemetry columns missing: {missing}")
    if forbidden:
        raise SystemExit(f"{path.name}: forbidden sensitive columns present: {forbidden}")
    run_id = path.stem
    if run_id not in manifest:
        raise SystemExit(f"{path.name}: run_id absent from manifest")


def validate_run_frame(df: pd.DataFrame, path: Path, run: dict[str, str]) -> pd.DataFrame:
    run_id = path.stem
    if df.empty:
        raise SystemExit(f"{path.name}: empty telemetry file")
    ids = df["run_id"].fillna("").astype(str).str.strip()
    if not ids.eq(run_id).all():
        raise SystemExit(f"{path.name}: telemetry run_id mismatch")
    observation_ids = df["application_observation_id"].fillna("").astype(str).str.strip()
    if observation_ids.eq("").any() or observation_ids.duplicated().any():
        raise SystemExit(f"{path.name}: blank or duplicate application_observation_id")
    try:
        generation = pd.to_numeric(df["generation"], errors="raise")
        start = float(run["start_time"])
        end = float(run["end_time"])
        timestamps = pd.to_numeric(df["timestamp"], errors="raise")
    except (TypeError, ValueError, KeyError) as exc:
        raise SystemExit(f"{path.name}: invalid generation/timestamp/manifest interval: {exc}") from exc
    if generation.nunique() != 1 or (generation <= 0).any() or start <= 0 or end < start:
        raise SystemExit(f"{path.name}: invalid generation or manifest run interval")
    outside = (timestamps < start) | (timestamps > end + 5.0)
    if outside.any():
        raise SystemExit(f"{path.name}: {int(outside.sum())} app events outside run window")

    label = (run.get("label") or "").strip()
    if label not in ALLOWED_LABELS:
        raise SystemExit(f"{path.name}: only Normal/Malicious_POST are valid in this app branch")
    expected_src = (run.get("attacker_ip") or "").strip()
    expected_dst = (run.get("target_ip") or "").strip()
    if not df["src_ip"].fillna("").astype(str).str.strip().eq(expected_src).all():
        raise SystemExit(f"{path.name}: source IP differs from manifest attacker_ip")
    if not df["dst_ip"].fillna("").astype(str).str.strip().eq(expected_dst).all():
        raise SystemExit(f"{path.name}: destination IP differs from manifest target_ip")

    methods = df["http_method"].fillna("").astype(str).str.upper()
    routes = df["route_category"].fillna("").astype(str).str.lower()
    if not methods.isin({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "OTHER"}).all():
        raise SystemExit(f"{path.name}: unsupported HTTP method")
    if not routes.isin({"health", "auth", "iot_api", "root", "other"}).all():
        raise SystemExit(f"{path.name}: unsupported route category")
    ports = pd.to_numeric(df["dst_port"], errors="coerce")
    if ports.isna().any() or not ports.eq(5000).all():
        raise SystemExit(f"{path.name}: application telemetry destination must be TCP/5000")
    status = pd.to_numeric(df["response_status"], errors="coerce")
    if status.isna().any() or not status.between(100, 599).all():
        raise SystemExit(f"{path.name}: invalid HTTP response status")
    if label == "Malicious_POST" and not ((methods == "POST") & (routes == "auth")).any():
        raise SystemExit(f"{path.name}: Malicious_POST run has no POST/auth event")

    out = pd.DataFrame({
        "run_id": run_id,
        "observation_id": observation_ids,
        "timestamp": timestamps,
        "http_method": methods,
        "route_category": routes,
        # Kept for QA only; training script explicitly excludes it.
        "response_status": status.astype(int),
        "label": label,
        "label_status": "matched",
    })
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, default=DATASET_ROOT / "raw" / "application")
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--expected-runs-per-label", type=int, default=None,
        help="if set, refuse to write unless each binary class has exactly this many completed runs",
    )
    args = parser.parse_args()

    manifest = read_manifest(args.manifest)
    paths = sorted(args.input_dir.glob("*.csv"))
    if not paths:
        raise SystemExit(f"no application telemetry CSV files found: {args.input_dir}")
    frames = []
    skipped = 0
    for path in paths:
        run_id = path.stem
        run = manifest.get(run_id)
        if run is None:
            raise SystemExit(f"{path.name}: run_id absent from manifest")
        status = (run.get("status") or "").strip().lower()
        if status != "completed":
            print(f"skip {run_id}: manifest status={status or 'blank'}")
            skipped += 1
            continue
        label = (run.get("label") or "").strip()
        if label not in ALLOWED_LABELS:
            print(f"skip {run_id}: app branch excludes label={label or 'blank'}")
            skipped += 1
            continue
        validate_columns(path, manifest)
        raw = pd.read_csv(path, dtype={"run_id": str, "src_ip": str, "dst_ip": str})
        frame = validate_run_frame(raw, path, run)
        frames.append(frame)
        print(f"include {run_id}: label={label}, events={len(frame)}")

    if not frames:
        raise SystemExit("no completed Normal/Malicious_POST application events found")
    result = pd.concat(frames, ignore_index=True)
    if result["observation_id"].duplicated().any():
        raise SystemExit("duplicate application observation_id across runs")
    run_labels = result[["run_id", "label"]].drop_duplicates()
    if run_labels["run_id"].duplicated().any():
        raise SystemExit("a run_id maps to multiple labels")
    run_counts = run_labels.groupby("label")["run_id"].nunique().to_dict()
    if args.expected_runs_per_label is not None:
        expected = {label: args.expected_runs_per_label for label in sorted(ALLOWED_LABELS)}
        observed = {label: int(run_counts.get(label, 0)) for label in sorted(ALLOWED_LABELS)}
        if args.expected_runs_per_label < 1 or observed != expected:
            raise SystemExit(f"expected exactly {expected} completed runs; observed {observed}; no output written")
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {args.output}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result[OUTPUT_COLUMNS].to_csv(args.output, index=False)
    print(f"wrote {len(result)} HTTP event rows from {result['run_id'].nunique()} runs to {args.output}")
    print("runs per label:", run_counts)
    print("events per label:", result["label"].value_counts().to_dict())
    print(f"non-completed/non-app rows skipped: {skipped}")
    print("MODEL FEATURES ONLY: http_method, route_category; response_status is QA-only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
