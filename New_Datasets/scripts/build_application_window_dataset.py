#!/usr/bin/env python3
"""Build a fresh, run-grouped login-burst dataset from application_v2 telemetry.

The target is repeated failed-login behavior, not arbitrary malicious payloads.
Only fixed-window aggregate counts/rates are model features. Raw bodies,
credentials, paths, headers, IPs, timestamps, and run identifiers are excluded.
"""
from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path
import uuid

WINDOW_SECONDS = 5.0
ALLOWED_LABELS = {"Normal", "Malicious_POST"}
REQUIRED_RAW_COLUMNS = {
    "run_id", "generation", "application_observation_id", "timestamp",
    "src_ip", "dst_ip", "dst_port", "http_method", "route_category",
    "response_status",
}
FORBIDDEN_TOKENS = {
    "body", "payload", "password", "authorization", "cookie", "query",
    "headers", "raw_url",
}
FEATURES = [
    "total_requests",
    "post_count",
    "auth_post_count",
    "auth_post_2xx_count",
    "auth_post_401_count",
    "auth_post_4xx_other_count",
    "auth_post_5xx_count",
    "auth_get_count",
    "health_get_count",
    "iot_api_post_count",
    "other_route_post_count",
    "all_2xx_count",
    "all_4xx_count",
    "all_5xx_count",
    "auth_post_rate_per_sec",
    "auth_401_rate_per_sec",
]
OUTPUT_COLUMNS = ["run_id", "observation_id", "window_index", "label", "label_status", *FEATURES]


def read_manifest(path: Path) -> dict[str, dict[str, str]]:
    if not path.is_file():
        raise SystemExit(f"manifest not found: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
    required = {"run_id", "status", "label", "start_time", "end_time", "attacker_ip", "target_ip"}
    missing = required - set(reader.fieldnames or [])
    if missing:
        raise SystemExit(f"manifest missing required columns: {sorted(missing)}")
    result: dict[str, dict[str, str]] = {}
    for row in rows:
        run_id = (row.get("run_id") or "").strip()
        if not run_id:
            continue
        if run_id in result:
            raise SystemExit(f"duplicate run_id in manifest: {run_id}")
        result[run_id] = row
    return result


def load_raw(path: Path, run: dict[str, str], seen_event_ids: set[str]) -> list[tuple[float, dict[str, str]]]:
    run_id = path.stem
    try:
        uuid.UUID(run_id)
    except ValueError as exc:
        raise SystemExit(f"invalid UUID raw filename: {path.name}") from exc

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        columns = set(reader.fieldnames or [])
        missing = REQUIRED_RAW_COLUMNS - columns
        forbidden = sorted(
            col for col in columns if any(token in col.lower() for token in FORBIDDEN_TOKENS)
        )
        if missing:
            raise SystemExit(f"{path.name}: missing raw columns {sorted(missing)}")
        if forbidden:
            raise SystemExit(f"{path.name}: forbidden sensitive raw columns {forbidden}")
        rows = list(reader)

    if not rows:
        raise SystemExit(f"{path.name}: no application events")
    label = (run.get("label") or "").strip()
    if label not in ALLOWED_LABELS:
        raise SystemExit(f"{path.name}: unsupported label {label!r}")
    if run.get("status") != "completed":
        raise SystemExit(f"{path.name}: selected run is not completed")

    try:
        start = float(run["start_time"])
        end = float(run["end_time"])
    except (TypeError, ValueError) as exc:
        raise SystemExit(f"{path.name}: invalid manifest start/end time") from exc
    if not math.isfinite(start) or not math.isfinite(end) or start <= 0 or end < start:
        raise SystemExit(f"{path.name}: invalid run time interval")

    parsed: list[tuple[float, dict[str, str]]] = []
    generations: set[int] = set()
    expected_src = (run.get("attacker_ip") or "").strip()
    expected_dst = (run.get("target_ip") or "").strip()
    for row in rows:
        if (row.get("run_id") or "").strip() != run_id:
            raise SystemExit(f"{path.name}: row run_id mismatch")
        event_id = (row.get("application_observation_id") or "").strip()
        if not event_id or event_id in seen_event_ids:
            raise SystemExit(f"{path.name}: blank or duplicate application observation id")
        seen_event_ids.add(event_id)
        try:
            generation = int(row.get("generation", ""))
            timestamp = float(row.get("timestamp", ""))
            status = int(row.get("response_status", ""))
        except (TypeError, ValueError) as exc:
            raise SystemExit(f"{path.name}: invalid generation/timestamp/status") from exc
        if generation < 1 or not math.isfinite(timestamp) or not 100 <= status <= 599:
            raise SystemExit(f"{path.name}: invalid generation, timestamp, or status")
        generations.add(generation)
        if timestamp < start - 1.0 or timestamp > end + 3.0:
            raise SystemExit(f"{path.name}: event outside manifest run window")
        if expected_src and (row.get("src_ip") or "").strip() != expected_src:
            raise SystemExit(f"{path.name}: src_ip mismatch with manifest")
        if expected_dst and (row.get("dst_ip") or "").strip() != expected_dst:
            raise SystemExit(f"{path.name}: dst_ip mismatch with manifest")
        method = (row.get("http_method") or "").strip().upper()
        route = (row.get("route_category") or "").strip()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "OTHER"}:
            raise SystemExit(f"{path.name}: unexpected HTTP method")
        if route not in {"auth", "health", "iot_api", "root", "other"}:
            raise SystemExit(f"{path.name}: unexpected route category")
        parsed.append((timestamp, row))
    if len(generations) != 1:
        raise SystemExit(f"{path.name}: mixed or invalid run generations")
    service = (run.get("service_name") or "").strip()
    auth_post_statuses = [
        int(row["response_status"])
        for _, row in parsed
        if row["http_method"].upper() == "POST" and row["route_category"] == "auth"
    ]
    if label == "Malicious_POST":
        if (run.get("run_type") or "").strip() != "attack":
            raise SystemExit(f"{path.name}: Malicious_POST run is not marked as an attack")
        if sum(code == 401 for code in auth_post_statuses) < 5:
            raise SystemExit(f"{path.name}: fewer than five failed auth POSTs; reject as non-burst")
    elif service == "http_api_login_success":
        if auth_post_statuses != [200]:
            raise SystemExit(f"{path.name}: successful-login control must contain exactly one HTTP 200 auth POST")
    elif service == "http_api_login_invalid_once":
        if auth_post_statuses != [401]:
            raise SystemExit(f"{path.name}: isolated-failure control must contain exactly one HTTP 401 auth POST")
    return parsed


def aggregate_run(run_id: str, run: dict[str, str], events: list[tuple[float, dict[str, str]]]) -> list[dict[str, object]]:
    start = float(run["start_time"])
    label = (run.get("label") or "").strip()
    bins: dict[int, list[dict[str, str]]] = {}
    for timestamp, row in events:
        index = max(0, int((timestamp - start) // WINDOW_SECONDS))
        bins.setdefault(index, []).append(row)

    output: list[dict[str, object]] = []
    for index, rows in sorted(bins.items()):
        status_counts = [int(row["response_status"]) for row in rows]
        auth_posts = [row for row in rows if row["http_method"].upper() == "POST" and row["route_category"] == "auth"]
        auth_post_statuses = [int(row["response_status"]) for row in auth_posts]
        values: dict[str, object] = {
            "run_id": run_id,
            "observation_id": f"{run_id}:window:{index}",
            "window_index": index,
            "label": label,
            "label_status": "manifest_completed",
            "total_requests": len(rows),
            "post_count": sum(row["http_method"].upper() == "POST" for row in rows),
            "auth_post_count": len(auth_posts),
            "auth_post_2xx_count": sum(200 <= code < 300 for code in auth_post_statuses),
            "auth_post_401_count": sum(code == 401 for code in auth_post_statuses),
            "auth_post_4xx_other_count": sum(400 <= code < 500 and code != 401 for code in auth_post_statuses),
            "auth_post_5xx_count": sum(500 <= code < 600 for code in auth_post_statuses),
            "auth_get_count": sum(row["http_method"].upper() == "GET" and row["route_category"] == "auth" for row in rows),
            "health_get_count": sum(row["http_method"].upper() == "GET" and row["route_category"] == "health" for row in rows),
            "iot_api_post_count": sum(row["http_method"].upper() == "POST" and row["route_category"] == "iot_api" for row in rows),
            "other_route_post_count": sum(row["http_method"].upper() == "POST" and row["route_category"] not in {"auth", "iot_api"} for row in rows),
            "all_2xx_count": sum(200 <= code < 300 for code in status_counts),
            "all_4xx_count": sum(400 <= code < 500 for code in status_counts),
            "all_5xx_count": sum(500 <= code < 600 for code in status_counts),
        }
        values["auth_post_rate_per_sec"] = values["auth_post_count"] / WINDOW_SECONDS
        values["auth_401_rate_per_sec"] = values["auth_post_401_count"] / WINDOW_SECONDS
        output.append(values)
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, default=Path("New_Datasets/raw/application_v2"))
    parser.add_argument("--manifest", type=Path, default=Path("New_Datasets/experiments/run_manifest.csv"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-runs-per-label", type=int, default=15)
    args = parser.parse_args()

    if args.expected_runs_per_label < 1:
        raise SystemExit("expected-runs-per-label must be >=1")
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {args.output}")
    if not args.input_dir.is_dir():
        raise SystemExit(f"application telemetry directory not found: {args.input_dir}")

    manifest = read_manifest(args.manifest)
    files = sorted(args.input_dir.glob("*.csv"))
    if not files:
        raise SystemExit(f"no application-v2 CSV files found in {args.input_dir}")
    seen_event_ids: set[str] = set()
    selected_runs: dict[str, dict[str, str]] = {}
    output_rows: list[dict[str, object]] = []
    skipped = 0
    for path in files:
        run_id = path.stem
        run = manifest.get(run_id)
        if run is None:
            raise SystemExit(f"raw application run is missing from manifest: {run_id}")
        if run.get("status") != "completed":
            skipped += 1
            continue
        label = (run.get("label") or "").strip()
        if label not in ALLOWED_LABELS:
            skipped += 1
            continue
        events = load_raw(path, run, seen_event_ids)
        selected_runs[run_id] = run
        output_rows.extend(aggregate_run(run_id, run, events))

    counts = {label: sum((run.get("label") or "").strip() == label for run in selected_runs.values()) for label in sorted(ALLOWED_LABELS)}
    expected = args.expected_runs_per_label
    if counts != {"Malicious_POST": expected, "Normal": expected}:
        raise SystemExit(f"run-count gate failed: expected {expected} per class, got {counts}; no output written")
    if not output_rows:
        raise SystemExit("no windows created; no output written")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with args.output.open("x", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS)
            writer.writeheader()
            writer.writerows(output_rows)
    except FileExistsError:
        raise SystemExit(f"refusing to overwrite existing output: {args.output}")

    windows_by_label: dict[str, int] = {}
    for label in sorted(ALLOWED_LABELS):
        windows_by_label[label] = sum(row["label"] == label for row in output_rows)
    print(f"wrote {len(output_rows)} fixed {WINDOW_SECONDS:g}s windows from {len(selected_runs)} fresh completed runs to {args.output}")
    print("runs per label:", counts)
    print("windows per label:", windows_by_label)
    print("non-completed/non-app rows skipped:", skipped)
    print("model inputs:", ", ".join(FEATURES))
    print("excluded: credentials, bodies, paths, headers, IPs, timestamps, run IDs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
