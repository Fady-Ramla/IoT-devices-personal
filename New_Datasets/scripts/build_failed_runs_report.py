#!/usr/bin/env python3
"""Create failed_runs_report.csv from failed rows in the run manifest."""
import argparse
import csv
import os
from pathlib import Path
import tempfile

FIELDS = [
    "run_id", "generation", "run_type", "label", "attack_type", "status",
    "start_time", "end_time", "attacker_host", "attacker_ip", "target_host",
    "target_ip", "service_name", "protocol", "src_port", "dst_port",
    "rate_value", "duration_sec", "notes",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    if not args.manifest.is_file():
        raise SystemExit(f"manifest not found: {args.manifest}")

    failed = []
    with args.manifest.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not {"run_id", "status"}.issubset(reader.fieldnames):
            raise SystemExit("manifest header is missing run_id/status")
        for row in reader:
            if (row.get("status") or "").strip().lower() == "failed":
                failed.append({field: row.get(field, "") or "" for field in FIELDS})

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", newline="", encoding="utf-8", dir=args.output.parent,
            prefix="." + args.output.name + ".", delete=False
        ) as handle:
            temp_path = Path(handle.name)
            writer = csv.DictWriter(handle, fieldnames=FIELDS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(failed)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o644)
        os.replace(temp_path, args.output)
        dir_fd = os.open(str(args.output.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)

    print(f"Report: {args.output}")
    print(f"Failed/partial runs in manifest: {len(failed)}")
    if not failed:
        print("No failed runs are currently recorded; report contains only its header.")


if __name__ == "__main__":
    main()
