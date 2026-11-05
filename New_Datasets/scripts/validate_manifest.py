#!/usr/bin/env python3
"""Validate run_manifest.csv before any collection or labeling step."""
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "experiments" / "run_manifest.csv"
REPORT = ROOT / "reports" / "collection_report.json"
REQUIRED = {"run_id", "run_type", "start_time", "end_time", "status"}


def main() -> int:
    errors = []
    rows = []
    if not MANIFEST.exists():
        errors.append(f"missing file: {MANIFEST}")
    else:
        with MANIFEST.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            headers = set(reader.fieldnames or [])
            errors.extend(f"missing column: {c}" for c in sorted(REQUIRED - headers))
            rows = list(reader)

    ids = [r.get("run_id", "") for r in rows]
    duplicates = sorted(k for k, v in Counter(ids).items() if k and v > 1)
    errors.extend(f"duplicate run_id: {x}" for x in duplicates)
    for i, row in enumerate(rows, 2):
        if not row.get("run_id", "").strip():
            errors.append(f"row {i}: empty run_id")
        if not row.get("start_time", "").strip() or not row.get("end_time", "").strip():
            errors.append(f"row {i}: missing time boundary")
        if row.get("run_type") == "attack" and not row.get("label", "").strip():
            errors.append(f"row {i}: attack without label")

    report = {
        "manifest": str(MANIFEST),
        "rows": len(rows),
        "run_ids": len(set(x for x in ids if x)),
        "labels": dict(Counter(r.get("label", "") for r in rows)),
        "errors": errors,
        "status": "FAIL" if errors else "PASS",
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
