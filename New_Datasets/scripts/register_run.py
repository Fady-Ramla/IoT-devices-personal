#!/usr/bin/env python3
"""Atomic run-manifest support for the fail-closed collector orchestrator."""
from __future__ import annotations

import argparse
import contextlib
import csv
import fcntl
import os
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "New_Datasets" / "experiments" / "run_manifest.csv"
FIELDS = [
    "run_id", "generation", "run_type", "label", "attack_type",
    "experiment_category", "start_time", "end_time", "attacker_host",
    "attacker_ip", "target_host", "target_ip", "service_name", "protocol",
    "src_port", "dst_port", "rate_value", "duration_sec", "status", "notes",
]


@contextlib.contextmanager
def file_lock(path, timeout=5.0):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+") as handle:
        deadline = time.monotonic() + float(timeout)
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("timed out acquiring manifest lock: " + str(path))
                time.sleep(0.05)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def fsync_directory(path):
    fd = os.open(str(Path(path)), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_text(path, text, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        fsync_directory(path.parent)
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def _read_manifest(path):
    path = Path(path)
    if not path.exists() or path.stat().st_size == 0:
        return [], False
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        header = reader.fieldnames or []
    if header != FIELDS:
        if rows:
            raise RuntimeError("non-empty manifest schema mismatch; archive it before starting fresh collection")
        return [], False
    return rows, True


def next_generation(path=MANIFEST):
    rows, _ = _read_manifest(path)
    values = []
    for row in rows:
        value = (row.get("generation") or "").strip()
        if value:
            try:
                values.append(int(value))
            except ValueError as exc:
                raise RuntimeError("invalid generation in manifest") from exc
    return max(values, default=0) + 1


def register_run(updates, path=MANIFEST):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows, _ = _read_manifest(path)
    run_id = str(updates.get("run_id", "")).strip()
    if not run_id:
        raise ValueError("run_id is required")
    match = next((row for row in rows if row.get("run_id") == run_id), None)
    if match is None:
        row = {field: "" for field in FIELDS}
        row.update({key: value for key, value in updates.items() if key in FIELDS})
        rows.append(row)
    else:
        match.update({key: value for key, value in updates.items() if key in FIELDS})
        row = match
    fd, temp_name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        fsync_directory(path.parent)
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise
    return dict(row)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in FIELDS:
        required = field in {"run_id", "run_type", "start_time", "status"}
        parser.add_argument("--" + field.replace("_", "-"), required=required, default="")
    return parser.parse_args()


def main():
    args = vars(parse_args())
    lock = MANIFEST.with_name(MANIFEST.name + ".orchestrator.lock")
    with file_lock(lock):
        row = register_run(args, MANIFEST)
    print("registered run_id=%s status=%s" % (row["run_id"], row["status"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
