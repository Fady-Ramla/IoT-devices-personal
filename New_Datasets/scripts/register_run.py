#!/usr/bin/env python3
"""Create/update a UUID run in New_Datasets/experiments/run_manifest.csv.

Use a stable sidecar lock, never the CSV inode replaced by os.replace().
New rows must be planned; terminal rows cannot be reopened. Imports do no I/O.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import csv
import fcntl
import io
import math
import os
from pathlib import Path
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "experiments" / "run_manifest.csv"
BASE_FIELDS = [
    "run_id", "run_type", "label", "attack_type", "experiment_category",
    "start_time", "end_time", "attacker_host", "attacker_ip", "target_host",
    "target_ip", "service_name", "protocol", "dst_port", "rate_value",
    "duration_sec", "status", "notes",
]
FIELDS = BASE_FIELDS + ["generation", "src_port"]
LABELS = {"", "Normal", "Malicious_POST", "Port_Scan", "SYN_Flood"}
RUN_TYPES = {"normal", "attack"}
STATUSES = {"planned", "running", "completed", "failed"}
CATEGORIES = {
    "normal_baseline", "allowed_attack_delivery", "firewall_blocked_attack_attempt",
    "service_unavailable_control", "failed_experiment", "",
}
TRANSITIONS = {
    "planned": {"running", "failed"}, "running": {"completed", "failed"},
    "completed": set(), "failed": set(),
}
MUTABLE = {"status", "start_time", "end_time", "notes", "experiment_category"}


class ManifestError(ValueError):
    """Invalid metadata, corrupt manifest, or forbidden state transition."""


@contextmanager
def file_lock(path: Path, timeout: float = 5.0):
    """Bounded process-wide flock, released after exceptions/interrupts."""
    path = Path(path)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("lock timeout must be positive and finite")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as lock:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"lock busy: {path}")
                time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def fsync_directory(path: Path) -> None:
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_text(path: Path, text: str, mode: int = 0o644) -> None:
    """Durable same-directory replacement; caller owns a sidecar lock."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="",
                                         dir=path.parent, prefix="." + path.name + ".",
                                         delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def read_manifest(manifest: Path = MANIFEST):
    """Read an atomic snapshot; reject malformed CSV rather than overwrite it."""
    manifest = Path(manifest)
    if not manifest.exists():
        return list(FIELDS), []
    with manifest.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        headers = reader.fieldnames or []
        if len(headers) != len(set(headers)) or not set(BASE_FIELDS).issubset(headers):
            raise ManifestError("manifest header is missing/duplicated: " + str(manifest))
        rows = list(reader)
    ids = set()
    for row in rows:
        if None in row or any(value is None for value in row.values()):
            raise ManifestError("malformed CSV row")
        run_id = row.get("run_id", "")
        if not run_id or run_id in ids or row.get("status") not in STATUSES:
            raise ManifestError("invalid/duplicate existing run: " + run_id)
        ids.add(run_id)
    return headers + [field for field in FIELDS if field not in headers], rows


def validate_row(row: dict) -> None:
    try:
        if str(uuid.UUID(row["run_id"])) != row["run_id"]:
            raise ValueError("noncanonical UUID")
    except (ValueError, KeyError, AttributeError) as exc:
        raise ManifestError("run_id must be a canonical UUID") from exc
    try:
        if int(row["generation"]) < 1 or str(int(row["generation"])) != row["generation"]:
            raise ValueError("invalid generation")
    except (ValueError, KeyError) as exc:
        raise ManifestError("generation must be a positive integer") from exc
    if row["run_type"] not in RUN_TYPES or row["status"] not in STATUSES:
        raise ManifestError("invalid run_type/status")
    if row["label"] not in LABELS or row["experiment_category"] not in CATEGORIES:
        raise ManifestError("invalid label/experiment_category")
    if row["run_type"] == "normal" and (row["label"] or row["attack_type"]):
        raise ManifestError("normal runs cannot have attack label or attack_type")
    attack_labels = {"syn_flood": "SYN_Flood", "port_scan": "Port_Scan",
                     "malicious_post": "Malicious_POST"}
    if row["run_type"] == "attack" and attack_labels.get(row["attack_type"]) != row["label"]:
        raise ManifestError("attack_type and label must match")
    for field in ("rate_value", "duration_sec", "start_time", "end_time"):
        if row[field]:
            try:
                number = float(row[field])
                if not math.isfinite(number) or number < 0:
                    raise ValueError("negative/nonfinite")
            except ValueError as exc:
                raise ManifestError(f"{field} must be finite nonnegative numeric text") from exc
    if row["status"] in {"running", "completed", "failed"} and not row["start_time"]:
        raise ManifestError("running/terminal runs require start_time")
    if row["status"] in {"completed", "failed"} and not row["end_time"]:
        raise ManifestError("terminal runs require end_time")
    if row["status"] in {"planned", "running"} and row["end_time"]:
        raise ManifestError("nonterminal runs cannot have end_time")
    if row["end_time"] and float(row["end_time"]) < float(row["start_time"]):
        raise ManifestError("end_time precedes start_time")


def register_run(values: dict, manifest: Path = MANIFEST, lock_timeout: float = 5.0) -> dict:
    """Atomic insert/transition; exactly one row per UUID, no duplicate append."""
    manifest = Path(manifest)
    unknown = set(values) - set(FIELDS)
    if unknown:
        raise ManifestError("unknown fields: " + ", ".join(sorted(unknown)))
    values = {key: str(value) for key, value in values.items() if value is not None}
    if not values.get("run_id") or not values.get("status"):
        raise ManifestError("run_id/status are required")
    with file_lock(manifest.with_name(manifest.name + ".lock"), lock_timeout):
        headers, rows = read_manifest(manifest)
        matches = [i for i, row in enumerate(rows) if row["run_id"] == values["run_id"]]
        if matches:
            index = matches[0]
            old = rows[index]
            if values["status"] not in TRANSITIONS[old["status"]]:
                raise ManifestError(f"forbidden transition {old['status']} -> {values['status']}")
            for key, value in values.items():
                if key not in MUTABLE and value != old.get(key, ""):
                    raise ManifestError("cannot change run identity/metadata: " + key)
            row = {field: old.get(field, "") for field in headers}
            row.update(values)
            validate_row(row)
            rows[index] = row
        else:
            if values["status"] != "planned":
                raise ManifestError("new runs must start as planned")
            row = {field: "" for field in headers}
            row.update(values)
            validate_row(row)
            rows.append(row)
        buffer = io.StringIO(newline="")
        writer = csv.DictWriter(buffer, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
        atomic_text(manifest, buffer.getvalue())
        return {field: row.get(field, "") for field in FIELDS}


def next_generation(manifest: Path = MANIFEST) -> int:
    """Caller holds lifetime lock; unresolved nonterminal history blocks runs."""
    manifest = Path(manifest)
    with file_lock(manifest.with_name(manifest.name + ".lock")):
        _, rows = read_manifest(manifest)
    if any(row["status"] in {"planned", "running"} for row in rows):
        raise ManifestError("unresolved planned/running run; explicit operator recovery required")
    generations = []
    for row in rows:
        value = row.get("generation", "")
        if value:
            try:
                number = int(value)
                if number < 1:
                    raise ValueError("invalid generation")
                generations.append(number)
            except ValueError as exc:
                raise ManifestError("invalid existing generation") from exc
    return max(generations, default=0) + 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    for field in FIELDS:
        options = {"required": field in {"run_id", "status"}, "default": None}
        if field == "status":
            options["choices"] = sorted(STATUSES)
        elif field == "run_type":
            options["choices"] = sorted(RUN_TYPES)
        parser.add_argument("--" + field.replace("_", "-"), **options)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        row = register_run({field: getattr(args, field) for field in FIELDS})
    except (ManifestError, OSError, TimeoutError) as exc:
        raise SystemExit(str(exc))
    print(f"registered run_id={row['run_id']} status={row['status']} in {MANIFEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
