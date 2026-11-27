"""Static integrity checks for the IOT-API-Merge two-branch merge.

This deliberately checks both active files and immutable source snapshots. It
prevents future cleanup from silently deleting an implementation that could
not be safely combined into a shared runtime file.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "merge_compatibility" / "merge_manifest.json"
SNAP = ROOT / "merge_compatibility" / "source_snapshots"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def test_manifest_has_both_source_tips_and_files():
    data = json.loads(MANIFEST.read_text())
    assert data["merge_branch"] == "IOT-API-Merge"
    assert set(data["sources"]) == {"api-runtime-latest-20261111", "iot-simulator-integration"}
    assert all(item["files"] for item in data["sources"].values())
    assert data["conflicted_paths"]


def test_every_source_file_is_active_or_preserved_snapshot():
    data = json.loads(MANIFEST.read_text())
    active = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts}
    for source, meta in data["sources"].items():
        for item in meta["files"]:
            path = item["path"]
            preserved = SNAP / source / path
            assert path in active or preserved.is_file(), f"dropped {source}:{path}"


def test_conflict_snapshots_match_source_blobs():
    data = json.loads(MANIFEST.read_text())
    for source, meta in data["sources"].items():
        by_path = {item["path"]: item["blob"] for item in meta["files"]}
        for path in data["conflicted_paths"]:
            snapshot = SNAP / source / path
            assert snapshot.is_file(), f"missing {source} snapshot: {path}"
            actual_blob = hashlib.sha1(
                f"blob {snapshot.stat().st_size}\0".encode() + snapshot.read_bytes()
            ).hexdigest()
            assert actual_blob == by_path[path], f"changed {source} snapshot: {path}"


def test_required_operations_are_present():
    candidates = [
        ROOT / "topology_monitor.py",
        ROOT / "traffic_monitor_merged.py",
        ROOT / "runtime_network_api.py",
        ROOT / "shadow_api_client.py",
        ROOT / "shadow_verdict_gate.py",
        ROOT / "mininet" / "iot_device_simulator.py",
        ROOT / "mininet" / "load_balancer.py",
        ROOT / "mininet" / "lb_fallback_agent.py",
    ]
    corpus = "\n".join(p.read_text(errors="replace") for p in candidates if p.is_file())
    for marker in (
        "block_device", "unblock_device", "reroute", "load_balancer",
        "shadow", "BLOCK_DEVICE", "UNBLOCK_DEVICE", "health",
    ):
        assert marker.lower() in corpus.lower(), f"missing operation marker: {marker}"
