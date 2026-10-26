#!/usr/bin/env python3
"""Package and verify the existing AI_OFFLINE_LEARNING_V2 splits.

This does NOT reshuffle or alter data. It verifies existing run-grouped splits
against balanced_candidate_*_qc_v2.csv, then creates a new, clean package at:
  New_Datasets/AI_OFFLINE_LEARNING_V2_FINAL
It never overwrites the source or an existing destination.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path

import pandas as pd

KINDS = ("packet", "flow")
SPLITS = ("train", "validation", "test")
LABELS = {"Normal", "Malicious_POST", "Port_Scan", "SYN_Flood"}


def fail(msg: str) -> None:
    raise SystemExit(f"ERROR: {msg}")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_csv(path: Path, required: set[str], desc: str) -> pd.DataFrame:
    if not path.is_file():
        fail(f"missing {desc}: {path}")
    df = pd.read_csv(path)
    missing = sorted(required - set(df.columns))
    if missing:
        fail(f"{desc} is missing required columns: {missing}")
    if df.empty:
        fail(f"{desc} is empty")
    if df[list(required)].isna().any().any():
        nulls = df[list(required)].isna().sum()
        fail(f"{desc} has null required values: {nulls[nulls > 0].to_dict()}")
    return df


def validate_kind(root: Path, source: Path, kind: str, features: list[str]):
    required = {"run_id", "observation_id", "label", *features}
    frames = {}
    run_split: dict[str, str] = {}
    all_ids: set[str] = set()
    report = {"splits": {}, "source": {}}

    # Check every split, unique IDs/rows, and no run leakage.
    for split in SPLITS:
        path = source / f"{kind}_splits" / f"{split}.csv"
        df = read_csv(path, required, f"{kind}/{split}")
        if int(df.duplicated().sum()):
            fail(f"{kind}/{split} contains exact duplicate rows")
        if int(df["observation_id"].duplicated().sum()):
            fail(f"{kind}/{split} contains duplicate observation_id")
        ids = set(df["observation_id"].astype(str))
        if all_ids & ids:
            fail(f"{kind}: observation_id repeats across splits")
        all_ids |= ids
        for run_id in df["run_id"].astype(str).unique():
            if run_id in run_split:
                fail(f"{kind}: run_id leaks across splits: {run_id}")
            run_split[run_id] = split
        if not set(df["label"].astype(str)).issubset(LABELS):
            fail(f"{kind}/{split} contains unexpected label")
        frames[split] = df
        report["splits"][split] = {
            "rows": int(len(df)),
            "runs": int(df["run_id"].nunique()),
            "rows_by_label": {str(k): int(v) for k, v in df["label"].value_counts().sort_index().items()},
            "runs_by_label": {str(k): int(v) for k, v in df.groupby("label")["run_id"].nunique().sort_index().items()},
            "exact_duplicate_rows": 0,
            "duplicate_observation_id": 0,
        }

    combined = pd.concat([frames[s] for s in SPLITS], ignore_index=True)
    if int(combined.duplicated().sum()) or int(combined["observation_id"].duplicated().sum()):
        fail(f"{kind}: duplicate rows or IDs across all splits")

    # The delivered splits must contain every QC candidate observation exactly once.
    candidate_path = root / f"New_Datasets/reports/balanced_candidate_{kind}_qc_v2.csv"
    candidate = read_csv(candidate_path, required, f"{kind} full QC candidate")
    if int(candidate.duplicated().sum()) or int(candidate["observation_id"].duplicated().sum()):
        fail(f"{kind} QC candidate itself contains exact duplicate rows or IDs")
    split_ids = set(combined["observation_id"].astype(str))
    candidate_ids = set(candidate["observation_id"].astype(str))
    if split_ids != candidate_ids:
        missing = len(candidate_ids - split_ids)
        extra = len(split_ids - candidate_ids)
        fail(f"{kind} split coverage differs from QC candidate: missing={missing}, extra={extra}")
    candidate_labels = dict(zip(candidate["observation_id"].astype(str), candidate["label"].astype(str)))
    split_labels = dict(zip(combined["observation_id"].astype(str), combined["label"].astype(str)))
    if candidate_labels != split_labels:
        fail(f"{kind}: labels changed between QC candidate and split files")

    # Report feature collisions but do not treat them as duplicate observations.
    vec = candidate[features].astype("string").fillna("<NA>")
    vector_counts = Counter(tuple(r) for r in vec.itertuples(index=False, name=None))
    repeated_vectors = {k: v for k, v in vector_counts.items() if v > 1}
    labels_by_vector = {}
    for key, label in zip(map(tuple, vec.itertuples(index=False, name=None)), candidate["label"].astype(str)):
        labels_by_vector.setdefault(key, set()).add(label)
    report["source"] = {
        "rows": int(len(candidate)),
        "runs": int(candidate["run_id"].nunique()),
        "runs_by_label": {str(k): int(v) for k, v in candidate.groupby("label")["run_id"].nunique().sort_index().items()},
        "rows_by_label": {str(k): int(v) for k, v in candidate["label"].value_counts().sort_index().items()},
        "exact_duplicate_rows": 0,
        "duplicate_observation_id": 0,
        "repeated_feature_vector_groups": int(len(repeated_vectors)),
        "rows_in_repeated_feature_vectors": int(sum(repeated_vectors.values())),
        "feature_vectors_with_conflicting_labels": int(sum(len(v) > 1 for v in labels_by_vector.values())),
        "unique_values_per_feature": {col: int(candidate[col].nunique(dropna=False)) for col in features},
    }
    return frames, run_split, report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path,
                        default=Path("New_Datasets/AI_OFFLINE_LEARNING_V2_FINAL"))
    args = parser.parse_args()
    root = args.project_root.expanduser().resolve()
    source = root / "New_Datasets/AI_OFFLINE_LEARNING_V2"
    out = args.output if args.output.is_absolute() else root / args.output
    out = out.resolve()
    if not root.is_dir():
        fail(f"project root does not exist: {root}")
    if out.exists():
        fail(f"destination already exists; nothing was changed: {out}")

    config_path = source / "config/model_features.json"
    if not config_path.is_file():
        config_path = root / "New_Datasets/config/model_features.json"
    if not config_path.is_file():
        fail("model_features.json was not found in source or project config")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    packet_features = config.get("packet_features")
    flow_features = config.get("flow_features")
    if not isinstance(packet_features, list) or not isinstance(flow_features, list):
        fail("model_features.json must define packet_features and flow_features")

    results = {}
    for kind, features in (("packet", packet_features), ("flow", flow_features)):
        results[kind] = validate_kind(root, source, kind, features)

    packet_runs = results["packet"][1]
    flow_runs = results["flow"][1]
    if packet_runs != flow_runs:
        fail("packet and flow do not share the exact same run_id -> split mapping")

    # Packet training must retain the previously established 10k+ training size.
    packet_train_rows = results["packet"][0]["train"]
    if len(packet_train_rows) < 10_000:
        fail(f"packet train has only {len(packet_train_rows)} rows (<10,000); refusing to label package final")

    out.parent.mkdir(parents=True, exist_ok=True)
    temp = Path(tempfile.mkdtemp(prefix=f".{out.name}.staging-", dir=out.parent))
    try:
        for kind in KINDS:
            dest = temp / f"{kind}_splits"
            dest.mkdir()
            for split in SPLITS:
                shutil.copy2(source / f"{kind}_splits" / f"{split}.csv", dest / f"{split}.csv")
        (temp / "config").mkdir()
        shutil.copy2(config_path, temp / "config/model_features.json")

        manifest_rows = []
        for run_id, split in sorted(packet_runs.items()):
            labels = set()
            for kind in KINDS:
                df = results[kind][0][split]
                labels.update(df.loc[df["run_id"].astype(str) == run_id, "label"].astype(str))
            if len(labels) != 1:
                fail(f"run {run_id} has inconsistent packet/flow labels")
            manifest_rows.append((run_id, next(iter(labels)), split))
        manifest = pd.DataFrame(manifest_rows, columns=["run_id", "label", "split"])
        manifest.to_csv(temp / "run_split_manifest.csv", index=False)

        report = {
            "version": "AI_OFFLINE_LEARNING_V2_FINAL",
            "source_split_directory": str(source.relative_to(root)),
            "source_qc_candidates": {
                "packet": "New_Datasets/reports/balanced_candidate_packet_qc_v2.csv",
                "flow": "New_Datasets/reports/balanced_candidate_flow_qc_v2.csv",
            },
            "split_method": "preserved existing run-grouped train/validation/test split; no reshuffle",
            "packet": results["packet"][2],
            "flow": results["flow"][2],
            "integrity": {
                "exact_duplicate_rows": 0,
                "duplicate_observation_id": 0,
                "run_id_overlap_across_splits": 0,
                "all_candidate_observations_included_once": True,
                "same_run_split_assignment_for_packet_and_flow": True,
                "packet_train_at_least_10000_rows": True,
                "feature_vector_collisions_are_informational_not_removed": True,
                "bias_free_claim": False,
            },
            "notes": [
                "No data rows were resampled, synthesized, duplicated, dropped, or reshuffled.",
                "The separate collection_report.json says 55 runs; this package uses only the verified balanced QC candidates (15 runs per label, 60 total) and does not merge that separate collection.",
                "Equal run counts do not imply equal packet-row counts. Use macro-F1, balanced accuracy, and per-class confusion matrices.",
                "Feature-vector collisions can occur between distinct observations and are not exact duplicates or proof of leakage.",
                "The flow candidate contains 86 rows and is an exploratory dataset, not a large benchmark.",
                "Training metrics were not copied; if models are retrained, save metrics against these exact splits.",
            ],
        }
        (temp / "qc_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        readme = """# AI Offline Learning V2 — Final package\n\nThis package preserves the verified, existing train/validation/test splits without reshuffling. Packet and flow use the same run_id assignment. All observations from the balanced QC candidate CSVs are included exactly once.\n\n## Contents\n- `packet_splits/{train,validation,test}.csv`\n- `flow_splits/{train,validation,test}.csv`\n- `config/model_features.json`\n- `run_split_manifest.csv`\n- `qc_report.json`\n- `SHA256SUMS.txt`\n\n## Important limits\nNo exact duplicate rows or observation IDs were found in the source candidates, and run IDs do not cross train/validation/test. Similar feature vectors are retained: different real observations can share the same selected features. This is not proof of zero bias. Packet rows are imbalanced even though each label has 15 runs; report macro-F1, balanced accuracy, per-class precision/recall, and confusion matrix. The flow data has only 86 rows, so treat its metrics as exploratory.\n\nThe 55-run collection report does not match these 60-run balanced candidates and was not merged. Existing model metrics were not copied; retrain and report metrics for the exact splits if needed.\n"""
        (temp / "README_V2_FINAL.md").write_text(readme, encoding="utf-8")

        files = sorted(p for p in temp.rglob("*") if p.is_file())
        lines = [f"{sha256(p)}  {p.relative_to(temp).as_posix()}" for p in files]
        (temp / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.rename(temp, out)
    except Exception:
        shutil.rmtree(temp, ignore_errors=True)
        raise

    print(f"FINAL PACKAGE CREATED: {out}")
    for kind in KINDS:
        print(f"{kind.upper()} row counts:", {s: int(results[kind][0][s].shape[0]) for s in SPLITS})
        print(f"{kind.upper()} run counts:", {s: int(results[kind][0][s]['run_id'].nunique()) for s in SPLITS})
    print("Exact duplicate rows: 0; duplicate observation IDs: 0; run leakage: 0")
    print("Run `sha256sum -c SHA256SUMS.txt` from the new package before sending.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
