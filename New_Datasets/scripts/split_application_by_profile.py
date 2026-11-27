#!/usr/bin/env python3
"""Split app-v2 windows by whole experiment profile, not individual runs.

A profile is defined only from collection configuration metadata. No profile
metadata is added to model inputs. This is a stricter complement to a run_id
split: every run and window from one exact profile remains in the same split.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd

PROFILE_COLUMNS = [
    "service_name",
    "attack_type",
    "dst_port",
    "rate_value",
    "duration_sec",
]
EXPECTED_LABELS = {"Normal", "Malicious_POST"}


def canonical_profile(row: pd.Series) -> tuple[str, ...]:
    return tuple(str(row.get(column, "")).strip() for column in PROFILE_COLUMNS)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True, help="built app-v2 window CSV")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--validation-profile-fraction", type=float, default=0.20)
    parser.add_argument("--test-profile-fraction", type=float, default=0.20)
    args = parser.parse_args()

    if args.output_dir.exists():
        raise SystemExit(f"refusing to overwrite output directory: {args.output_dir}")
    if not 0 < args.validation_profile_fraction < 1:
        raise SystemExit("validation profile fraction must be in (0, 1)")
    if not 0 < args.test_profile_fraction < 1:
        raise SystemExit("test profile fraction must be in (0, 1)")
    if args.validation_profile_fraction + args.test_profile_fraction >= 1:
        raise SystemExit("validation + test profile fractions must be < 1")

    windows = pd.read_csv(args.input, dtype={"run_id": str, "label": str})
    manifest = pd.read_csv(args.manifest, dtype=str).fillna("")
    for frame, required, name in (
        (windows, {"run_id", "label"}, "window data"),
        (manifest, {"run_id", "label", "status", *PROFILE_COLUMNS}, "manifest"),
    ):
        missing = required - set(frame.columns)
        if missing:
            raise SystemExit(f"{name}: missing columns {sorted(missing)}")
    if windows.empty:
        raise SystemExit("window data is empty")
    if windows["run_id"].isna().any() or windows["label"].isna().any():
        raise SystemExit("window data has missing run_id/label")
    if windows.groupby("run_id")["label"].nunique().gt(1).any():
        raise SystemExit("a run_id maps to multiple labels in windows")
    labels = set(windows["label"].astype(str))
    if labels != EXPECTED_LABELS:
        raise SystemExit(f"expected labels {sorted(EXPECTED_LABELS)}, got {sorted(labels)}")
    if manifest["run_id"].duplicated().any():
        raise SystemExit("manifest has duplicate run_id rows")

    run_labels = windows[["run_id", "label"]].drop_duplicates().copy()
    manifest_index = manifest.set_index("run_id", drop=False)
    missing_ids = set(run_labels["run_id"]) - set(manifest_index.index.astype(str))
    if missing_ids:
        raise SystemExit(f"window runs missing from manifest: {sorted(missing_ids)[:5]}")

    selected_manifest = manifest_index.loc[run_labels["run_id"].tolist()].reset_index(drop=True)
    selected_manifest["run_id"] = selected_manifest["run_id"].astype(str)
    run_labels["run_id"] = run_labels["run_id"].astype(str)
    joined = run_labels.merge(
        selected_manifest[["run_id", "label", "status", *PROFILE_COLUMNS]],
        on="run_id",
        suffixes=("_window", "_manifest"),
        validate="one_to_one",
    )
    if not joined["label_window"].eq(joined["label_manifest"]).all():
        raise SystemExit("window labels disagree with manifest")
    if not joined["status"].eq("completed").all():
        raise SystemExit("all input runs must be completed in the manifest")
    joined["label"] = joined["label_window"]
    joined["profile"] = joined.apply(canonical_profile, axis=1)

    profile_labels = joined.groupby("profile")["label"].nunique()
    if profile_labels.gt(1).any():
        raise SystemExit("an exact collection profile appears under multiple labels; manual grouping required")

    rng = np.random.default_rng(args.seed)
    profile_to_split: dict[tuple[str, ...], str] = {}
    for label in sorted(EXPECTED_LABELS):
        profiles = sorted(joined.loc[joined["label"] == label, "profile"].unique().tolist())
        n_profiles = len(profiles)
        if n_profiles < 3:
            raise SystemExit(
                f"{label}: need at least 3 distinct profiles to create train/validation/test; found {n_profiles}"
            )
        shuffled = np.asarray(profiles, dtype=object)
        rng.shuffle(shuffled)
        n_validation = max(1, int(math.floor(n_profiles * args.validation_profile_fraction + 0.5)))
        n_test = max(1, int(math.floor(n_profiles * args.test_profile_fraction + 0.5)))
        if n_validation + n_test >= n_profiles:
            raise SystemExit(f"{label}: fractions leave no profile for training")
        validation_profiles = shuffled[:n_validation]
        test_profiles = shuffled[n_validation:n_validation + n_test]
        train_profiles = shuffled[n_validation + n_test:]
        profile_to_split.update({tuple(p): "validation" for p in validation_profiles})
        profile_to_split.update({tuple(p): "test" for p in test_profiles})
        profile_to_split.update({tuple(p): "train" for p in train_profiles})

    joined["split"] = joined["profile"].map(profile_to_split)
    if joined["split"].isna().any():
        raise SystemExit("internal error: one or more profiles were not assigned")
    run_to_split = joined.set_index("run_id")["split"]
    windows["split"] = windows["run_id"].astype(str).map(run_to_split)
    if windows["split"].isna().any():
        raise SystemExit("internal error: windows could not be mapped to a split")

    split_profiles = {
        name: set(joined.loc[joined["split"] == name, "profile"])
        for name in ("train", "validation", "test")
    }
    for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")):
        if split_profiles[left] & split_profiles[right]:
            raise SystemExit(f"profile leakage between {left} and {right}")

    args.output_dir.mkdir(parents=True, exist_ok=False)
    for name in ("train", "validation", "test"):
        part = windows[windows["split"] == name].drop(columns="split").copy()
        run_subset = joined[joined["split"] == name]
        if set(part["label"]) != EXPECTED_LABELS:
            raise SystemExit(f"{name}: missing one or more labels")
        part.to_csv(args.output_dir / f"{name}.csv", index=False)
        print(
            f"{name}: windows={len(part)}, runs={part['run_id'].nunique()}, "
            f"profiles={run_subset['profile'].nunique()}, "
            f"runs_per_label={run_subset.groupby('label')['run_id'].nunique().to_dict()}, "
            f"profiles_per_label={run_subset.groupby('label')['profile'].nunique().to_dict()}"
        )

    assignment = joined[["run_id", "label", "status", *PROFILE_COLUMNS, "split"]].copy()
    assignment["profile_id"] = joined["profile"].map(
        lambda profile: json.dumps(profile, ensure_ascii=False, separators=(",", ":"))
    )
    assignment.to_csv(args.output_dir / "profile_assignment.csv", index=False)
    print("PROFILE-LEVEL SPLIT AUDIT: PASS; exact profiles do not cross splits")
    print(f"profile assignment: {args.output_dir / 'profile_assignment.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
