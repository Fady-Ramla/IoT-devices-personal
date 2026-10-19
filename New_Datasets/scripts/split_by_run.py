#!/usr/bin/env python3
"""Split a labeled dataset by run_id, never by individual rows."""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def allocate(grouped: pd.DataFrame, seed: int, train: float, val: float) -> tuple[set[str], set[str], set[str]]:
    rng = __import__("numpy").random.default_rng(seed)
    train_ids: list[str] = []
    val_ids: list[str] = []
    test_ids: list[str] = []
    for _, group in grouped.groupby("label", sort=True):
        ids = group["run_id"].astype(str).drop_duplicates().to_numpy()
        rng.shuffle(ids)
        n = len(ids)
        n_train = max(1, int(round(n * train))) if n >= 3 else int(n * train)
        n_val = max(1, int(round(n * val))) if n >= 3 else int(n * val)
        if n_train + n_val >= n and n >= 3:
            n_val = max(1, n - n_train - 1)
        train_ids.extend(ids[:n_train])
        val_ids.extend(ids[n_train:n_train + n_val])
        test_ids.extend(ids[n_train + n_val:])
    return set(train_ids), set(val_ids), set(test_ids)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--train", type=float, default=0.70)
    p.add_argument("--val", type=float, default=0.15)
    args = p.parse_args()
    if args.train <= 0 or args.val < 0 or args.train + args.val >= 1:
        raise SystemExit("require 0 < train, 0 <= val, and train + val < 1")
    df = pd.read_csv(args.input)
    required = {"run_id", "label"}
    missing = required - set(df.columns)
    if missing:
        raise SystemExit(f"missing columns: {sorted(missing)}")
    grouped = df[["run_id", "label"]].drop_duplicates()
    train_ids, val_ids, test_ids = allocate(grouped, args.seed, args.train, args.val)
    if train_ids & val_ids or train_ids & test_ids or val_ids & test_ids:
        raise SystemExit("internal error: run_id overlap between splits")
    splits = {"train": train_ids, "validation": val_ids, "test": test_ids}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, ids in splits.items():
        part = df[df["run_id"].astype(str).isin(ids)].copy()
        part.to_csv(args.output_dir / f"{name}.csv", index=False)
        print(f"{name}: {len(part)} rows, {part['run_id'].nunique()} runs, labels={part['label'].value_counts().to_dict()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
