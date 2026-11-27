#!/usr/bin/env python3
"""Read-only accuracy, duplication, bias and overfit diagnostics for final V3.
Does not modify data, models, metrics, or split assignments.
"""
from __future__ import annotations
import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

LABELS = ("Malicious_POST", "Normal", "Port_Scan", "SYN_Flood")
SPLITS = ("train", "validation", "test")


def load_csv(path: Path):
    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError(f"No CSV header: {path}")
        rows = list(reader)
        return reader.fieldnames, rows


def fmt(x):
    if isinstance(x, (int, float)):
        return f"{x:.4f}"
    return str(x)


def walk_metrics(obj, path=()):
    if isinstance(obj, dict):
        if "confusion_matrix" in obj or "classification_report" in obj or "accuracy" in obj:
            yield path, obj
        for key, value in obj.items():
            if str(key) in ("classification_report", "report"):
                continue
            if isinstance(value, (dict, list)):
                yield from walk_metrics(value, path + (str(key),))
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            if isinstance(value, (dict, list)):
                yield from walk_metrics(value, path + (str(i),))


def show_metrics(path: Path):
    print(f"\n=== MODEL METRICS: {path.parent.name.upper()} ===")
    if not path.is_file():
        print("Metrics file missing:", path)
        return
    data = json.loads(path.read_text(encoding="utf-8"))
    nodes = list(walk_metrics(data))
    if not nodes:
        print("No standard accuracy/confusion/report nodes found; top-level keys:", list(data) if isinstance(data, dict) else type(data).__name__)
        return
    seen = set()
    for route, node in nodes:
        key = (route, id(node))
        if key in seen:
            continue
        seen.add(key)
        report = node.get("classification_report") or node.get("report") or {}
        acc = node.get("accuracy", report.get("accuracy") if isinstance(report, dict) else None)
        if acc is None and "confusion_matrix" in node:
            cm = node["confusion_matrix"]
            try:
                total = sum(sum(float(x) for x in row) for row in cm)
                correct = sum(float(cm[i][i]) for i in range(min(len(cm), min(len(row) for row in cm))))
                if total:
                    acc = correct / total
            except (TypeError, ValueError, IndexError):
                pass
        macro = node.get("macro_f1", node.get("f1_macro"))
        if macro is None and isinstance(report, dict):
            macro = (report.get("macro avg") or {}).get("f1-score")
        if acc is None and macro is None and "confusion_matrix" not in node:
            continue
        print("level:", ".".join(route) or "root")
        print("  accuracy:", fmt(acc) if acc is not None else "not recorded")
        print("  macro-F1:", fmt(macro) if macro is not None else "not recorded")
        if "confusion_matrix" in node:
            print("  confusion_matrix:", json.dumps(node["confusion_matrix"]))
        if isinstance(report, dict):
            for label in LABELS:
                s = report.get(label)
                if isinstance(s, dict):
                    print("  %-15s precision=%s recall=%s F1=%s support=%s" % (
                        label, fmt(s.get("precision")), fmt(s.get("recall")),
                        fmt(s.get("f1-score")), fmt(s.get("support"))))


def audit_level(base: Path, level: str, run_splits: dict[str, str]):
    all_rows = {}
    all_headers = {}
    row_counts = {}
    run_counts = {}
    for split in SPLITS:
        path = base / f"{level}_splits" / f"{split}.csv"
        headers, rows = load_csv(path)
        all_headers[split], all_rows[split] = headers, rows
        labels = Counter(r.get("label", "") for r in rows)
        runs = defaultdict(set)
        for r in rows:
            runs[r.get("label", "")].add(r.get("run_id", ""))
        row_counts[split] = labels
        run_counts[split] = {label: len(ids) for label, ids in runs.items()}
        print(f"\n{level.upper()} {split}: rows={len(rows)} labels={dict(labels)}")
        print("  distinct runs by label:", run_counts[split])

    # Exact rows, observation IDs, run leakage, and repeated feature vectors.
    exact = set()
    obs_owner = {}
    run_owner = {}
    run_labels = {}
    feature_labels = defaultdict(set)
    feature_splits = defaultdict(set)
    repeated_feature_label = Counter()
    duplicate_exact = 0
    duplicate_obs = []
    leakage = []
    feature_cols = [c for c in all_headers["train"] if c not in ("run_id", "observation_id", "label", "label_status")]
    vectors_by_split = {s: set() for s in SPLITS}
    categorical = {"dst_port", "protocol"} & set(feature_cols)
    cat_counts = {c: {label: Counter() for label in LABELS} for c in categorical}

    for split in SPLITS:
        rows = all_rows[split]
        header = all_headers[split]
        for r in rows:
            sig = tuple(r.get(c, "") for c in header)
            if sig in exact:
                duplicate_exact += 1
            exact.add(sig)
            obs = r.get("observation_id", "")
            prev = obs_owner.get(obs)
            if not obs or prev is not None:
                duplicate_obs.append((obs, prev, split))
            else:
                obs_owner[obs] = split
            run = r.get("run_id", "")
            expected_split = run_splits.get(run)
            expected_split_name = "test" if expected_split == "final_test" else expected_split
            if expected_split_name != split:
                raise SystemExit(f"STOP: run {run} appears in {split}, but the predeclared split is {expected_split}.")
            prior_label = run_labels.get(run)
            if prior_label is not None and prior_label != r.get("label", ""):
                raise SystemExit(f"STOP: run {run} has mixed labels: {prior_label} and {r.get('label')}.")
            run_labels[run] = r.get("label", "")
            prev_split = run_owner.get(run)
            if prev_split is not None and prev_split != split:
                leakage.append((run, prev_split, split))
            else:
                run_owner[run] = split
            vector = tuple(r.get(c, "") for c in feature_cols)
            vectors_by_split[split].add(vector)
            feature_labels[vector].add(r.get("label", ""))
            feature_splits[vector].add(split)
            repeated_feature_label[(vector, r.get("label", ""))] += 1
            for col in categorical:
                cat_counts[col].setdefault(r.get("label", ""), Counter())[r.get(col, "")] += 1

    duplicate_vector_groups = sum(1 for n in Counter(
        tuple(r.get(c, "") for c in feature_cols) for s in SPLITS for r in all_rows[s]
    ).values() if n > 1)
    conflicting_vector_groups = sum(1 for labs in feature_labels.values() if len(labs) > 1)
    shared_train_test = vectors_by_split["train"] & vectors_by_split["test"]
    shared_train_test_conflict = sum(1 for v in shared_train_test if len(feature_labels[v]) > 1)

    print(f"\n{level.upper()} duplication/leakage audit:")
    print("  exact full-row duplicates (including IDs):", duplicate_exact)
    print("  duplicate/missing observation IDs across splits:", len(duplicate_obs))
    print("  run IDs crossing splits:", len(leakage))
    print("  distinct repeated feature-vector groups (natural repeats retained):", duplicate_vector_groups)
    print("  feature vectors associated with multiple labels:", conflicting_vector_groups)
    print("  feature vectors shared train/test:", len(shared_train_test),
          "| shared with conflicting labels:", shared_train_test_conflict)

    for col in sorted(categorical):
        print(f"  {col} distinct values by label (train only):")
        for label in LABELS:
            counts = cat_counts[col].get(label, Counter())
            print(f"    {label}: distinct={len(counts)} top={counts.most_common(5)}")

    if duplicate_exact or duplicate_obs or leakage:
        raise SystemExit(f"STOP: exact-duplicate/ID/leakage check failed for {level}.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = args.project_root.resolve()
    package = root / "New_Datasets/AI_OFFLINE_LEARNING_FINAL_V3_20261025"
    models = package / "models/final_v3_20261025"
    split_manifest_path = package / "run_split_manifest.csv"
    if not split_manifest_path.is_file():
        raise SystemExit(f"STOP: split manifest missing: {split_manifest_path}")

    with split_manifest_path.open("r", newline="", encoding="utf-8") as f:
        assignments = list(csv.DictReader(f))
    run_splits = {r["run_id"]: r["planned_split"] for r in assignments}
    if len(run_splits) != 160:
        raise SystemExit(f"STOP: expected 160 unique run assignments, got {len(run_splits)}")
    print("=== RUN-LEVEL SPLIT COUNTS ===")
    for split in ("train", "validation", "final_test"):
        rows = [r for r in assignments if r["planned_split"] == split]
        print(split, len(rows), dict(Counter(r["label"] for r in rows)))
    if set(run_splits.values()) != set(("train", "validation", "final_test")):
        raise SystemExit("STOP: unexpected split names")

    for level in ("packet", "flow"):
        audit_level(package, level, run_splits)
        show_metrics(models / level / "training_metrics.json")

    print("\n=== OVERFITTING / BIAS INTERPRETATION LIMITS ===")
    print("Compare train/validation/test metrics only if train metrics are recorded; this script prints every available split.")
    print("A low test score is not proof of overfitting. Check train-to-validation gap and per-class errors.")
    print("Balanced runs do not guarantee balanced rows or absence of shortcut features; inspect label-specific port/protocol distributions above.")
    print("Repeated feature vectors are reported, not removed: repeated packets can be legitimate observations.")
    print("Use final_test only for final reporting, not tuning.")


if __name__ == "__main__":
    main()
