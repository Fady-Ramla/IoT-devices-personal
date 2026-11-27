#!/usr/bin/env python3
"""Exploratory Flow source ablation using TRAIN and VALIDATION only.

Uses the project's existing feature encoding, equal-run weights, RF/XGBoost
hyperparameters, and mean-probability run aggregation. Never opens test.csv or
reads final_test raw runs. Saves only a JSON report, not models or modified data.
"""
from __future__ import annotations
import argparse
import csv
import json
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

FEATURES = [
    "protocol", "src_port", "dst_port", "packet_count", "byte_count",
    "packet_rate", "byte_rate", "duration_sec", "avg_packet_size",
    "syn_count", "ack_count", "rst_count", "fin_count", "syn_ack_ratio",
    "rst_ratio", "unique_dst_ports", "failed_connection_count",
    "tcp_fraction", "udp_fraction", "icmp_fraction",
]
LABELS = ["Malicious_POST", "Normal", "Port_Scan", "SYN_Flood"]
VARIANTS = ("mixed_all", "packetin_window_only", "switch_flow_stats_all",
            "mixed_nonzero_counters", "switch_flow_stats_nonzero_counters")


def encode(df: pd.DataFrame) -> pd.DataFrame:
    missing = sorted(set(FEATURES) - set(df.columns))
    if missing:
        raise ValueError(f"Missing flow model features: {missing}")
    x = df.loc[:, FEATURES].copy()
    x["protocol"] = (
        x["protocol"].astype(str).str.strip().str.lower()
        .map({"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58,
              "igmp": 2, "other": 0, "unknown": 0})
        .fillna(0)
    )
    for col in x.columns:
        x[col] = pd.to_numeric(x[col], errors="coerce").fillna(0)
    return x


def equal_run_weights(df):
    run_ids = df["run_id"].astype(str)
    counts = run_ids.value_counts()
    weights = run_ids.map(lambda rid: 1.0 / counts[rid]).to_numpy(dtype=float, copy=True)
    weights *= len(weights) / weights.sum()
    return weights


def scores(model, x, frame, encoder):
    from sklearn.metrics import (accuracy_score, classification_report,
                                 confusion_matrix, f1_score)
    y_true = encoder.transform(frame["label"].astype(str))
    y_pred = model.predict(x)
    row = {
        "rows": int(len(frame)),
        "runs": int(frame["run_id"].nunique()),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=range(len(encoder.classes_))).tolist(),
        "classification_report": classification_report(
            y_true, y_pred, labels=range(len(encoder.classes_)),
            target_names=encoder.classes_.tolist(), output_dict=True, zero_division=0),
    }
    probs = pd.DataFrame(model.predict_proba(x), index=frame.index, columns=model.classes_)
    probs["_rid"] = frame["run_id"].astype(str).to_numpy()
    mean_probs = probs.groupby("_rid", sort=True).mean()
    actual = (frame.assign(_rid=frame["run_id"].astype(str))
              .groupby("_rid", sort=True)["label"].first().loc[mean_probs.index])
    pred_id = mean_probs.to_numpy().argmax(axis=1)
    pred = encoder.inverse_transform(pred_id)
    run = {
        "runs": int(len(actual)),
        "runs_by_label": actual.value_counts().reindex(encoder.classes_, fill_value=0).astype(int).to_dict(),
        "accuracy": float(accuracy_score(actual.to_numpy(), pred)),
        "macro_f1": float(f1_score(actual.to_numpy(), pred, labels=encoder.classes_.tolist(), average="macro", zero_division=0)),
        "confusion_matrix": confusion_matrix(actual.to_numpy(), pred, labels=encoder.classes_.tolist()).tolist(),
        "classification_report": classification_report(
            actual.to_numpy(), pred, labels=encoder.classes_.tolist(),
            target_names=encoder.classes_.tolist(), output_dict=True, zero_division=0),
        "predictions": [{"run_id": rid, "actual": str(y), "predicted": str(p)}
                        for rid, y, p in zip(mean_probs.index, actual.to_numpy(), pred)],
    }
    return {"row_level": row, "run_level": run}


def make_variant(frame, name):
    if name == "mixed_all":
        out = frame.copy()
    elif name == "packetin_window_only":
        out = frame[frame["source"] == "packetin_window"].copy()
    elif name == "switch_flow_stats_all":
        out = frame[frame["source"] == "switch_flow_stats"].copy()
    elif name == "mixed_nonzero_counters":
        out = frame[(pd.to_numeric(frame["packet_count"], errors="coerce").fillna(0) > 0)
                    & (pd.to_numeric(frame["byte_count"], errors="coerce").fillna(0) > 0)].copy()
    elif name == "switch_flow_stats_nonzero_counters":
        out = frame[(frame["source"] == "switch_flow_stats")
                    & (pd.to_numeric(frame["packet_count"], errors="coerce").fillna(0) > 0)
                    & (pd.to_numeric(frame["byte_count"], errors="coerce").fillna(0) > 0)].copy()
    else:
        raise ValueError(name)
    return out.reset_index(drop=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--project-root", type=Path, default=Path.cwd())
    ap.add_argument("--output", type=Path,
                    default=Path("New_Datasets/reports/flow_source_ablation_trainval_20261025.json"))
    args = ap.parse_args()
    root = args.project_root.resolve()
    package = root / "New_Datasets/AI_OFFLINE_LEARNING_FINAL_V3_20261025"
    raw_dir = root / "New_Datasets/raw/flow"
    split_manifest = package / "run_split_manifest.csv"
    output = args.output if args.output.is_absolute() else root / args.output
    if output.exists():
        raise SystemExit(f"STOP: output already exists; refusing overwrite: {output}")
    if not split_manifest.is_file():
        raise SystemExit(f"STOP: missing run split manifest: {split_manifest}")

    assignments = pd.read_csv(split_manifest)
    assignments = assignments[assignments["planned_split"].isin(["train", "validation"])]
    if assignments["run_id"].nunique() != 80:
        raise SystemExit(f"STOP: expected 80 train+validation runs, found {assignments['run_id'].nunique()}")
    frames = {"train": [], "validation": []}
    for row in assignments.to_dict("records"):
        split = "validation" if row["planned_split"] == "validation" else "train"
        path = raw_dir / f"{row['run_id']}.csv"
        if not path.is_file():
            raise SystemExit(f"STOP: missing raw flow file for train/validation run: {path}")
        data = pd.read_csv(path)
        if "source" not in data or "run_id" not in data:
            raise SystemExit(f"STOP: raw source/run_id columns missing: {path}")
        if not set(data["run_id"].astype(str)) <= {str(row["run_id"])}:
            raise SystemExit(f"STOP: run_id mismatch in {path}")
        data["label"] = row["label"]
        frames[split].append(data)
    train = pd.concat(frames["train"], ignore_index=True)
    val = pd.concat(frames["validation"], ignore_index=True)
    if set(train["label"].astype(str)) != set(LABELS) or set(val["label"].astype(str)) != set(LABELS):
        raise SystemExit("STOP: train/validation are missing one or more classes")

    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import LabelEncoder
        from xgboost import XGBClassifier
    except ImportError as exc:
        raise SystemExit(f"Required sklearn/xgboost unavailable in the active environment: {exc}")

    encoder = LabelEncoder().fit(train["label"].astype(str))
    y_train = encoder.transform(train["label"].astype(str))
    y_val = encoder.transform(val["label"].astype(str))
    report = {
        "purpose": "Exploratory source ablation; current test set intentionally not read or evaluated.",
        "features": FEATURES,
        "encoding": "Exact existing train_models.py protocol/numeric coercion; missing numeric values fill to 0.",
        "weights": "equal total sample weight per run_id, normalized to mean 1",
        "models": {
            "random_forest": {"n_estimators": 400, "random_state": 42, "n_jobs": -1},
            "xgboost": {"n_estimators": 300, "max_depth": 3, "learning_rate": 0.05,
                        "subsample": 0.9, "colsample_bytree": 0.9, "min_child_weight": 2,
                        "reg_lambda": 1.0, "random_state": 42, "tree_method": "hist"},
        },
        "variants": {},
    }
    for name in VARIANTS:
        tr = make_variant(train, name)
        va = make_variant(val, name)
        for split_name, frame in (("train", tr), ("validation", va)):
            if frame.empty or set(frame["label"].astype(str)) != set(LABELS):
                raise SystemExit(f"STOP: variant {name} {split_name} has no rows or lacks a class")
        xtr, xva = encode(tr), encode(va)
        ytr = encoder.transform(tr["label"].astype(str))
        yva = encoder.transform(va["label"].astype(str))
        weights = equal_run_weights(tr)
        variant_result = {
            "train_rows_by_label": tr["label"].value_counts().to_dict(),
            "train_runs_by_label": tr[["run_id", "label"]].drop_duplicates().groupby("label")["run_id"].nunique().to_dict(),
            "validation_rows_by_label": va["label"].value_counts().to_dict(),
            "validation_runs_by_label": va[["run_id", "label"]].drop_duplicates().groupby("label")["run_id"].nunique().to_dict(),
            "source_row_counts_train": tr["source"].value_counts().to_dict(),
            "source_row_counts_validation": va["source"].value_counts().to_dict(),
            "random_forest": {}, "xgboost": {},
        }
        rf = RandomForestClassifier(n_estimators=400, random_state=42, n_jobs=-1)
        rf.fit(xtr, ytr, sample_weight=weights)
        variant_result["random_forest"] = {
            "train": scores(rf, xtr, tr, encoder),
            "validation": scores(rf, xva, va, encoder),
        }
        xgb = XGBClassifier(
            n_estimators=300, max_depth=3, learning_rate=0.05, subsample=0.9,
            colsample_bytree=0.9, min_child_weight=2, reg_lambda=1.0,
            objective="multi:softprob", eval_metric="mlogloss", random_state=42,
            n_jobs=-1, tree_method="hist",
        )
        xgb.fit(xtr, ytr, sample_weight=weights, eval_set=[(xva, yva)], verbose=False)
        variant_result["xgboost"] = {
            "train": scores(xgb, xtr, tr, encoder),
            "validation": scores(xgb, xva, va, encoder),
        }
        report["variants"][name] = variant_result
        print(f"{name}: train rows/runs={len(tr)}/{tr.run_id.nunique()} "
              f"validation rows/runs={len(va)}/{va.run_id.nunique()}; "
              f"RF val run acc/F1={variant_result['random_forest']['validation']['run_level']['accuracy']:.3f}/"
              f"{variant_result['random_forest']['validation']['run_level']['macro_f1']:.3f}; "
              f"XGB val run acc/F1={variant_result['xgboost']['validation']['run_level']['accuracy']:.3f}/"
              f"{variant_result['xgboost']['validation']['run_level']['macro_f1']:.3f}", flush=True)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Saved train/validation-only report:", output)
    print("No test.csv or final_test raw flow files were opened; no models or source data were modified.")


if __name__ == "__main__":
    main()
