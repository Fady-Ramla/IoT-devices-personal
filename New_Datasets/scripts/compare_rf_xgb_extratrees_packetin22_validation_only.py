#!/usr/bin/env python3
"""Memory-conscious validation-only comparison of 3 classifiers.

Uses the exact 22-feature Ryu packetin_window contract and the same inverse-
observations-per-run weighting, with a 1.30 multiplier for Normal runs.
Evaluates row and run metrics from train/validation only; it never opens test.csv
and saves metrics only (no model artifacts).
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

# Limit common numerical-library thread pools before importing NumPy/sklearn/XGBoost.
for key in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS", "VECLIB_MAXIMUM_THREADS"):
    os.environ.setdefault(key, "1")

import numpy as np
import pandas as pd

FEATURES = [
    "protocol", "src_port", "dst_port", "priority", "packet_count",
    "byte_count", "packet_rate", "byte_rate", "duration_sec",
    "avg_packet_size", "syn_count", "ack_count", "rst_count", "fin_count",
    "syn_ack_ratio", "rst_ratio", "unique_dst_ports",
    "failed_connection_count", "tcp_fraction", "udp_fraction",
    "icmp_fraction", "source",
]
LABELS = ["Malicious_POST", "Normal", "Port_Scan", "SYN_Flood"]
NUMERIC_FEATURES = [c for c in FEATURES if c not in {"protocol", "source"}]
PROTOCOL_MAP = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "igmp": 2, "other": 0, "unknown": 0}
SOURCE_MAP = {"packetin_window": 1}
NORMAL_MULTIPLIER = 1.30


def read_split(path: Path, name: str) -> pd.DataFrame:
    if not path.is_file():
        raise SystemExit(f"STOP: required {name} split not found: {path}")
    df = pd.read_csv(path)
    expected = ["run_id", "observation_id", *FEATURES, "label"]
    if df.columns.tolist() != expected:
        raise SystemExit(f"STOP: {name} columns/order do not match the exact 22-feature contract")
    if df.empty or df[["run_id", "observation_id", "label"]].isna().any().any():
        raise SystemExit(f"STOP: {name} is empty or has missing IDs/labels")
    if df["observation_id"].astype(str).duplicated().any():
        raise SystemExit(f"STOP: duplicate observation_id in {name}")
    if set(df["label"].astype(str)) != set(LABELS):
        raise SystemExit(f"STOP: {name} does not contain all four labels")
    if df.groupby("run_id")["label"].nunique().gt(1).any():
        raise SystemExit(f"STOP: multiple labels assigned to a run in {name}")
    if set(df["source"].astype(str)) != {"packetin_window"}:
        raise SystemExit(f"STOP: unexpected source value in {name}")
    if df[FEATURES].isna().any().any():
        raise SystemExit(f"STOP: missing feature value in {name}")
    return df


def encode_features(df: pd.DataFrame) -> pd.DataFrame:
    x = df.loc[:, FEATURES].copy()
    protocol = x["protocol"].astype(str).str.strip().str.lower()
    unknown_protocols = sorted(set(protocol) - set(PROTOCOL_MAP))
    if unknown_protocols:
        raise SystemExit(f"STOP: unknown protocol value(s): {unknown_protocols}")
    x["protocol"] = protocol.map(PROTOCOL_MAP)
    source = x["source"].astype(str).str.strip()
    unknown_sources = sorted(set(source) - set(SOURCE_MAP))
    if unknown_sources:
        raise SystemExit(f"STOP: unknown source value(s): {unknown_sources}")
    x["source"] = source.map(SOURCE_MAP)
    for col in NUMERIC_FEATURES:
        x[col] = pd.to_numeric(x[col], errors="coerce")
    if x.isna().any().any() or not np.isfinite(x.to_numpy(dtype=float)).all():
        raise SystemExit("STOP: a model feature is nonnumeric, missing, or non-finite")
    return x


def training_weights(df: pd.DataFrame) -> np.ndarray:
    counts = df["run_id"].astype(str).value_counts()
    run_labels = df[["run_id", "label"]].copy()
    run_labels["run_id"] = run_labels["run_id"].astype(str)
    if run_labels.groupby("run_id")["label"].nunique().gt(1).any():
        raise SystemExit("STOP: each run must have exactly one label")
    label_by_run = run_labels.drop_duplicates("run_id").set_index("run_id")["label"].to_dict()
    w = np.asarray([
        (NORMAL_MULTIPLIER if label_by_run[rid] == "Normal" else 1.0) / counts[rid]
        for rid in df["run_id"].astype(str)
    ], dtype=float)
    w *= len(w) / w.sum()
    return w


def scores(model, x: pd.DataFrame, df: pd.DataFrame, encoder) -> dict[str, Any]:
    from sklearn.metrics import accuracy_score, balanced_accuracy_score, classification_report, confusion_matrix, f1_score

    y_true = encoder.transform(df["label"].astype(str))
    y_pred = model.predict(x)
    ids = list(range(len(encoder.classes_)))
    row_report = classification_report(
        y_true, y_pred, labels=ids, target_names=encoder.classes_.tolist(),
        output_dict=True, zero_division=0,
    )
    row = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=ids).tolist(),
        "classification_report": row_report,
    }

    prob = pd.DataFrame(model.predict_proba(x), columns=encoder.classes_)
    prob["run_id"] = df["run_id"].astype(str).to_numpy()
    run_prob = prob.groupby("run_id", sort=True)[encoder.classes_.tolist()].mean()
    actual = (
        df.assign(_rid=df["run_id"].astype(str))
        .groupby("_rid", sort=True)["label"].first()
        .loc[run_prob.index]
    )
    pred_run = encoder.inverse_transform(run_prob.to_numpy().argmax(axis=1))
    y_run = encoder.transform(actual.astype(str))
    pred_run_ids = encoder.transform(pred_run)
    run_report = classification_report(
        y_run, pred_run_ids, labels=ids, target_names=encoder.classes_.tolist(),
        output_dict=True, zero_division=0,
    )
    attack_ids = [i for i, label in enumerate(encoder.classes_) if label != "Normal"]
    actual_attack = np.isin(y_run, attack_ids)
    pred_attack = np.isin(pred_run_ids, attack_ids)
    attack_recall = float((actual_attack & pred_attack).sum() / max(1, actual_attack.sum()))
    run = {
        "runs": int(len(actual)),
        "aggregation": "mean predicted class probability across observations in each run",
        "accuracy": float(accuracy_score(y_run, pred_run_ids)),
        "balanced_accuracy": float(balanced_accuracy_score(y_run, pred_run_ids)),
        "macro_f1": float(f1_score(y_run, pred_run_ids, average="macro", zero_division=0)),
        "attack_vs_normal_recall": attack_recall,
        "normal_recall": float(run_report["Normal"]["recall"]),
        "per_class": {
            label: {
                "precision": float(run_report[label]["precision"]),
                "recall": float(run_report[label]["recall"]),
                "f1": float(run_report[label]["f1-score"]),
                "support_runs": int(run_report[label]["support"]),
            }
            for label in encoder.classes_
        },
        "confusion_matrix": confusion_matrix(y_run, pred_run_ids, labels=ids).tolist(),
        "classification_report": run_report,
    }
    return {"row_level": row, "run_level": run}


def model_specs(seed: int):
    from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
    from xgboost import XGBClassifier

    return [
        ("random_forest", RandomForestClassifier(
            n_estimators=200, max_features="sqrt", min_samples_leaf=2,
            random_state=seed, n_jobs=1,
        )),
        ("xgboost", XGBClassifier(
            n_estimators=200, max_depth=3, learning_rate=0.05,
            min_child_weight=2, subsample=0.9, colsample_bytree=0.9,
            reg_lambda=1.0, objective="multi:softprob", eval_metric="mlogloss",
            num_class=len(LABELS), random_state=seed, n_jobs=1,
            tree_method="hist", max_bin=64,
        )),
        ("extra_trees", ExtraTreesClassifier(
            n_estimators=200, max_features=0.7, min_samples_leaf=2,
            random_state=seed, n_jobs=1,
        )),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split-dir", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20261105)
    args = parser.parse_args()
    if args.output_json.exists():
        raise SystemExit(f"STOP: output exists; refusing overwrite: {args.output_json}")

    try:
        import joblib  # noqa: F401 - verifies expected project environment, but no model is saved
        from sklearn.preprocessing import LabelEncoder
        import xgboost  # noqa: F401
    except ImportError as exc:
        raise SystemExit("STOP: scikit-learn and xgboost must be installed in the dataset environment") from exc

    train = read_split(args.split_dir / "train.csv", "train")
    validation = read_split(args.split_dir / "validation.csv", "validation")
    train_runs = set(train["run_id"].astype(str))
    val_runs = set(validation["run_id"].astype(str))
    if train_runs & val_runs:
        raise SystemExit("STOP: run_id overlap between train and validation")
    if set(train["observation_id"].astype(str)) & set(validation["observation_id"].astype(str)):
        raise SystemExit("STOP: observation_id overlap between train and validation")

    encoder = LabelEncoder().fit(train["label"].astype(str))
    y_train = encoder.transform(train["label"].astype(str))
    x_train = encode_features(train)
    x_val = encode_features(validation)
    weights = training_weights(train)
    print(
        f"Three-model validation comparison: features={len(FEATURES)}, "
        f"train={len(train)} rows/{len(train_runs)} runs, "
        f"validation={len(validation)} rows/{len(val_runs)} runs; "
        f"Normal multiplier={NORMAL_MULTIPLIER:.2f}; model threads=1",
        flush=True,
    )
    print("Test data is not read or scored. Models run sequentially; no models are saved.", flush=True)

    results = {}
    for index, (name, model) in enumerate(model_specs(args.seed), 1):
        print(f"[{index}/3] Fitting {name}...", flush=True)
        model.fit(x_train, y_train, sample_weight=weights)
        metric = scores(model, x_val, validation, encoder)
        results[name] = metric
        run = metric["run_level"]
        print(
            f"{name}: run accuracy={run['accuracy']:.4f}, "
            f"balanced accuracy={run['balanced_accuracy']:.4f}, macro-F1={run['macro_f1']:.4f}, "
            f"attack recall={run['attack_vs_normal_recall']:.4f}, "
            f"Normal recall={run['normal_recall']:.4f}; "
            f"row accuracy={metric['row_level']['accuracy']:.4f}, "
            f"row macro-F1={metric['row_level']['macro_f1']:.4f}",
            flush=True,
        )
        del model

    best_macro = max(results, key=lambda name: (
        results[name]["run_level"]["macro_f1"],
        results[name]["run_level"]["balanced_accuracy"],
        results[name]["run_level"]["attack_vs_normal_recall"],
        results[name]["run_level"]["accuracy"],
    ))
    best_accuracy = max(results, key=lambda name: results[name]["run_level"]["accuracy"])
    payload = {
        "feature_count": len(FEATURES),
        "model_features": FEATURES,
        "categorical_encoding": {"protocol": PROTOCOL_MAP, "source": SOURCE_MAP},
        "training_weighting": "inverse observations per run; multiply Normal-run weights by 1.30; normalize mean weight to 1",
        "normal_multiplier": NORMAL_MULTIPLIER,
        "selection_unit": "run",
        "test_used": False,
        "train_rows": int(len(train)),
        "train_runs": int(len(train_runs)),
        "validation_rows": int(len(validation)),
        "validation_runs": int(len(val_runs)),
        "best_by_run_macro_f1": best_macro,
        "best_by_run_accuracy": best_accuracy,
        "models": results,
        "warning": "Validation results select/compare models; they are not a final unbiased test estimate. Test was not opened.",
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nBest by run Macro-F1: {best_macro}")
    print(f"Best by run Accuracy: {best_accuracy}")
    print("Comparison JSON saved to", args.output_json)
    print("Test data was not read or scored.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
