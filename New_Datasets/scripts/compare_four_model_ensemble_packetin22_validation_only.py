#!/usr/bin/env python3
"""Validation-only soft-voting ensemble test for the exact 22 Ryu features.

Fits RF, XGBoost, ExtraTrees, and HistGradientBoosting sequentially with the
same run-based sample weights and Normal multiplier 1.30. Stores only validation
probabilities between fits, not four model objects. Compares individual models
with equal-probability and fixed weighted soft-voting ensembles. Never opens
 test.csv and never saves trained model artifacts.
"""
from __future__ import annotations

import argparse
import gc
import json
import os
from pathlib import Path
from typing import Any

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
        raise SystemExit(f"STOP: {name} columns/order do not match exact 22-feature contract")
    if df.empty or df[["run_id", "observation_id", "label"]].isna().any().any():
        raise SystemExit(f"STOP: {name} is empty or has missing IDs/labels")
    if df["observation_id"].astype(str).duplicated().any():
        raise SystemExit(f"STOP: duplicate observation_id in {name}")
    if set(df["label"].astype(str)) != set(LABELS):
        raise SystemExit(f"STOP: {name} does not contain all four labels")
    if df.groupby("run_id")["label"].nunique().gt(1).any():
        raise SystemExit(f"STOP: a run_id has multiple labels in {name}")
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
        raise SystemExit("STOP: each run must have one label")
    labels_by_run = run_labels.drop_duplicates("run_id").set_index("run_id")["label"].to_dict()
    weights = np.asarray([
        (NORMAL_MULTIPLIER if labels_by_run[rid] == "Normal" else 1.0) / counts[rid]
        for rid in df["run_id"].astype(str)
    ], dtype=float)
    weights *= len(weights) / weights.sum()
    return weights


def evaluate_probabilities(probabilities: np.ndarray, df: pd.DataFrame, class_names: list[str]) -> dict[str, Any]:
    from sklearn.metrics import accuracy_score, balanced_accuracy_score, classification_report, confusion_matrix, f1_score

    class_ids = list(range(len(class_names)))
    y_true = np.asarray([class_names.index(label) for label in df["label"].astype(str)], dtype=int)
    y_pred = probabilities.argmax(axis=1)
    row_report = classification_report(y_true, y_pred, labels=class_ids,
                                       target_names=class_names, output_dict=True, zero_division=0)
    row = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "per_class": {
            label: {"precision": float(row_report[label]["precision"]),
                    "recall": float(row_report[label]["recall"]),
                    "f1": float(row_report[label]["f1-score"]),
                    "support_rows": int(row_report[label]["support"])}
            for label in class_names
        },
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=class_ids).tolist(),
    }

    prob_frame = pd.DataFrame(probabilities, columns=class_names)
    prob_frame["run_id"] = df["run_id"].astype(str).to_numpy()
    run_prob = prob_frame.groupby("run_id", sort=True)[class_names].mean()
    actual = (df.assign(_rid=df["run_id"].astype(str))
              .groupby("_rid", sort=True)["label"].first().loc[run_prob.index])
    y_run = np.asarray([class_names.index(label) for label in actual.astype(str)], dtype=int)
    pred_run = run_prob.to_numpy().argmax(axis=1)
    run_report = classification_report(y_run, pred_run, labels=class_ids,
                                       target_names=class_names, output_dict=True, zero_division=0)
    attack_ids = [i for i, label in enumerate(class_names) if label != "Normal"]
    actual_attack, predicted_attack = np.isin(y_run, attack_ids), np.isin(pred_run, attack_ids)
    run = {
        "runs": int(len(actual)),
        "aggregation": "average window probabilities within run",
        "accuracy": float(accuracy_score(y_run, pred_run)),
        "balanced_accuracy": float(balanced_accuracy_score(y_run, pred_run)),
        "macro_f1": float(f1_score(y_run, pred_run, average="macro", zero_division=0)),
        "attack_vs_normal_recall": float((actual_attack & predicted_attack).sum() / max(1, actual_attack.sum())),
        "normal_recall": float(run_report["Normal"]["recall"]),
        "per_class": {
            label: {"precision": float(run_report[label]["precision"]),
                    "recall": float(run_report[label]["recall"]),
                    "f1": float(run_report[label]["f1-score"]),
                    "support_runs": int(run_report[label]["support"])}
            for label in class_names
        },
        "confusion_matrix": confusion_matrix(y_run, pred_run, labels=class_ids).tolist(),
    }
    return {"row_level": row, "run_level": run}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split-dir", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20261105)
    args = parser.parse_args()
    if args.output_json.exists():
        raise SystemExit(f"STOP: output exists; refusing overwrite: {args.output_json}")

    try:
        from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier, HistGradientBoostingClassifier
        from sklearn.preprocessing import LabelEncoder
        from xgboost import XGBClassifier
    except ImportError as exc:
        raise SystemExit("STOP: scikit-learn and xgboost are required in the dataset environment") from exc

    train = read_split(args.split_dir / "train.csv", "train")
    validation = read_split(args.split_dir / "validation.csv", "validation")
    train_runs, val_runs = set(train["run_id"].astype(str)), set(validation["run_id"].astype(str))
    if train_runs & val_runs:
        raise SystemExit("STOP: run_id overlap between train and validation")
    if set(train["observation_id"].astype(str)) & set(validation["observation_id"].astype(str)):
        raise SystemExit("STOP: observation_id overlap between train and validation")

    encoder = LabelEncoder().fit(train["label"].astype(str))
    class_names = encoder.classes_.tolist()
    y_train = encoder.transform(train["label"].astype(str))
    x_train, x_val = encode_features(train), encode_features(validation)
    sample_weight = training_weights(train)

    def build_models():
        return [
            ("random_forest", RandomForestClassifier(
                n_estimators=200, max_features="sqrt", min_samples_leaf=2,
                random_state=args.seed, n_jobs=1,
            )),
            ("xgboost", XGBClassifier(
                n_estimators=200, max_depth=3, learning_rate=0.05,
                min_child_weight=2, subsample=0.9, colsample_bytree=0.9,
                reg_lambda=1.0, objective="multi:softprob", eval_metric="mlogloss",
                num_class=len(class_names), random_state=args.seed, n_jobs=1,
                tree_method="hist", max_bin=64,
            )),
            ("extra_trees", ExtraTreesClassifier(
                n_estimators=200, max_features=0.7, min_samples_leaf=2,
                random_state=args.seed, n_jobs=1,
            )),
            ("hist_gradient_boosting", HistGradientBoostingClassifier(
                max_iter=250, learning_rate=0.06, max_leaf_nodes=15,
                min_samples_leaf=30, l2_regularization=2.0,
                early_stopping=False, random_state=args.seed,
            )),
        ]

    print(
        f"Four-model ensemble validation: 22 features, train={len(train)} rows/{len(train_runs)} runs, "
        f"validation={len(validation)} rows/{len(val_runs)} runs; Normal multiplier=1.30; one model at a time",
        flush=True,
    )
    print("Test data is not read or scored. Only validation probability arrays are retained.", flush=True)

    prob_by_model = {}
    individual_metrics = {}
    for index, (name, model) in enumerate(build_models(), 1):
        print(f"[{index}/4] Fitting {name}...", flush=True)
        model.fit(x_train, y_train, sample_weight=sample_weight)
        probabilities = model.predict_proba(x_val)
        # Reorder model probabilities to the shared LabelEncoder class order.
        model_classes = [int(value) for value in model.classes_]
        order = [model_classes.index(i) for i in range(len(class_names))]
        probabilities = np.asarray(probabilities[:, order], dtype=np.float32)
        prob_by_model[name] = probabilities
        individual_metrics[name] = evaluate_probabilities(probabilities, validation, class_names)
        r = individual_metrics[name]["run_level"]
        print(
            f"{name}: run accuracy={r['accuracy']:.4f}, balanced accuracy={r['balanced_accuracy']:.4f}, "
            f"macro-F1={r['macro_f1']:.4f}, attack recall={r['attack_vs_normal_recall']:.4f}, "
            f"Normal recall={r['normal_recall']:.4f}",
            flush=True,
        )
        del model, probabilities
        gc.collect()

    equal_weights = {name: 0.25 for name in prob_by_model}
    weighted = {"random_forest": 0.30, "xgboost": 0.10, "extra_trees": 0.35, "hist_gradient_boosting": 0.25}
    ensemble_specs = {"soft_vote_equal": equal_weights, "soft_vote_xgb_downweighted": weighted}
    ensemble_metrics = {}
    for name, weights in ensemble_specs.items():
        combined = sum(prob_by_model[model] * weights[model] for model in prob_by_model)
        ensemble_metrics[name] = {
            "weights": weights,
            **evaluate_probabilities(combined, validation, class_names),
        }
        r = ensemble_metrics[name]["run_level"]
        print(
            f"{name}: run accuracy={r['accuracy']:.4f}, balanced accuracy={r['balanced_accuracy']:.4f}, "
            f"macro-F1={r['macro_f1']:.4f}, attack recall={r['attack_vs_normal_recall']:.4f}, "
            f"Normal recall={r['normal_recall']:.4f}",
            flush=True,
        )

    all_results = dict(individual_metrics)
    all_results.update(ensemble_metrics)
    best = max(all_results, key=lambda key: (
        all_results[key]["run_level"]["macro_f1"],
        all_results[key]["run_level"]["balanced_accuracy"],
        all_results[key]["run_level"]["attack_vs_normal_recall"],
        all_results[key]["run_level"]["accuracy"],
    ))
    payload = {
        "feature_count": len(FEATURES),
        "model_features": FEATURES,
        "categorical_encoding": {"protocol": PROTOCOL_MAP, "source": SOURCE_MAP},
        "training_weighting": "inverse observations per run; Normal multiplier=1.30; normalized mean weight 1",
        "selection_unit": "run",
        "ensemble_method": "soft voting on per-window class probabilities; then mean probabilities within each run",
        "ensemble_weights": ensemble_specs,
        "test_used": False,
        "models": individual_metrics,
        "ensembles": ensemble_metrics,
        "best_validation_candidate_by_run_macro_f1": best,
        "warning": "Validation results are for candidate comparison only; test was not opened. Weighted ensemble weights are a fixed exploratory choice, not learned from test.",
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nBest validation candidate by run Macro-F1: {best}")
    print("Comparison JSON saved to", args.output_json)
    print("Test data was not read or scored.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
