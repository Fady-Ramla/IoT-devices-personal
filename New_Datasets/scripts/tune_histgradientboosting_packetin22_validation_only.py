#!/usr/bin/env python3
"""Low-memory HistGradientBoosting validation-only trial for Packet-In Flow.

Uses the exact 22-feature Ryu packetin_window contract and the same
inverse-observations-per-run weighting with Normal multiplier 1.30. Trains on
train.csv and selects using validation run-level metrics only. It never opens
test.csv and does not save model files.
"""
from __future__ import annotations

import argparse
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
    labels_by_run = run_labels.drop_duplicates("run_id").set_index("run_id")["label"].to_dict()
    weights = np.asarray([
        (NORMAL_MULTIPLIER if labels_by_run[rid] == "Normal" else 1.0) / counts[rid]
        for rid in df["run_id"].astype(str)
    ], dtype=float)
    weights *= len(weights) / weights.sum()
    return weights


def evaluate(model, x: pd.DataFrame, df: pd.DataFrame, encoder) -> dict[str, Any]:
    from sklearn.metrics import accuracy_score, balanced_accuracy_score, classification_report, confusion_matrix, f1_score

    labels = encoder.classes_.tolist()
    ids = list(range(len(labels)))
    y = encoder.transform(df["label"].astype(str))
    pred = model.predict(x)
    row_report = classification_report(y, pred, labels=ids, target_names=labels,
                                       output_dict=True, zero_division=0)
    row = {
        "accuracy": float(accuracy_score(y, pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y, pred)),
        "macro_f1": float(f1_score(y, pred, average="macro", zero_division=0)),
        "per_class": {
            label: {"precision": float(row_report[label]["precision"]),
                    "recall": float(row_report[label]["recall"]),
                    "f1": float(row_report[label]["f1-score"]),
                    "support_rows": int(row_report[label]["support"])}
            for label in labels
        },
        "confusion_matrix": confusion_matrix(y, pred, labels=ids).tolist(),
    }
    prob = pd.DataFrame(model.predict_proba(x), columns=labels)
    prob["run_id"] = df["run_id"].astype(str).to_numpy()
    run_prob = prob.groupby("run_id", sort=True)[labels].mean()
    actual = (df.assign(_rid=df["run_id"].astype(str))
              .groupby("_rid", sort=True)["label"].first().loc[run_prob.index])
    pred_run = encoder.transform(encoder.inverse_transform(run_prob.to_numpy().argmax(axis=1)))
    y_run = encoder.transform(actual.astype(str))
    run_report = classification_report(y_run, pred_run, labels=ids, target_names=labels,
                                       output_dict=True, zero_division=0)
    attack_ids = [i for i, label in enumerate(labels) if label != "Normal"]
    actual_attack, pred_attack = np.isin(y_run, attack_ids), np.isin(pred_run, attack_ids)
    run = {
        "runs": int(len(actual)),
        "aggregation": "mean predicted class probability across observations in each run",
        "accuracy": float(accuracy_score(y_run, pred_run)),
        "balanced_accuracy": float(balanced_accuracy_score(y_run, pred_run)),
        "macro_f1": float(f1_score(y_run, pred_run, average="macro", zero_division=0)),
        "attack_vs_normal_recall": float((actual_attack & pred_attack).sum() / max(1, actual_attack.sum())),
        "normal_recall": float(run_report["Normal"]["recall"]),
        "per_class": {
            label: {"precision": float(run_report[label]["precision"]),
                    "recall": float(run_report[label]["recall"]),
                    "f1": float(run_report[label]["f1-score"]),
                    "support_runs": int(run_report[label]["support"])}
            for label in labels
        },
        "confusion_matrix": confusion_matrix(y_run, pred_run, labels=ids).tolist(),
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
        from sklearn.ensemble import HistGradientBoostingClassifier
        from sklearn.preprocessing import LabelEncoder
    except ImportError as exc:
        raise SystemExit("STOP: scikit-learn with HistGradientBoostingClassifier is required") from exc

    train = read_split(args.split_dir / "train.csv", "train")
    val = read_split(args.split_dir / "validation.csv", "validation")
    train_runs, val_runs = set(train["run_id"].astype(str)), set(val["run_id"].astype(str))
    if train_runs & val_runs:
        raise SystemExit("STOP: run_id overlap between train and validation")
    if set(train["observation_id"].astype(str)) & set(val["observation_id"].astype(str)):
        raise SystemExit("STOP: observation_id overlap between train and validation")

    encoder = LabelEncoder().fit(train["label"].astype(str))
    y_train = encoder.transform(train["label"].astype(str))
    x_train, x_val = encode_features(train), encode_features(val)
    weights = training_weights(train)
    configs = [
        ("hgb_baseline", {"max_iter": 200, "learning_rate": 0.10, "max_leaf_nodes": 31,
                          "min_samples_leaf": 20, "l2_regularization": 1.0}),
        ("hgb_regularized", {"max_iter": 250, "learning_rate": 0.06, "max_leaf_nodes": 15,
                              "min_samples_leaf": 30, "l2_regularization": 2.0}),
    ]
    print(
        f"HistGradientBoosting validation-only trial: features=22, "
        f"train={len(train)} rows/{len(train_runs)} runs, val={len(val)} rows/{len(val_runs)} runs, "
        f"Normal multiplier={NORMAL_MULTIPLIER:.2f}; early_stopping=False",
        flush=True,
    )
    print("Test data is not read or scored. Two configurations run sequentially.", flush=True)

    results = {}
    for i, (name, params) in enumerate(configs, 1):
        model = HistGradientBoostingClassifier(
            **params, early_stopping=False, random_state=args.seed,
        )
        print(f"[{i}/{len(configs)}] Fitting {name}...", flush=True)
        model.fit(x_train, y_train, sample_weight=weights)
        result = evaluate(model, x_val, val, encoder)
        results[name] = {"parameters": params, "validation": result}
        r = result["run_level"]
        print(
            f"{name}: run accuracy={r['accuracy']:.4f}, balanced accuracy={r['balanced_accuracy']:.4f}, "
            f"macro-F1={r['macro_f1']:.4f}, attack recall={r['attack_vs_normal_recall']:.4f}, "
            f"Normal recall={r['normal_recall']:.4f}; row accuracy={result['row_level']['accuracy']:.4f}",
            flush=True,
        )
        del model

    best = max(results, key=lambda name: (
        results[name]["validation"]["run_level"]["macro_f1"],
        results[name]["validation"]["run_level"]["balanced_accuracy"],
        results[name]["validation"]["run_level"]["attack_vs_normal_recall"],
        results[name]["validation"]["run_level"]["accuracy"],
    ))
    payload = {
        "model_family": "HistGradientBoostingClassifier",
        "feature_count": len(FEATURES),
        "model_features": FEATURES,
        "categorical_encoding": {"protocol": PROTOCOL_MAP, "source": SOURCE_MAP},
        "training_weighting": "inverse observations per run; multiply Normal run weights by 1.30",
        "normal_multiplier": NORMAL_MULTIPLIER,
        "selection_unit": "run",
        "test_used": False,
        "train_rows": int(len(train)),
        "train_runs": int(len(train_runs)),
        "validation_rows": int(len(val)),
        "validation_runs": int(len(val_runs)),
        "best_by_run_macro_f1": best,
        "models": results,
        "warning": "Validation compares configurations; test was not read or scored.",
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nBest HistGradientBoosting configuration by run Macro-F1: {best}")
    print("Comparison JSON saved to", args.output_json)
    print("Test data was not read or scored.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
