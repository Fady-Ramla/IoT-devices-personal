#!/usr/bin/env python3
"""Validation-only run-level tuning for the exact 22-feature Ryu contract.

Compares ExtraTrees configurations and Normal run-weight multipliers. It reads
train.csv and validation.csv only; test.csv is never opened. Run probabilities
are averaged over observations, matching the operational run-level unit.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

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


def read_split(path: Path, name: str) -> pd.DataFrame:
    if not path.is_file():
        raise SystemExit(f"STOP: required {name} split not found: {path}")
    df = pd.read_csv(path)
    required = {"run_id", "observation_id", "label", *FEATURES}
    missing = sorted(required - set(df.columns))
    if missing:
        raise SystemExit(f"STOP: {name} split missing fields: {missing}")
    if df.empty:
        raise SystemExit(f"STOP: {name} split is empty")
    for col in ("run_id", "observation_id", "label"):
        if df[col].isna().any() or df[col].astype(str).str.strip().eq("").any():
            raise SystemExit(f"STOP: {name} has blank {col}")
    if set(df["label"].astype(str)) != set(LABELS):
        raise SystemExit(f"STOP: {name} labels do not match the four-class contract")
    if df["observation_id"].astype(str).duplicated().any():
        raise SystemExit(f"STOP: duplicate observation_id in {name}")
    if df.groupby("run_id")["label"].nunique().gt(1).any():
        raise SystemExit(f"STOP: one run_id has multiple labels in {name}")
    if set(df["source"].astype(str)) != {"packetin_window"}:
        raise SystemExit(f"STOP: {name} contains source other than packetin_window")
    return df


def encode_features(df: pd.DataFrame) -> pd.DataFrame:
    x = df.loc[:, FEATURES].copy()
    protocol = x["protocol"].astype(str).str.strip().str.lower()
    unknown_protocols = sorted(set(protocol) - set(PROTOCOL_MAP))
    if unknown_protocols:
        raise SystemExit(f"STOP: protocol value(s) missing from fixed encoder: {unknown_protocols}")
    x["protocol"] = protocol.map(PROTOCOL_MAP)
    source = x["source"].astype(str).str.strip()
    unknown_sources = sorted(set(source) - set(SOURCE_MAP))
    if unknown_sources:
        raise SystemExit(f"STOP: source value(s) missing from fixed encoder: {unknown_sources}")
    x["source"] = source.map(SOURCE_MAP)
    for col in NUMERIC_FEATURES:
        x[col] = pd.to_numeric(x[col], errors="coerce")
    if x.isna().any().any() or not np.isfinite(x.to_numpy(dtype=float)).all():
        bad = x.columns[x.isna().any()].tolist()
        raise SystemExit(f"STOP: invalid/missing numeric feature(s): {bad}")
    return x


def weights_for_runs(df: pd.DataFrame, normal_multiplier: float) -> np.ndarray:
    counts = df["run_id"].astype(str).value_counts()
    run_labels = df[["run_id", "label"]].copy()
    run_labels["run_id"] = run_labels["run_id"].astype(str)
    if run_labels.groupby("run_id")["label"].nunique().gt(1).any():
        raise SystemExit("STOP: run-level weights require a single label per run")
    label_by_run = run_labels.drop_duplicates("run_id").set_index("run_id")["label"].to_dict()
    weights = np.asarray([
        (normal_multiplier if label_by_run[rid] == "Normal" else 1.0) / counts[rid]
        for rid in df["run_id"].astype(str)
    ], dtype=float)
    weights *= len(weights) / weights.sum()
    return weights


def metrics_for(model, x: pd.DataFrame, df: pd.DataFrame, encoder) -> dict[str, Any]:
    from sklearn.metrics import accuracy_score, balanced_accuracy_score, classification_report, confusion_matrix, f1_score

    y_true = encoder.transform(df["label"].astype(str))
    y_pred = model.predict(x)
    class_ids = list(range(len(encoder.classes_)))
    row_metrics = {
        "rows": int(len(df)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=class_ids).tolist(),
        "classification_report": classification_report(
            y_true, y_pred, labels=class_ids, target_names=encoder.classes_.tolist(),
            output_dict=True, zero_division=0,
        ),
    }
    probabilities = pd.DataFrame(model.predict_proba(x), columns=encoder.classes_)
    probabilities["run_id"] = df["run_id"].astype(str).to_numpy()
    run_probabilities = probabilities.groupby("run_id", sort=True)[encoder.classes_.tolist()].mean()
    actual = (
        df.assign(_run_id=df["run_id"].astype(str))
        .groupby("_run_id", sort=True)["label"].first()
        .loc[run_probabilities.index]
    )
    pred_run = encoder.inverse_transform(run_probabilities.to_numpy().argmax(axis=1))
    y_run = encoder.transform(actual.astype(str))
    pred_run_ids = encoder.transform(pred_run)
    run_metrics = {
        "runs": int(len(actual)),
        "aggregation": "mean predicted class probability across observations in each run",
        "accuracy": float(accuracy_score(y_run, pred_run_ids)),
        "balanced_accuracy": float(balanced_accuracy_score(y_run, pred_run_ids)),
        "macro_f1": float(f1_score(y_run, pred_run_ids, average="macro", zero_division=0)),
        "confusion_matrix": confusion_matrix(y_run, pred_run_ids, labels=class_ids).tolist(),
        "classification_report": classification_report(
            y_run, pred_run_ids, labels=class_ids, target_names=encoder.classes_.tolist(),
            output_dict=True, zero_division=0,
        ),
    }
    return {"row_level": row_metrics, "run_level": run_metrics}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20261105)
    args = parser.parse_args()
    if args.output_dir.exists():
        raise SystemExit(f"STOP: output already exists; refusing overwrite: {args.output_dir}")
    try:
        import joblib
        from sklearn.ensemble import ExtraTreesClassifier
        from sklearn.preprocessing import LabelEncoder
    except ImportError as exc:
        raise SystemExit("Required packages: scikit-learn and joblib in the active dataset environment") from exc

    train = read_split(args.split_dir / "train.csv", "train")
    validation = read_split(args.split_dir / "validation.csv", "validation")
    train_runs = set(train["run_id"].astype(str))
    val_runs = set(validation["run_id"].astype(str))
    if train_runs & val_runs:
        raise SystemExit("STOP: run_id leakage between train and validation")
    train_ids = set(train["observation_id"].astype(str))
    val_ids = set(validation["observation_id"].astype(str))
    if train_ids & val_ids:
        raise SystemExit("STOP: observation_id overlap between train and validation")

    encoder = LabelEncoder().fit(train["label"].astype(str))
    y_train = encoder.transform(train["label"].astype(str))
    x_train = encode_features(train)
    x_val = encode_features(validation)
    print(
        f"22-feature run-level tuning: train={len(train)} rows/{len(train_runs)} runs; "
        f"validation={len(validation)} rows/{len(val_runs)} runs",
        flush=True,
    )
    print("Test data is not read, scored, or used for selection.", flush=True)
    print("Feature contract retained: " + ", ".join(FEATURES), flush=True)

    configs = [
        ("et_baseline", {"n_estimators": 400, "max_features": "sqrt", "min_samples_leaf": 1}),
        ("et_regularized", {"n_estimators": 600, "max_features": 0.7, "min_samples_leaf": 2}),
    ]
    multipliers = (1.0, 1.30, 1.50)
    candidates = []
    selected_model = None
    selected_spec = None
    selected_key = None

    total = len(configs) * len(multipliers)
    index = 0
    for config_name, params in configs:
        for multiplier in multipliers:
            index += 1
            model = ExtraTreesClassifier(**params, random_state=args.seed, n_jobs=-1)
            weights = weights_for_runs(train, multiplier)
            model.fit(x_train, y_train, sample_weight=weights)
            metrics = metrics_for(model, x_val, validation, encoder)
            run = metrics["run_level"]
            malicious_recall = float(run["classification_report"]["Malicious_POST"]["recall"])
            key = (run["macro_f1"], run["balanced_accuracy"], run["accuracy"], malicious_recall)
            name = f"{config_name}__normal_{multiplier:.2f}"
            spec = {"name": name, "parameters": params, "normal_multiplier": multiplier}
            candidates.append({**spec, "validation": metrics})
            print(
                f"[{index}/{total}] {name}: run accuracy={run['accuracy']:.4f}, "
                f"balanced accuracy={run['balanced_accuracy']:.4f}, run macro-F1={run['macro_f1']:.4f}, "
                f"Malicious_POST recall={malicious_recall:.4f}; "
                f"row accuracy={metrics['row_level']['accuracy']:.4f}, "
                f"row macro-F1={metrics['row_level']['macro_f1']:.4f}",
                flush=True,
            )
            if selected_key is None or key > selected_key:
                selected_key = key
                selected_spec = spec
                selected_model = model

    assert selected_model is not None and selected_spec is not None
    candidates.sort(
        key=lambda c: (
            c["validation"]["run_level"]["macro_f1"],
            c["validation"]["run_level"]["balanced_accuracy"],
            c["validation"]["run_level"]["accuracy"],
            c["validation"]["run_level"]["classification_report"]["Malicious_POST"]["recall"],
        ),
        reverse=True,
    )
    args.output_dir.mkdir(parents=True, exist_ok=False)
    joblib.dump(selected_model, args.output_dir / "validation_selected_extratrees.joblib")
    joblib.dump(encoder, args.output_dir / "label_encoder.joblib")
    (args.output_dir / "feature_contract.json").write_text(
        json.dumps({
            "features": FEATURES,
            "categorical_encoding": {"protocol": PROTOCOL_MAP, "source": SOURCE_MAP},
            "target": "label",
            "group_column": "run_id",
        }, indent=2), encoding="utf-8"
    )
    best_validation = next(c["validation"] for c in candidates if c["name"] == selected_spec["name"])
    payload = {
        "model_family": "ExtraTreesClassifier",
        "model_selection_unit": "run",
        "selection_rule": "highest validation run-level Macro-F1; tie-break by balanced accuracy, accuracy, then Malicious_POST recall",
        "test_used": False,
        "feature_count": len(FEATURES),
        "model_features": FEATURES,
        "categorical_encoding": {"protocol": PROTOCOL_MAP, "source": SOURCE_MAP},
        "train_rows": int(len(train)),
        "train_runs": int(len(train_runs)),
        "validation_rows": int(len(validation)),
        "validation_runs": int(len(val_runs)),
        "best_candidate": selected_spec["name"],
        "best_parameters": selected_spec["parameters"],
        "best_normal_multiplier": selected_spec["normal_multiplier"],
        "best_validation": best_validation,
        "candidates_ranked_by_validation_run_macro_f1": candidates,
        "warning": "Validation selects the candidate; it is not an unbiased final score. Test remains unopened. The frozen generation holdout is excluded from the supplied splits.",
    }
    (args.output_dir / "tuning_validation_metrics.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )
    run = best_validation["run_level"]
    print(f"\nSelected on validation only: {selected_spec['name']}")
    print(f"Validation run accuracy={run['accuracy']:.4f}; balanced accuracy={run['balanced_accuracy']:.4f}; "
          f"run macro-F1={run['macro_f1']:.4f}")
    print("Test data was not read or scored. Results saved to", args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
