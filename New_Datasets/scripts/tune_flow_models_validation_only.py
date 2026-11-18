#!/usr/bin/env python3
"""Tune 4-class flow classifiers using train and validation splits only.

The held-out test file is intentionally never opened. All 20 configured flow
features are retained; IDs and labels are used only for grouping/evaluation.
The selected model is chosen by validation row accuracy, with macro-F1 and
Malicious_POST recall as tie-breakers. Do not use this validation score as a
final generalization estimate.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

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
WEIGHT_SCHEMES = ("row", "run", "class_run")


def read_split(path: Path, name: str) -> pd.DataFrame:
    if not path.is_file():
        raise SystemExit(f"STOP: required {name} split not found: {path}")
    df = pd.read_csv(path)
    required = {"run_id", "observation_id", "label", *FEATURES}
    missing = sorted(required - set(df.columns))
    if missing:
        raise SystemExit(f"STOP: {name} split is missing columns: {missing}")
    if df.empty:
        raise SystemExit(f"STOP: {name} split is empty")
    for col in ("run_id", "observation_id", "label"):
        if df[col].isna().any() or df[col].astype(str).str.strip().eq("").any():
            raise SystemExit(f"STOP: {name} split has blank {col}")
    labels = set(df["label"].astype(str))
    if labels != set(LABELS):
        raise SystemExit(f"STOP: {name} labels mismatch: {sorted(labels)}")
    if df.groupby("run_id")["label"].nunique().gt(1).any():
        raise SystemExit(f"STOP: a run_id maps to multiple labels in {name}")
    if df["observation_id"].astype(str).duplicated().any():
        raise SystemExit(f"STOP: duplicate observation_id in {name}")
    return df


def encode_features(df: pd.DataFrame) -> pd.DataFrame:
    x = df.loc[:, FEATURES].copy()
    protocol_map = {
        "tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58,
        "igmp": 2, "other": 0, "unknown": 0,
    }
    x["protocol"] = (
        x["protocol"].astype(str).str.strip().str.lower()
        .map(protocol_map).fillna(0)
    )
    for col in FEATURES:
        x[col] = pd.to_numeric(x[col], errors="coerce")
    if x.isna().any().any() or not np.isfinite(x.to_numpy(dtype=float)).all():
        bad = x.columns[x.isna().any()].tolist()
        raise SystemExit(f"STOP: invalid/missing numeric model feature(s): {bad}")
    return x


def sample_weights(df: pd.DataFrame, scheme: str) -> np.ndarray:
    if scheme == "row":
        weights = np.ones(len(df), dtype=float)
    elif scheme == "run":
        counts = df["run_id"].astype(str).value_counts()
        weights = df["run_id"].astype(str).map(lambda rid: 1.0 / counts[rid]).to_numpy(dtype=float, copy=True)
    elif scheme == "class_run":
        run_labels = df[["run_id", "label"]].drop_duplicates()
        if run_labels.groupby("run_id")["label"].nunique().gt(1).any():
            raise SystemExit("STOP: run-level weighting requires one label per run_id")
        runs_per_class = run_labels.groupby("label")["run_id"].nunique().to_dict()
        rows_per_run = df["run_id"].astype(str).value_counts().to_dict()
        labels_by_run = run_labels.assign(run_id=run_labels["run_id"].astype(str)).set_index("run_id")["label"].to_dict()
        weights = np.asarray([
            1.0 / (runs_per_class[label] * rows_per_run[rid])
            for rid, label in zip(df["run_id"].astype(str), df["label"].astype(str))
        ], dtype=float)
    else:
        raise ValueError(f"unknown weighting scheme: {scheme}")
    weights *= len(weights) / weights.sum()
    return weights


def candidate_specs(seed: int) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    rf_configs = [
        ("rf_baseline", {"n_estimators": 400, "max_features": "sqrt", "min_samples_leaf": 1}),
        ("rf_tuned", {"n_estimators": 600, "max_features": 0.7, "min_samples_leaf": 2}),
    ]
    et_configs = [
        ("extra_trees_baseline", {"n_estimators": 400, "max_features": "sqrt", "min_samples_leaf": 1}),
        ("extra_trees_tuned", {"n_estimators": 500, "max_features": 0.7, "min_samples_leaf": 2}),
    ]
    xgb_configs = [
        ("xgb_baseline", {"n_estimators": 300, "max_depth": 3, "learning_rate": 0.05,
                           "min_child_weight": 2, "reg_lambda": 1.0}),
        ("xgb_shallow", {"n_estimators": 450, "max_depth": 2, "learning_rate": 0.05,
                          "min_child_weight": 2, "reg_lambda": 2.0}),
    ]
    for family, configs in (("random_forest", rf_configs), ("extra_trees", et_configs), ("xgboost", xgb_configs)):
        for config_name, params in configs:
            for weighting in WEIGHT_SCHEMES:
                specs.append({
                    "family": family,
                    "name": f"{config_name}__{weighting}",
                    "params": params.copy(),
                    "weighting": weighting,
                    "seed": seed,
                })
    return specs


def make_model(spec: dict[str, Any]):
    family = spec["family"]
    params = spec["params"]
    seed = spec["seed"]
    if family == "random_forest":
        from sklearn.ensemble import RandomForestClassifier
        return RandomForestClassifier(**params, random_state=seed, n_jobs=-1)
    if family == "extra_trees":
        from sklearn.ensemble import ExtraTreesClassifier
        return ExtraTreesClassifier(**params, random_state=seed, n_jobs=-1)
    if family == "xgboost":
        from xgboost import XGBClassifier
        return XGBClassifier(
            **params, subsample=0.9, colsample_bytree=0.9,
            objective="multi:softprob", eval_metric="mlogloss",
            num_class=len(LABELS), random_state=seed, n_jobs=-1,
            tree_method="hist", use_label_encoder=False,
        )
    raise ValueError(f"unsupported family: {family}")


def metrics_for(model, x: pd.DataFrame, df: pd.DataFrame, encoder) -> dict[str, Any]:
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score

    y_true = encoder.transform(df["label"].astype(str))
    y_pred = model.predict(x)
    ids = list(range(len(encoder.classes_)))
    row = {
        "rows": int(len(df)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=ids).tolist(),
        "classification_report": classification_report(
            y_true, y_pred, labels=ids, target_names=encoder.classes_.tolist(),
            output_dict=True, zero_division=0,
        ),
    }
    probabilities = pd.DataFrame(model.predict_proba(x), columns=encoder.classes_)
    probabilities["run_id"] = df["run_id"].astype(str).to_numpy()
    mean_prob = probabilities.groupby("run_id", sort=True)[encoder.classes_.tolist()].mean()
    actual = (
        df.assign(_run_id=df["run_id"].astype(str))
        .groupby("_run_id", sort=True)["label"].first()
        .loc[mean_prob.index]
    )
    predicted_run = encoder.inverse_transform(mean_prob.to_numpy().argmax(axis=1))
    actual_ids = encoder.transform(actual.astype(str))
    predicted_ids = encoder.transform(predicted_run)
    run = {
        "runs": int(len(actual)),
        "accuracy": float(accuracy_score(actual_ids, predicted_ids)),
        "macro_f1": float(f1_score(actual_ids, predicted_ids, average="macro", zero_division=0)),
        "confusion_matrix": confusion_matrix(actual_ids, predicted_ids, labels=ids).tolist(),
        "classification_report": classification_report(
            actual_ids, predicted_ids, labels=ids, target_names=encoder.classes_.tolist(),
            output_dict=True, zero_division=0,
        ),
    }
    return {"row_level": row, "run_level": run}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if args.output_dir.exists():
        raise SystemExit(f"STOP: output path already exists; refusing overwrite: {args.output_dir}")
    try:
        import joblib
        from sklearn.preprocessing import LabelEncoder
    except ImportError as exc:
        raise SystemExit("Required packages: scikit-learn and joblib") from exc

    train = read_split(args.split_dir / "train.csv", "train")
    validation = read_split(args.split_dir / "validation.csv", "validation")
    train_runs = set(train["run_id"].astype(str))
    val_runs = set(validation["run_id"].astype(str))
    if train_runs & val_runs:
        raise SystemExit("STOP: run_id leakage between train and validation")

    encoder = LabelEncoder().fit(train["label"].astype(str))
    x_train = encode_features(train)
    x_val = encode_features(validation)
    y_train = encoder.transform(train["label"].astype(str))
    print(
        f"Validation-only tuning: features={len(FEATURES)}; "
        f"train={len(train)} rows/{len(train_runs)} runs; "
        f"validation={len(validation)} rows/{len(val_runs)} runs",
        flush=True,
    )
    print("Test data is not read, scored, or used for model selection.", flush=True)

    results: list[dict[str, Any]] = []
    best_spec: dict[str, Any] | None = None
    best_model = None
    best_key: tuple[float, float, float] | None = None
    specs = candidate_specs(args.seed)
    for i, spec in enumerate(specs, 1):
        model = make_model(spec)
        weights = sample_weights(train, spec["weighting"])
        model.fit(x_train, y_train, sample_weight=weights)
        scores = metrics_for(model, x_val, validation, encoder)
        row = scores["row_level"]
        malicious_recall = float(row["classification_report"]["Malicious_POST"]["recall"])
        key = (row["accuracy"], row["macro_f1"], malicious_recall)
        record = {
            "candidate": spec["name"],
            "family": spec["family"],
            "parameters": spec["params"],
            "training_weighting": spec["weighting"],
            "validation": scores,
        }
        results.append(record)
        print(
            f"[{i}/{len(specs)}] {spec['name']}: "
            f"val row accuracy={row['accuracy']:.4f}, row macro-F1={row['macro_f1']:.4f}, "
            f"Malicious_POST recall={malicious_recall:.4f}; "
            f"run accuracy={scores['run_level']['accuracy']:.4f}, "
            f"run macro-F1={scores['run_level']['macro_f1']:.4f}",
            flush=True,
        )
        if best_key is None or key > best_key:
            best_key = key
            best_spec = spec.copy()
            best_model = model

    results.sort(
        key=lambda item: (
            item["validation"]["row_level"]["accuracy"],
            item["validation"]["row_level"]["macro_f1"],
            item["validation"]["row_level"]["classification_report"]["Malicious_POST"]["recall"],
        ),
        reverse=True,
    )
    assert best_spec is not None and best_model is not None and best_key is not None
    args.output_dir.mkdir(parents=True, exist_ok=False)
    joblib.dump(best_model, args.output_dir / "validation_selected_model.joblib")
    joblib.dump(encoder, args.output_dir / "label_encoder.joblib")
    (args.output_dir / "feature_columns.json").write_text(
        json.dumps({"level": "flow", "features": FEATURES}, indent=2), encoding="utf-8"
    )
    payload = {
        "selection_rule": "highest validation row accuracy; tie-break by validation row macro-F1, then Malicious_POST recall",
        "test_used": False,
        "model_features": FEATURES,
        "train_rows": int(len(train)),
        "train_runs": int(len(train_runs)),
        "validation_rows": int(len(validation)),
        "validation_runs": int(len(val_runs)),
        "best_candidate": best_spec["name"],
        "best_family": best_spec["family"],
        "best_parameters": best_spec["params"],
        "best_training_weighting": best_spec["weighting"],
        "best_validation": next(
            item["validation"] for item in results if item["candidate"] == best_spec["name"]
        ),
        "candidates_ranked_by_validation_objective": results,
        "warning": "Validation metrics select a candidate and are not an unbiased final test estimate. Keep test sealed until model choice is frozen.",
    }
    (args.output_dir / "tuning_validation_metrics.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )
    print(f"\nSelected on validation only: {best_spec['name']}")
    print(f"Validation row accuracy={best_key[0]:.4f}; row macro-F1={best_key[1]:.4f}; "
          f"Malicious_POST recall={best_key[2]:.4f}")
    print("Test data was not read or scored. Selected model and validation report saved to", args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
