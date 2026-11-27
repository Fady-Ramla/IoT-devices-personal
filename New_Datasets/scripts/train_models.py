#!/usr/bin/env python3
"""Train Random Forest and XGBoost on a prepared run-grouped split.

Uses equal total training weight per run to prevent high-volume runs from
implicitly dominating. Evaluates both observation-level and aggregated
run-level performance. Does not create or alter splits.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

FLOW_FEATURES = [
    "protocol", "src_port", "dst_port", "packet_count", "byte_count",
    "packet_rate", "byte_rate", "duration_sec", "avg_packet_size",
    "syn_count", "ack_count", "rst_count", "fin_count", "syn_ack_ratio",
    "rst_ratio", "unique_dst_ports", "failed_connection_count",
    "tcp_fraction", "udp_fraction", "icmp_fraction",
]
PACKET_FEATURES = [
    "protocol", "src_port", "dst_port", "packet_length", "tcp_syn",
    "tcp_ack", "tcp_rst", "tcp_fin", "icmp_type", "arp_operation",
]
EXPECTED_LABELS = {"Normal", "Malicious_POST", "Port_Scan", "SYN_Flood"}


def encode(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    missing = sorted(set(columns) - set(df.columns))
    if missing:
        raise SystemExit(f"split is missing model features: {missing}")
    x = df.loc[:, columns].copy()
    if "protocol" in x.columns:
        x["protocol"] = (
            x["protocol"].astype(str).str.strip().str.lower()
            .map({"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "igmp": 2, "other": 0, "unknown": 0})
            .fillna(0)
        )
    for col in x.columns:
        x[col] = pd.to_numeric(x[col], errors="coerce").fillna(0)
    return x


def validate_splits(train: pd.DataFrame, val: pd.DataFrame, test: pd.DataFrame) -> None:
    required = {"run_id", "label"}
    for name, df in (("train", train), ("validation", val), ("test", test)):
        missing = sorted(required - set(df.columns))
        if missing:
            raise SystemExit(f"{name} split is missing columns: {missing}")
        if df.empty:
            raise SystemExit(f"{name} split is empty")
        if df["run_id"].isna().any() or df["label"].isna().any():
            raise SystemExit(f"{name} split contains missing run_id/label")
        labels = set(df["label"].astype(str))
        if labels != EXPECTED_LABELS:
            raise SystemExit(f"{name} labels {sorted(labels)} do not match expected {sorted(EXPECTED_LABELS)}")
        if df.groupby("run_id")["label"].nunique().gt(1).any():
            raise SystemExit(f"{name} has a run_id assigned to multiple labels")
    sets = {
        name: set(df["run_id"].astype(str))
        for name, df in (("train", train), ("validation", val), ("test", test))
    }
    if sets["train"] & sets["validation"] or sets["train"] & sets["test"] or sets["validation"] & sets["test"]:
        raise SystemExit("run_id leakage detected across train/validation/test")


def equal_run_weights(df: pd.DataFrame) -> np.ndarray:
    """Give each run the same sum of sample weights; normalize mean to one."""
    run_ids = df["run_id"].astype(str)
    counts = run_ids.value_counts()
    weights = run_ids.map(lambda rid: 1.0 / counts[rid]).to_numpy(dtype=float, copy=True)
    weights *= len(weights) / weights.sum()
    return weights


def evaluate(model, x: pd.DataFrame, df: pd.DataFrame, encoder) -> dict:
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score

    y_true = encoder.transform(df["label"].astype(str))
    y_pred = model.predict(x)
    label_ids = list(range(len(encoder.classes_)))
    row_metrics = {
        "rows": int(len(df)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_macro": float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=label_ids).tolist(),
        "classification_report": classification_report(
            y_true, y_pred, labels=label_ids, target_names=encoder.classes_.tolist(),
            output_dict=True, zero_division=0,
        ),
    }

    probabilities = pd.DataFrame(model.predict_proba(x), index=df.index, columns=model.classes_)
    probabilities["run_id"] = df["run_id"].astype(str).to_numpy()
    mean_probability = probabilities.groupby("run_id", sort=True).mean()
    actual = df.assign(_run_id=df["run_id"].astype(str)).groupby("_run_id", sort=True)["label"].first().loc[mean_probability.index]
    predicted_ids = mean_probability.to_numpy().argmax(axis=1)
    run_pred = encoder.inverse_transform(predicted_ids)
    run_true = actual.to_numpy()
    run_metrics = {
        "runs": int(len(run_true)),
        "aggregation": "mean class probability across observations in each run",
        "accuracy": float(accuracy_score(run_true, run_pred)),
        "precision_macro": float(precision_score(run_true, run_pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(run_true, run_pred, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(run_true, run_pred, average="macro", zero_division=0)),
        "confusion_matrix": confusion_matrix(run_true, run_pred, labels=encoder.classes_.tolist()).tolist(),
        "classification_report": classification_report(
            run_true, run_pred, labels=encoder.classes_.tolist(),
            target_names=encoder.classes_.tolist(), output_dict=True, zero_division=0,
        ),
        "predictions": [
            {"run_id": str(rid), "actual": str(y), "predicted": str(p)}
            for rid, y, p in zip(mean_probability.index, run_true, run_pred)
        ],
    }
    return {"row_level": row_metrics, "run_level": run_metrics}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--level", choices=["flow", "packet"], default="flow")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import LabelEncoder
        import joblib
    except ImportError as exc:
        raise SystemExit("Install in active environment: python -m pip install scikit-learn joblib xgboost") from exc
    try:
        from xgboost import XGBClassifier
    except ImportError as exc:
        raise SystemExit("XGBoost required: python -m pip install xgboost") from exc

    columns = FLOW_FEATURES if args.level == "flow" else PACKET_FEATURES
    train = pd.read_csv(args.split_dir / "train.csv")
    val = pd.read_csv(args.split_dir / "validation.csv")
    test = pd.read_csv(args.split_dir / "test.csv")
    validate_splits(train, val, test)

    encoder = LabelEncoder().fit(train["label"].astype(str))
    y_train = encoder.transform(train["label"].astype(str))
    x_train, x_val, x_test = (encode(frame, columns) for frame in (train, val, test))
    sample_weight = equal_run_weights(train)

    print(f"Training level={args.level}; features={len(columns)}; rows train/val/test="
          f"{len(train)}/{len(val)}/{len(test)}; run_ids="
          f"{train.run_id.nunique()}/{val.run_id.nunique()}/{test.run_id.nunique()}", flush=True)
    print("Training sample weights: equal total contribution per run; labels="
          f"{encoder.classes_.tolist()}", flush=True)

    rf = RandomForestClassifier(n_estimators=400, random_state=args.seed, n_jobs=-1)
    rf.fit(x_train, y_train, sample_weight=sample_weight)
    print("Random Forest fitted.", flush=True)

    xgb = XGBClassifier(
        n_estimators=300, max_depth=3, learning_rate=0.05,
        subsample=0.9, colsample_bytree=0.9, min_child_weight=2,
        reg_lambda=1.0, objective="multi:softprob", eval_metric="mlogloss",
        random_state=args.seed, n_jobs=-1, tree_method="hist",
    )
    xgb.fit(x_train, y_train, sample_weight=sample_weight,
            eval_set=[(x_val, encoder.transform(val["label"].astype(str)))], verbose=False)
    print("XGBoost fitted.", flush=True)

    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise SystemExit(f"output directory is not empty; refusing to overwrite: {args.output_dir}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    models = {"random_forest": rf, "xgboost": xgb}
    results = {
        "level": args.level,
        "features": columns,
        "classes": encoder.classes_.tolist(),
        "seed": args.seed,
        "training_weighting": "equal total sample weight per run_id",
        "split_dir": str(args.split_dir),
        "split_summary": {
            name: {
                "rows": int(len(frame)),
                "runs": int(frame["run_id"].nunique()),
                "runs_per_label": frame[["run_id", "label"]].drop_duplicates().groupby("label")["run_id"].nunique().to_dict(),
                "rows_per_label": frame["label"].value_counts().to_dict(),
            }
            for name, frame in (("train", train), ("validation", val), ("test", test))
        },
        "models": {},
    }
    for name, model in models.items():
        results["models"][name] = {
            "validation": evaluate(model, x_val, val, encoder),
            "test": evaluate(model, x_test, test, encoder),
        }
        joblib.dump(model, args.output_dir / f"{name}.joblib")
    joblib.dump(encoder, args.output_dir / "label_encoder.joblib")
    (args.output_dir / "feature_columns.json").write_text(
        json.dumps({"level": args.level, "features": columns}, indent=2), encoding="utf-8"
    )
    (args.output_dir / "training_metrics.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    print("Saved both models and row-level/run-level metrics to", args.output_dir, flush=True)
    for name, scores in results["models"].items():
        print(f"{name}: validation run macro-F1={scores['validation']['run_level']['f1_macro']:.4f}; "
              f"test run macro-F1={scores['test']['run_level']['f1_macro']:.4f}; "
              f"test row macro-F1={scores['test']['row_level']['f1_macro']:.4f}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
