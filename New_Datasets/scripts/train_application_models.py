#!/usr/bin/env python3
"""Train separate Normal-vs-Malicious_POST HTTP event baselines.

Uses only http_method and route_category. response_status is intentionally not
used because demo authentication configuration can change it. Runs—not event
rows—must be disjoint across the supplied splits.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

FEATURES = ["http_method", "route_category"]
EXPECTED_LABELS = {"Normal", "Malicious_POST"}


def validate_splits(train: pd.DataFrame, val: pd.DataFrame, test: pd.DataFrame) -> None:
    sets = {}
    for name, df in (("train", train), ("validation", val), ("test", test)):
        missing = {"run_id", "label", *FEATURES} - set(df.columns)
        if missing:
            raise SystemExit(f"{name} split missing fields: {sorted(missing)}")
        if df.empty or df[["run_id", "label", *FEATURES]].isna().any().any():
            raise SystemExit(f"{name} split has empty data or missing required fields")
        if set(df["label"].astype(str)) != EXPECTED_LABELS:
            raise SystemExit(f"{name} split must contain both labels {sorted(EXPECTED_LABELS)}")
        if df.groupby("run_id")["label"].nunique().gt(1).any():
            raise SystemExit(f"{name} split has a run assigned multiple labels")
        sets[name] = set(df["run_id"].astype(str))
        counts = df[["run_id", "label"]].drop_duplicates().groupby("label")["run_id"].nunique()
        minimum = 5 if name == "train" else 2
        if (counts.reindex(sorted(EXPECTED_LABELS), fill_value=0) < minimum).any():
            raise SystemExit(f"{name} split needs at least {minimum} independent runs per class; found {counts.to_dict()}")
    if sets["train"] & sets["validation"] or sets["train"] & sets["test"] or sets["validation"] & sets["test"]:
        raise SystemExit("run_id leakage across train/validation/test")


def equal_run_weights(df: pd.DataFrame) -> np.ndarray:
    ids = df["run_id"].astype(str)
    counts = ids.value_counts()
    weights = ids.map(lambda rid: 1.0 / counts[rid]).to_numpy(dtype=float, copy=True)
    weights *= len(weights) / weights.sum()
    return weights


def score(model, encoder, x: np.ndarray, df: pd.DataFrame) -> dict:
    from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

    true = encoder.transform(df["label"].astype(str))
    pred = model.predict(x).astype(int)
    probs = model.predict_proba(x)
    row = {
        "rows": int(len(df)),
        "accuracy": float(accuracy_score(true, pred)),
        "precision_macro": float(precision_score(true, pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(true, pred, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(true, pred, average="macro", zero_division=0)),
        "confusion_matrix": confusion_matrix(true, pred, labels=[0, 1]).tolist(),
    }
    per_run = pd.DataFrame(probs, columns=[str(c) for c in model.classes_], index=df.index)
    per_run["run_id"] = df["run_id"].astype(str).to_numpy()
    mean_probs = per_run.groupby("run_id", sort=True)[["0", "1"]].mean()
    truth = df.assign(_rid=df["run_id"].astype(str)).groupby("_rid", sort=True)["label"].first().loc[mean_probs.index]
    predicted = encoder.inverse_transform(mean_probs.to_numpy().argmax(axis=1))
    run = {
        "runs": int(len(truth)),
        "aggregation": "mean class probability across HTTP events within run_id",
        "accuracy": float(accuracy_score(truth, predicted)),
        "precision_macro": float(precision_score(truth, predicted, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(truth, predicted, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(truth, predicted, average="macro", zero_division=0)),
        "confusion_matrix": confusion_matrix(truth, predicted, labels=encoder.classes_.tolist()).tolist(),
        "predictions": [
            {"run_id": str(rid), "actual": str(y), "predicted": str(p)}
            for rid, y, p in zip(mean_probs.index, truth.to_numpy(), predicted)
        ],
    }
    return {"row_level": row, "run_level": run}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import LabelEncoder, OneHotEncoder
        import joblib
        from xgboost import XGBClassifier
    except ImportError as exc:
        raise SystemExit("Required packages: scikit-learn, joblib, xgboost") from exc

    splits = {name: pd.read_csv(args.split_dir / f"{name}.csv") for name in ("train", "validation", "test")}
    train, val, test = splits["train"], splits["validation"], splits["test"]
    validate_splits(train, val, test)
    encoder = LabelEncoder().fit(train["label"].astype(str))
    y_train = encoder.transform(train["label"].astype(str))
    sample_weight = equal_run_weights(train)

    # Fixed, deterministic field order; model sees no run IDs, timestamps,
    # response codes, IPs, ports, route paths, headers, or request bodies.
    preprocessor = OneHotEncoder(handle_unknown="ignore", sparse_output=False, dtype=np.float32)
    x_train = preprocessor.fit_transform(train[FEATURES].astype(str))
    x_val = preprocessor.transform(val[FEATURES].astype(str))
    x_test = preprocessor.transform(test[FEATURES].astype(str))

    rf = RandomForestClassifier(n_estimators=300, min_samples_leaf=2, random_state=args.seed, n_jobs=-1)
    rf.fit(x_train, y_train, sample_weight=sample_weight)
    xgb = XGBClassifier(
        n_estimators=200, max_depth=2, learning_rate=0.05,
        subsample=0.9, colsample_bytree=0.9, min_child_weight=2,
        reg_lambda=1.0, objective="binary:logistic", eval_metric="logloss",
        random_state=args.seed, n_jobs=-1, tree_method="hist",
    )
    xgb.fit(x_train, y_train, sample_weight=sample_weight, verbose=False)
    models = {"random_forest": rf, "xgboost": xgb}

    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise SystemExit(f"refusing to overwrite non-empty output directory: {args.output_dir}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    results = {
        "task": "binary HTTP application event classification",
        "features": FEATURES,
        "excluded_fields": ["run_id", "observation_id", "timestamp", "response_status", "src_ip", "dst_ip", "src_port", "dst_port", "request headers", "route path", "body/payload"],
        "classes": encoder.classes_.tolist(),
        "seed": args.seed,
        "training_weighting": "equal total sample weight per run_id",
        "metrics": {},
        "split_summary": {},
    }
    for name, df in splits.items():
        grouped = df[["run_id", "label"]].drop_duplicates()
        results["split_summary"][name] = {
            "events": int(len(df)),
            "runs": int(df["run_id"].nunique()),
            "runs_per_label": grouped.groupby("label")["run_id"].nunique().to_dict(),
            "events_per_label": df["label"].value_counts().to_dict(),
        }
    for name, model in models.items():
        results["metrics"][name] = {
            "validation": score(model, encoder, x_val, val),
            "test": score(model, encoder, x_test, test),
        }
        joblib.dump(model, args.output_dir / f"{name}.joblib")
    joblib.dump(preprocessor, args.output_dir / "one_hot_encoder.joblib")
    joblib.dump(encoder, args.output_dir / "label_encoder.joblib")
    (args.output_dir / "feature_columns.json").write_text(json.dumps({"features": FEATURES}, indent=2), encoding="utf-8")
    (args.output_dir / "training_metrics.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Trained application baselines with {len(train)} train events from {train.run_id.nunique()} runs.")
    for name, metrics in results["metrics"].items():
        print(f"{name}: validation run macro-F1={metrics['validation']['run_level']['f1_macro']:.4f}; "
              f"test run macro-F1={metrics['test']['run_level']['f1_macro']:.4f}")
    print("Saved models/metrics to", args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
