#!/usr/bin/env python3
"""Train RF/XGBoost models on one-row-per-run aggregated datasets."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

IDENTITY = {"run_id", "observation_id", "label", "label_status"}


def numeric_features(train, val, test):
    candidates = [
        c for c in train.columns
        if c not in IDENTITY and pd.api.types.is_numeric_dtype(train[c])
    ]
    if not candidates:
        raise ValueError("No numeric run-level features found")
    missing = [c for c in candidates if c not in val.columns or c not in test.columns]
    if missing:
        raise ValueError("Features missing from validation/test: {}".format(missing))
    return candidates


def encode(df, columns):
    result = df.reindex(columns=columns).copy()
    for col in columns:
        result[col] = pd.to_numeric(result[col], errors="coerce")
    result = result.replace([float("inf"), float("-inf")], float("nan"))
    return result.fillna(0.0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--split-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
        from sklearn.preprocessing import LabelEncoder
    except ImportError as exc:
        raise SystemExit("scikit-learn is required") from exc

    try:
        import joblib
    except ImportError as exc:
        raise SystemExit("joblib is required") from exc

    train = pd.read_csv(args.split_dir / "train.csv")
    val = pd.read_csv(args.split_dir / "validation.csv")
    test = pd.read_csv(args.split_dir / "test.csv")
    if train.empty or val.empty or test.empty:
        raise SystemExit("train/validation/test must all contain rows")

    columns = numeric_features(train, val, test)
    encoder = LabelEncoder().fit(train["label"])
    unknown = (set(val["label"]) | set(test["label"])) - set(encoder.classes_)
    if unknown:
        raise SystemExit("Labels absent from train split: {}".format(sorted(unknown)))

    y_train = encoder.transform(train["label"])
    y_val = encoder.transform(val["label"])
    y_test = encoder.transform(test["label"])
    x_train = encode(train, columns)
    x_val = encode(val, columns)
    x_test = encode(test, columns)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    model = RandomForestClassifier(
        n_estimators=400,
        class_weight="balanced",
        random_state=args.seed,
        n_jobs=-1,
    )
    model.fit(x_train, y_train)

    val_pred = model.predict(x_val)
    test_pred = model.predict(x_test)
    metrics = {
        "model": "random_forest_run_level",
        "features": columns,
        "feature_count": len(columns),
        "classes": encoder.classes_.tolist(),
        "train_runs": int(train["run_id"].nunique()),
        "validation_runs": int(val["run_id"].nunique()),
        "test_runs": int(test["run_id"].nunique()),
        "validation": {
            "accuracy": float(accuracy_score(y_val, val_pred)),
            "macro_f1": float(f1_score(y_val, val_pred, average="macro")),
            "classification_report": classification_report(
                y_val, val_pred, target_names=encoder.classes_, output_dict=True, zero_division=0
            ),
        },
        "test": {
            "accuracy": float(accuracy_score(y_test, test_pred)),
            "macro_f1": float(f1_score(y_test, test_pred, average="macro")),
            "confusion_matrix": confusion_matrix(y_test, test_pred).tolist(),
            "classification_report": classification_report(
                y_test, test_pred, target_names=encoder.classes_, output_dict=True, zero_division=0
            ),
        },
    }

    joblib.dump(model, args.output_dir / "random_forest.joblib")
    joblib.dump(encoder, args.output_dir / "label_encoder.joblib")

    try:
        from xgboost import XGBClassifier
    except ImportError:
        metrics["xgboost"] = "not installed"
    else:
        xgb = XGBClassifier(
            n_estimators=400,
            max_depth=6,
            learning_rate=0.05,
            subsample=0.9,
            colsample_bytree=0.9,
            objective="multi:softprob",
            eval_metric="mlogloss",
            random_state=args.seed,
        )
        xgb.fit(x_train, y_train, eval_set=[(x_val, y_val)], verbose=False)
        joblib.dump(xgb, args.output_dir / "xgboost.joblib")
        metrics["xgboost"] = "completed"

    (args.output_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )
    print(json.dumps(metrics["test"], indent=2))
    print("features:", len(columns))
    print("wrote:", args.output_dir)


if __name__ == "__main__":
    main()
