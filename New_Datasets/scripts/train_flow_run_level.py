#!/usr/bin/env python3
"""Train and evaluate a run-level Flow model with an exact split schema."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.preprocessing import LabelEncoder


def args():
    p = argparse.ArgumentParser()
    p.add_argument("--split-dir", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


def main():
    a = args()
    split_dir = Path(a.split_dir)
    output_dir = Path(a.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    frames = {
        name: pd.read_csv(split_dir / f"{name}.csv")
        for name in ("train", "validation", "test")
    }

    drop = {"run_id", "label", "observation_id"}
    train = frames["train"]
    features = [
        col for col in train.columns
        if col not in drop and pd.api.types.is_numeric_dtype(train[col])
    ]
    if not features:
        raise SystemExit("No numeric model features found")

    for name, frame in frames.items():
        missing = [col for col in features if col not in frame.columns]
        if missing:
            raise SystemExit(f"{name}: missing features: {missing}")
        if frame[features].isna().any().any():
            raise SystemExit(f"{name}: missing numeric values")
        non_numeric = frame[features].select_dtypes(exclude="number").columns.tolist()
        if non_numeric:
            raise SystemExit(f"{name}: non-numeric features: {non_numeric}")

    encoder = LabelEncoder()
    encoder.fit(train["label"].astype(str))

    model = RandomForestClassifier(
        n_estimators=500,
        random_state=a.seed,
        class_weight="balanced",
        n_jobs=-1,
        max_features="sqrt",
    )
    model.fit(
        train[features],
        encoder.transform(train["label"].astype(str)),
    )

    evaluations = {}
    for name, frame in frames.items():
        y_true = encoder.transform(frame["label"].astype(str))
        y_pred = model.predict(frame[features])
        labels = list(range(len(encoder.classes_)))
        evaluations[name] = {
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "macro_f1": float(f1_score(y_true, y_pred, average="macro")),
            "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
            "classification_report": classification_report(
                y_true,
                y_pred,
                labels=labels,
                target_names=list(encoder.classes_),
                output_dict=True,
                zero_division=0,
            ),
            "run_count": int(len(frame)),
            "label_counts": frame["label"].value_counts().to_dict(),
        }

    joblib.dump(model, output_dir / "random_forest.joblib")
    joblib.dump(encoder, output_dir / "label_encoder.joblib")

    metrics = {
        "model": "random_forest",
        "level": "flow_run_level",
        "seed": a.seed,
        "features": features,
        "feature_count": len(features),
        "classes": list(encoder.classes_),
        "train_runs": frames["train"]["run_id"].astype(str).tolist(),
        "validation_runs": frames["validation"]["run_id"].astype(str).tolist(),
        "test_runs": frames["test"]["run_id"].astype(str).tolist(),
        "validation": evaluations["validation"],
        "test": evaluations["test"],
    }
    (output_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )

    print(json.dumps({
        "model": "random_forest",
        "feature_count": len(features),
        "validation_accuracy": evaluations["validation"]["accuracy"],
        "validation_macro_f1": evaluations["validation"]["macro_f1"],
        "test_accuracy": evaluations["test"]["accuracy"],
        "test_macro_f1": evaluations["test"]["macro_f1"],
        "output_dir": str(output_dir),
    }, indent=2))


if __name__ == "__main__":
    main()
