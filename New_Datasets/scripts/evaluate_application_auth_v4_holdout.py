#!/usr/bin/env python3
"""Evaluate frozen app-auth models on a fresh, independent holdout CSV.

This script never fits/retrains a model. It loads the saved Random Forest and
XGBoost models plus their label encoder/features, scores a new 2-class dataset,
and reports window-level and run-level metrics.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

EXPECTED_CLASSES = {"Malicious_POST", "Normal"}


def metrics(y_true, y_pred, labels):
    return {
        "rows_or_runs": int(len(y_true)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_macro": float(precision_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0)),
        "classes": list(labels),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "classification_report": classification_report(
            y_true, y_pred, labels=labels, output_dict=True, zero_division=0
        ),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", type=Path, required=True, help="fresh application-window CSV")
    ap.add_argument("--model-dir", type=Path, required=True, help="directory containing saved models")
    ap.add_argument("--output", type=Path, required=True, help="new JSON output path; must not exist")
    args = ap.parse_args()

    dataset_path = args.dataset.expanduser().resolve()
    model_dir = args.model_dir.expanduser().resolve()
    out = args.output.expanduser().resolve()
    if not dataset_path.is_file():
        raise SystemExit(f"missing dataset: {dataset_path}")
    if not model_dir.is_dir():
        raise SystemExit(f"missing model directory: {model_dir}")
    if out.exists():
        raise SystemExit(f"refusing to overwrite output: {out}")

    frame = pd.read_csv(dataset_path).reset_index(drop=True)
    required_meta = {"run_id", "observation_id", "label"}
    missing_meta = sorted(required_meta - set(frame.columns))
    if missing_meta:
        raise SystemExit(f"dataset missing metadata columns: {missing_meta}")
    if frame.empty:
        raise SystemExit("dataset is empty")
    if frame["observation_id"].duplicated().any():
        raise SystemExit("duplicate observation_id in holdout dataset")
    labels_present = set(frame["label"].astype(str))
    if labels_present != EXPECTED_CLASSES:
        raise SystemExit(f"expected labels {EXPECTED_CLASSES}, found {labels_present}")
    run_map = frame[["run_id", "label"]].drop_duplicates()
    if run_map["run_id"].duplicated().any():
        raise SystemExit("a run_id maps to multiple labels")
    runs_per_label = {str(k): int(v) for k, v in run_map.groupby("label")["run_id"].nunique().items()}
    if runs_per_label != {"Malicious_POST": 15, "Normal": 15}:
        raise SystemExit(f"expected 15 new independent runs per class; found {runs_per_label}")

    features_path = model_dir / "feature_columns.json"
    encoder_path = model_dir / "label_encoder.joblib"
    if not features_path.is_file() or not encoder_path.is_file():
        raise SystemExit("model directory lacks feature_columns.json or label_encoder.joblib")
    features = json.loads(features_path.read_text(encoding="utf-8"))
    if not isinstance(features, list) or not features:
        raise SystemExit("invalid feature_columns.json")
    missing_features = sorted(set(features) - set(frame.columns))
    if missing_features:
        raise SystemExit(f"holdout CSV missing model features: {missing_features}")
    x = frame[features].to_numpy(dtype=float)
    if not np.isfinite(x).all():
        raise SystemExit("model feature matrix contains NaN or infinite values")

    encoder = joblib.load(encoder_path)
    classes = [str(x) for x in encoder.classes_]
    if set(classes) != EXPECTED_CLASSES:
        raise SystemExit(f"saved model classes do not match holdout labels: {classes}")
    y_true = frame["label"].astype(str).to_numpy()

    output = {
        "task": "repeated failed-login burst detection",
        "evaluation_type": "frozen-model independent holdout; no refitting",
        "dataset": str(dataset_path),
        "model_dir": str(model_dir),
        "rows": int(len(frame)),
        "runs": int(frame["run_id"].nunique()),
        "runs_per_label": runs_per_label,
        "windows_per_label": {str(k): int(v) for k, v in frame["label"].value_counts().items()},
        "features": features,
        "models": {},
        "interpretation_warning": (
            "This holdout is independent only if its runs/profiles were not used in model training or model selection. "
            "Do not use these results to tune the frozen models; collect another holdout for any revised model."
        ),
    }

    for name in ("random_forest", "xgboost"):
        model_path = model_dir / f"{name}.joblib"
        if not model_path.is_file():
            raise SystemExit(f"missing model file: {model_path}")
        model = joblib.load(model_path)
        pred_ids = np.asarray(model.predict(x), dtype=int)
        if pred_ids.min(initial=0) < 0 or pred_ids.max(initial=0) >= len(classes):
            raise SystemExit(f"{name} emitted class indices outside saved label encoder")
        y_pred = encoder.inverse_transform(pred_ids)
        result = {"window_level": metrics(y_true, y_pred, classes)}

        probabilities = model.predict_proba(x)
        probability_label_names = encoder.inverse_transform(np.asarray(model.classes_, dtype=int))
        probability_index = {str(label): i for i, label in enumerate(probability_label_names)}
        run_true = []
        run_pred = []
        run_predictions = []
        for run_id, group in frame.groupby("run_id", sort=True):
            actual_labels = set(group["label"].astype(str))
            if len(actual_labels) != 1:
                raise SystemExit(f"{name}: run {run_id} has multiple true labels")
            actual = next(iter(actual_labels))
            mean_prob = probabilities[group.index.to_numpy()].mean(axis=0)
            predicted = str(probability_label_names[int(np.argmax(mean_prob))])
            run_true.append(actual)
            run_pred.append(predicted)
            run_predictions.append({
                "run_id": str(run_id),
                "actual": actual,
                "predicted": predicted,
                "windows": int(len(group)),
                "mean_probability": {
                    label: float(mean_prob[probability_index[label]])
                    for label in classes
                },
            })
        run_result = metrics(np.asarray(run_true), np.asarray(run_pred), classes)
        run_result["predictions"] = run_predictions
        result["run_level"] = run_result
        output["models"][name] = result

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Frozen-model evaluation complete: {out}")
    for name, result in output["models"].items():
        print(
            f"{name}: run macro-F1={result['run_level']['f1_macro']:.4f}; "
            f"window macro-F1={result['window_level']['f1_macro']:.4f}"
        )
    print("No model was retrained or modified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
