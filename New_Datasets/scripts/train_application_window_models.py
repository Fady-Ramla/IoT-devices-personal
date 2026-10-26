#!/usr/bin/env python3
"""Train run-balanced RF/XGBoost baselines for app-v2 login-burst windows."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

FEATURES = [
    "total_requests", "post_count", "auth_post_count", "auth_post_2xx_count",
    "auth_post_401_count", "auth_post_4xx_other_count", "auth_post_5xx_count",
    "auth_get_count", "health_get_count", "iot_api_post_count",
    "other_route_post_count", "all_2xx_count", "all_4xx_count", "all_5xx_count",
    "auth_post_rate_per_sec", "auth_401_rate_per_sec",
]
CLASSES = {"Normal", "Malicious_POST"}


def load_split(path: Path) -> pd.DataFrame:
    if not path.is_file():
        raise SystemExit(f"missing split: {path}")
    frame = pd.read_csv(path)
    required = {"run_id", "label", *FEATURES}
    missing = required - set(frame.columns)
    if missing:
        raise SystemExit(f"{path}: missing required columns {sorted(missing)}")
    if frame.empty:
        raise SystemExit(f"{path}: empty split")
    if frame["run_id"].isna().any() or frame["label"].isna().any():
        raise SystemExit(f"{path}: missing run identity/label")
    frame["run_id"] = frame["run_id"].astype(str)
    frame["label"] = frame["label"].astype(str)
    if not set(frame["label"].unique()).issubset(CLASSES):
        raise SystemExit(f"{path}: unexpected labels {sorted(set(frame['label']) - CLASSES)}")
    if frame.groupby("run_id")["label"].nunique().gt(1).any():
        raise SystemExit(f"{path}: one run_id maps to multiple labels")
    values = frame[FEATURES].apply(pd.to_numeric, errors="coerce")
    if values.isna().any().any() or not np.isfinite(values.to_numpy(dtype=float)).all():
        raise SystemExit(f"{path}: features contain missing or non-finite values")
    if (values < 0).any().any():
        raise SystemExit(f"{path}: count/rate feature is negative")
    frame.loc[:, FEATURES] = values
    return frame


def run_balanced_weights(frame: pd.DataFrame) -> np.ndarray:
    counts = frame.groupby("run_id")["run_id"].transform("size").to_numpy(dtype=float)
    weights = 1.0 / counts
    weights *= len(weights) / weights.sum()
    return weights


def metric_pack(y_true: np.ndarray, y_pred: np.ndarray, classes: list[str], run_count: int | None = None) -> dict:
    result = {
        "rows": int(len(y_true)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "precision_macro": float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
        "classes": classes,
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=classes).tolist(),
    }
    if run_count is not None:
        result["runs"] = int(run_count)
    return result


def evaluate(model, frame: pd.DataFrame, feature_frame: pd.DataFrame, encoder: LabelEncoder, classes: list[str]) -> dict:
    x = frame[FEATURES].to_numpy(dtype=float)
    y_true_ids = encoder.transform(frame["label"])
    pred_ids = model.predict(x).astype(int)
    y_pred = encoder.inverse_transform(pred_ids)
    row_metrics = metric_pack(frame["label"].to_numpy(), y_pred, classes)

    probabilities = model.predict_proba(x)
    probability_labels = encoder.inverse_transform(model.classes_.astype(int))
    probability_columns = {label: index for index, label in enumerate(probability_labels)}
    run_truth = frame.groupby("run_id", sort=True)["label"].first()
    run_rows = frame.assign(_true=frame["label"].to_numpy()).groupby("run_id", sort=True)
    run_predictions = []
    run_actual: list[str] = []
    run_predicted: list[str] = []
    for run_id, group in run_rows:
        row_indices = group.index.to_numpy()
        # Probability rows align to the input frame's positional order.
        positions = frame.index.get_indexer(row_indices)
        mean_probability = probabilities[positions].mean(axis=0)
        pred_label = probability_labels[int(np.argmax(mean_probability))]
        actual = str(run_truth.loc[run_id])
        distribution = {
            label: float(mean_probability[probability_columns[label]])
            for label in classes
        }
        run_actual.append(actual)
        run_predicted.append(pred_label)
        run_predictions.append({
            "run_id": str(run_id),
            "actual": actual,
            "predicted": pred_label,
            "mean_probability": distribution,
            "windows": int(len(group)),
        })
    run_metrics = metric_pack(np.asarray(run_actual), np.asarray(run_predicted), classes, len(run_predictions))
    run_metrics["predictions"] = run_predictions
    return {"window_level": row_metrics, "run_level": run_metrics}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if args.output_dir.exists():
        raise SystemExit(f"refusing to overwrite output directory: {args.output_dir}")

    splits = {
        name: load_split(args.split_dir / f"{name}.csv")
        for name in ("train", "validation", "test")
    }
    run_sets = {name: set(frame["run_id"]) for name, frame in splits.items()}
    if (run_sets["train"] & run_sets["validation"] or
            run_sets["train"] & run_sets["test"] or
            run_sets["validation"] & run_sets["test"]):
        raise SystemExit("run_id leakage across train/validation/test")

    train_groups = splits["train"]["run_id"].drop_duplicates()
    train_map = splits["train"][ ["run_id", "label"] ].drop_duplicates()
    if train_map["run_id"].duplicated().any():
        raise SystemExit("train run has multiple labels")
    if set(train_map["label"]) != CLASSES:
        raise SystemExit("train split does not contain both classes")
    for split_name, frame in splits.items():
        if set(frame["label"]) != CLASSES:
            raise SystemExit(f"{split_name} split does not contain both classes")

    encoder = LabelEncoder().fit(sorted(CLASSES))
    y_train = encoder.transform(splits["train"]["label"])
    x_train = splits["train"][FEATURES].to_numpy(dtype=float)
    weights = run_balanced_weights(splits["train"])
    classes = encoder.classes_.tolist()

    models = {
        "random_forest": RandomForestClassifier(
            n_estimators=500,
            max_depth=8,
            min_samples_leaf=2,
            class_weight=None,
            random_state=args.seed,
            n_jobs=-1,
        ),
        "xgboost": XGBClassifier(
            n_estimators=300,
            max_depth=3,
            learning_rate=0.05,
            subsample=0.9,
            colsample_bytree=0.9,
            reg_lambda=1.0,
            objective="binary:logistic",
            eval_metric="logloss",
            random_state=args.seed,
            n_jobs=4,
        ),
    }

    args.output_dir.mkdir(parents=True, exist_ok=False)
    metrics = {
        "task": "repeated failed-login burst detection",
        "feature_columns": FEATURES,
        "classes": classes,
        "seed": args.seed,
        "weighting": "equal total sample weight per run_id",
        "split_summary": {},
        "models": {},
    }
    for name, frame in splits.items():
        group = frame[["run_id", "label"]].drop_duplicates()
        metrics["split_summary"][name] = {
            "windows": int(len(frame)),
            "runs": int(frame["run_id"].nunique()),
            "runs_per_label": group.groupby("label")["run_id"].nunique().to_dict(),
            "windows_per_label": frame["label"].value_counts().to_dict(),
        }

    try:
        for name, model in models.items():
            model.fit(x_train, y_train, sample_weight=weights)
            metrics["models"][name] = {}
            for split_name in ("validation", "test"):
                metrics["models"][name][split_name] = evaluate(
                    model, splits[split_name], splits[split_name][FEATURES], encoder, classes
                )
            joblib.dump(model, args.output_dir / f"{name}.joblib")
        joblib.dump(encoder, args.output_dir / "label_encoder.joblib")
        (args.output_dir / "feature_columns.json").write_text(
            json.dumps(FEATURES, indent=2) + "\n", encoding="utf-8"
        )
        (args.output_dir / "training_metrics.json").write_text(
            json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except Exception:
        # Keep any partial diagnostic artifacts in their new, versioned directory;
        # never remove or overwrite prior models automatically.
        raise

    print(
        f"Trained app-v2 window baselines: train_windows={len(splits['train'])}, "
        f"train_runs={splits['train']['run_id'].nunique()}, features={len(FEATURES)}"
    )
    for name, scores in metrics["models"].items():
        val = scores["validation"]["run_level"]["f1_macro"]
        test = scores["test"]["run_level"]["f1_macro"]
        print(f"{name}: validation run macro-F1={val:.4f}; test run macro-F1={test:.4f}")
    print(f"Saved models/metrics to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
