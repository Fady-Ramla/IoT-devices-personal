#!/usr/bin/env python3
"""Train and evaluate the run-level Flow v2 split without test-set tuning.

Protocol:
- Validate the existing 208/44/44 run-grouped splits and the 99-feature order.
- Fit fixed Random Forest and Extra Trees candidates on train only.
- Select one candidate by validation macro-F1 (accuracy as tie-breaker).
- Refit only that selected estimator on train+validation.
- Evaluate once on the held-out test split and save a report/model in a new
  timestamped directory. The CSV splits and the sealed 160-run holdout are not
  modified or accessed.
"""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

ROOT = Path.cwd()
SPLIT_DIR = ROOT / "New_Datasets/splits/run_level_296_flow"
METRICS_PATH = ROOT / "New_Datasets/models/run_level_296_flow_v2/metrics.json"
OUTPUT_BASE = ROOT / "New_Datasets/reports/flow_run_level_296_training"
MODEL_BASE = ROOT / "New_Datasets/models/flow_run_level_296_trained"
EXPECTED_ROWS = {"train.csv": 208, "validation.csv": 44, "test.csv": 44}
EXPECTED_PER_CLASS = {"train.csv": 52, "validation.csv": 11, "test.csv": 11}


def fail(message: str) -> None:
    raise SystemExit("STOPPED: " + message)


def read_split(name: str, feature_order: list[str], classes: list[str]):
    path = SPLIT_DIR / name
    if not path.is_file():
        fail(f"required split missing: {path}")
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        columns = list(reader.fieldnames or [])
        rows = list(reader)
    required = ["run_id", "label", *feature_order]
    missing = [column for column in required if column not in columns]
    if missing:
        fail(f"{name} missing required columns: {missing}")
    actual_features = [column for column in columns if column in set(feature_order)]
    if actual_features != feature_order:
        fail(f"{name} feature order differs from metrics.json")
    if len(rows) != EXPECTED_ROWS[name]:
        fail(f"{name} has {len(rows)} rows; expected {EXPECTED_ROWS[name]}")
    ids = [str(row.get("run_id", "")).strip() for row in rows]
    if any(not value for value in ids) or len(ids) != len(set(ids)):
        fail(f"{name} contains empty or duplicate run_id values")
    labels = [str(row.get("label", "")).strip() for row in rows]
    label_counts = {label: labels.count(label) for label in classes}
    if set(labels) != set(classes):
        fail(f"{name} contains unexpected labels: {sorted(set(labels))}")
    if any(label_counts[label] != EXPECTED_PER_CLASS[name] for label in classes):
        fail(f"{name} class counts are not the audited balanced counts: {label_counts}")
    try:
        X = np.asarray([[float(row[feature]) for feature in feature_order] for row in rows], dtype=np.float64)
    except (TypeError, ValueError) as exc:
        fail(f"{name} has non-numeric feature value: {exc}")
    if not np.isfinite(X).all():
        fail(f"{name} contains NaN or infinite feature values")
    return X, np.asarray(labels, dtype=object), set(ids), label_counts


def metrics_for(y_true, y_pred, classes):
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_precision": float(precision_score(y_true, y_pred, labels=classes, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(y_true, y_pred, labels=classes, average="macro", zero_division=0)),
        "macro_f1": float(f1_score(y_true, y_pred, labels=classes, average="macro", zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=classes).tolist(),
        "classification_report": classification_report(
            y_true, y_pred, labels=classes, output_dict=True, zero_division=0
        ),
    }


def main() -> int:
    if not METRICS_PATH.is_file():
        fail(f"metrics contract missing: {METRICS_PATH}")
    contract = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    feature_order = list(contract.get("features", []))
    classes = list(contract.get("classes", []))
    if contract.get("feature_count") != 99 or len(feature_order) != 99:
        fail("expected exactly 99 ordered features in metrics.json")
    if len(set(feature_order)) != 99:
        fail("metrics.json has duplicated feature names")
    expected_classes = {"Malicious_POST", "Normal", "Port_Scan", "SYN_Flood"}
    if set(classes) != expected_classes:
        fail(f"unexpected class contract: {classes}")

    data = {}
    for name in EXPECTED_ROWS:
        data[name] = read_split(name, feature_order, classes)
    for left, right in (("train.csv", "validation.csv"), ("train.csv", "test.csv"), ("validation.csv", "test.csv")):
        overlap = data[left][2] & data[right][2]
        if overlap:
            fail(f"run_id overlap between {left} and {right}: {len(overlap)}")
    all_ids = set.union(*(data[name][2] for name in EXPECTED_ROWS))
    if len(all_ids) != 296:
        fail(f"expected 296 distinct run IDs across splits, found {len(all_ids)}")

    X_train, y_train = data["train.csv"][0:2]
    X_val, y_val = data["validation.csv"][0:2]
    X_test, y_test = data["test.csv"][0:2]

    candidates = {
        "RandomForest": RandomForestClassifier(
            n_estimators=500,
            max_features="sqrt",
            min_samples_leaf=1,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        ),
        "ExtraTrees": ExtraTreesClassifier(
            n_estimators=500,
            max_features="sqrt",
            min_samples_leaf=1,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        ),
    }

    validation_results = {}
    fitted_candidates = {}
    for name, estimator in candidates.items():
        estimator.fit(X_train, y_train)
        pred = estimator.predict(X_val)
        validation_results[name] = metrics_for(y_val, pred, classes)
        fitted_candidates[name] = estimator
        print(
            f"VALIDATION {name}: accuracy={validation_results[name]['accuracy']:.4f} "
            f"macro_f1={validation_results[name]['macro_f1']:.4f} "
            f"balanced_accuracy={validation_results[name]['balanced_accuracy']:.4f}",
            flush=True,
        )

    # Fixed selection policy: highest validation macro-F1, then accuracy;
    # ties preserve the declared candidate order (RandomForest first).
    selected_name = max(
        candidates,
        key=lambda name: (
            validation_results[name]["macro_f1"],
            validation_results[name]["accuracy"],
        ),
    )
    print(f"SELECTED_BY_VALIDATION={selected_name}", flush=True)

    # Refit the validation-selected model on train+validation before the one
    # final test evaluation. Test labels are not used in model selection.
    final_model = candidates[selected_name]
    X_trainval = np.concatenate([X_train, X_val], axis=0)
    y_trainval = np.concatenate([y_train, y_val], axis=0)
    final_model.fit(X_trainval, y_trainval)
    test_predictions = final_model.predict(X_test)
    test_metrics = metrics_for(y_test, test_predictions, classes)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_dir = OUTPUT_BASE / stamp
    model_dir = MODEL_BASE / stamp
    report_dir.mkdir(parents=True, exist_ok=False)
    model_dir.mkdir(parents=True, exist_ok=False)
    joblib.dump(final_model, model_dir / "model.joblib")
    (model_dir / "feature_contract.json").write_text(
        json.dumps({"model": selected_name, "classes": classes, "features": feature_order}, indent=2) + "\n",
        encoding="utf-8",
    )

    report = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": "run_level_296_flow",
        "protocol": {
            "candidate_models": list(candidates),
            "selection_metric": "validation macro-F1, accuracy as tie-breaker",
            "final_fit": "train + validation",
            "test_used_for_selection_or_tuning": False,
            "test_evaluations": 1,
            "test_split_role": "final held-out evaluation only",
            "sealed_160_run_holdout_accessed": False,
        },
        "split_rows": {k: EXPECTED_ROWS[k] for k in EXPECTED_ROWS},
        "class_order": classes,
        "class_counts": {k: data[k][3] for k in EXPECTED_ROWS},
        "feature_count": len(feature_order),
        "feature_order_matches_metrics_json": True,
        "run_id_overlap": {"train_validation": 0, "train_test": 0, "validation_test": 0},
        "validation_candidate_metrics": validation_results,
        "selected_model": selected_name,
        "test_metrics": test_metrics,
        "test_metrics_percent": {
            key: round(test_metrics[key] * 100.0, 2)
            for key in ("accuracy", "balanced_accuracy", "macro_precision", "macro_recall", "macro_f1")
        },
        "model_path": str(model_dir / "model.joblib"),
        "feature_contract_path": str(model_dir / "feature_contract.json"),
    }
    report_path = report_dir / "metrics.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("\nFINAL TEST RESULT (one held-out evaluation; percentages):", flush=True)
    for key, value in report["test_metrics_percent"].items():
        print(f"{key}: {value:.2f}%", flush=True)
    print("\nPer-class test metrics:", flush=True)
    for label in classes:
        row = test_metrics["classification_report"][label]
        print(
            f"{label}: precision={row['precision']*100:.2f}% "
            f"recall={row['recall']*100:.2f}% f1={row['f1-score']*100:.2f}% support={int(row['support'])}",
            flush=True,
        )
    print("Confusion matrix (true rows, predicted columns; class order below):", flush=True)
    print(classes, flush=True)
    for row in test_metrics["confusion_matrix"]:
        print(row, flush=True)
    print(f"REPORT_JSON={report_path}", flush=True)
    print(f"MODEL={model_dir / 'model.joblib'}", flush=True)
    print("No source CSVs changed; sealed 160-run holdout was not accessed.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
