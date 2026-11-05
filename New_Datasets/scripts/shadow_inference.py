#!/usr/bin/env python3
"""Safe shadow-only inference adapter for the Packet v3 model.

Reads a CSV containing one run/window per row, loads the feature order from
metrics.json, and writes prediction records to JSONL. It never calls a network
API and never performs a security action.
"""
from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd

FORBIDDEN = {
    "run_id", "label", "timestamp", "src_ip", "dst_ip", "src_mac",
    "dst_mac", "filename", "attack_type",
}


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True, help="Run/window feature CSV")
    p.add_argument("--output", required=True, help="Prediction JSONL output")
    p.add_argument(
        "--model-dir",
        default="New_Datasets/models/run_level_144_packet_v3",
    )
    p.add_argument("--contract-version", default="1.0")
    return p.parse_args()


def main():
    args = parse_args()
    model_dir = Path(args.model_dir)
    metrics = json.loads((model_dir / "metrics.json").read_text(encoding="utf-8"))
    features = list(metrics["features"])
    classes = list(metrics["classes"])

    if metrics["feature_count"] != len(features):
        raise SystemExit("Feature-count mismatch in metrics.json")

    df = pd.read_csv(args.input)
    forbidden_present = sorted(set(df.columns) & FORBIDDEN)
    missing = [feature for feature in features if feature not in df.columns]
    if missing:
        raise SystemExit("Missing model features: " + ", ".join(missing))

    model = joblib.load(model_dir / "random_forest.joblib")
    encoder = joblib.load(model_dir / "label_encoder.joblib")
    X = df[features].apply(pd.to_numeric, errors="coerce")
    if X.isna().any().any():
        bad = X.columns[X.isna().any()].tolist()
        raise SystemExit("Non-numeric or missing feature values: " + ", ".join(bad))

    predictions = encoder.inverse_transform(model.predict(X))
    probabilities = model.predict_proba(X)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    observed = datetime.now(timezone.utc).isoformat()
    with output.open("w", encoding="utf-8") as handle:
        for index, (prediction, probability) in enumerate(zip(predictions, probabilities)):
            class_probabilities = {
                str(label): float(value)
                for label, value in zip(encoder.classes_, probability)
            }
            record = {
                "inference_id": str(uuid.uuid4()),
                "observed_at": observed,
                "row_index": index,
                "predicted_label": str(prediction),
                "confidence": float(max(probability)),
                "class_probabilities": class_probabilities,
                "model_version": "run_level_144_packet_v3",
                "feature_contract_version": args.contract_version,
                "mode": "shadow_only",
                "network_actions_enabled": False,
                "blocking_enabled": False,
                "quarantine_enabled": False,
                "rerouting_enabled": False,
            }
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    print("SHADOW_INFERENCE_OK")
    print("rows:", len(df))
    print("output:", output)
    print("forbidden_columns_present:", forbidden_present)
    print("network_actions_enabled: false")


if __name__ == "__main__":
    main()
