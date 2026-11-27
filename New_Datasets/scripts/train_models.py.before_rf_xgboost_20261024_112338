#!/usr/bin/env python3
"""Train offline RF and optionally XGBoost models on a prepared split."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

FEATURES = [
    "protocol", "src_port", "dst_port", "packet_count", "byte_count",
    "packet_rate", "byte_rate", "duration_sec", "avg_packet_size",
    "syn_count", "ack_count", "rst_count", "fin_count", "syn_ack_ratio",
    "rst_ratio", "unique_dst_ports", "failed_connection_count",
    "tcp_fraction", "udp_fraction", "icmp_fraction",
]


def encode(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    x = df.reindex(columns=columns).copy()
    if "protocol" in x:
        x["protocol"] = x["protocol"].astype(str).str.lower().map({"tcp": 6, "udp": 17, "icmp": 1}).fillna(0)
    for col in x.columns:
        x[col] = pd.to_numeric(x[col], errors="coerce").fillna(0)
    return x


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--split-dir", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--level", choices=["flow", "packet"], default="flow")
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
        from sklearn.preprocessing import LabelEncoder
    except ImportError as exc:
        raise SystemExit("scikit-learn is required: python3 -m pip install scikit-learn") from exc
    try:
        import joblib
    except ImportError as exc:
        raise SystemExit("joblib is required: python3 -m pip install joblib") from exc

    columns = FEATURES if args.level == "flow" else ["protocol", "src_port", "dst_port", "packet_length", "tcp_syn", "tcp_ack", "tcp_rst", "tcp_fin", "icmp_type", "arp_operation"]
    train = pd.read_csv(args.split_dir / "train.csv")
    val = pd.read_csv(args.split_dir / "validation.csv")
    test = pd.read_csv(args.split_dir / "test.csv")
    if train.empty or val.empty or test.empty:
        raise SystemExit("train/validation/test must all contain rows; collect more completed runs")
    encoder = LabelEncoder().fit(train["label"])
    unknown = (set(val["label"]) | set(test["label"])) - set(encoder.classes_)
    if unknown:
        raise SystemExit(f"labels absent from train split: {sorted(unknown)}")
    y_train = encoder.transform(train["label"])
    y_val = encoder.transform(val["label"])
    y_test = encoder.transform(test["label"])
    x_train, x_val, x_test = encode(train, columns), encode(val, columns), encode(test, columns)
    model = RandomForestClassifier(n_estimators=400, class_weight="balanced", random_state=args.seed, n_jobs=-1)
    model.fit(x_train, y_train)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.output_dir / "random_forest.joblib")
    joblib.dump(encoder, args.output_dir / "label_encoder.joblib")
    metrics = {
        "model": "random_forest",
        "features": columns,
        "classes": encoder.classes_.tolist(),
        "validation": {"accuracy": float(accuracy_score(y_val, model.predict(x_val)))},
        "test": {"accuracy": float(accuracy_score(y_test, model.predict(x_test))), "confusion_matrix": confusion_matrix(y_test, model.predict(x_test)).tolist(), "classification_report": classification_report(y_test, model.predict(x_test), target_names=encoder.classes_, output_dict=True, zero_division=0)},
    }
    (args.output_dir / "random_forest_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics["test"], indent=2))

    try:
        from xgboost import XGBClassifier
    except ImportError:
        print("xgboost not installed; Random Forest completed. Install xgboost to train the second model.")
        return 0
    xgb = XGBClassifier(n_estimators=400, max_depth=6, learning_rate=0.05, subsample=0.9, colsample_bytree=0.9, objective="multi:softprob", eval_metric="mlogloss", random_state=args.seed)
    xgb.fit(x_train, y_train, eval_set=[(x_val, y_val)], verbose=False)
    joblib.dump(xgb, args.output_dir / "xgboost.joblib")
    print("wrote xgboost.joblib")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
