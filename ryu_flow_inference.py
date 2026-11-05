import joblib
import numpy as np
import pandas as pd
from pathlib import Path

MODEL_DIR = Path("New_Datasets/models/packetin_ryu_flow_v1")

bundle = joblib.load(MODEL_DIR / "model.joblib")
model = bundle["model"]
encoder = bundle["encoder"]
FEATURES = bundle["features"]
CATEGORICAL = ["protocol", "source"]


def predict_ryu_flow(record):
    row = pd.DataFrame([record])

    for feature in FEATURES:
        if feature not in row.columns:
            raise ValueError(f"Missing Ryu feature: {feature}")

    encoded = encoder.transform(row[CATEGORICAL])
    columns = []

    for feature in FEATURES:
        if feature in CATEGORICAL:
            index = CATEGORICAL.index(feature)
            columns.append(encoded[:, index])
        else:
            columns.append(
                pd.to_numeric(
                    row[feature],
                    errors="coerce"
                ).fillna(0.0).to_numpy(dtype=float)
            )

    x = np.column_stack(columns)

    probabilities = model.predict_proba(x)[0]
    index = int(np.argmax(probabilities))

    return {
        "predicted_label": str(model.classes_[index]),
        "confidence": float(probabilities[index]),
        "source": record.get("source"),
        "model_feature_count": len(FEATURES),
    }


if __name__ == "__main__":
    sample = {
        "protocol": "tcp",
        "src_port": 42110,
        "dst_port": 5000,
        "priority": 100,
        "packet_count": 120,
        "byte_count": 5280,
        "packet_rate": 60.0,
        "byte_rate": 2640.0,
        "duration_sec": 2.0,
        "avg_packet_size": 44.0,
        "syn_count": 120,
        "ack_count": 0,
        "rst_count": 0,
        "fin_count": 0,
        "syn_ack_ratio": 0.0,
        "rst_ratio": 0.0,
        "unique_dst_ports": 1,
        "failed_connection_count": 0,
        "tcp_fraction": 1.0,
        "udp_fraction": 0.0,
        "icmp_fraction": 0.0,
        "source": "packetin_window",
    }

    print(predict_ryu_flow(sample))
