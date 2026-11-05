import joblib
import numpy as np
import pandas as pd
from pathlib import Path

model_dir = Path("New_Datasets/models/packetin_ryu_flow_v1")
data_path = Path(
    "New_Datasets/splits/packetin_valid_non_holdout_flow/test.csv"
)

bundle = joblib.load(model_dir / "model.joblib")
model = bundle["model"]
encoder = bundle["encoder"]
features = bundle["features"]

df = pd.read_csv(data_path)
sample = df.iloc[[0]].copy()

categorical = ["protocol", "source"]
encoded_categorical = encoder.transform(sample[categorical])

columns = []

for feature in features:
    if feature in categorical:
        index = categorical.index(feature)
        columns.append(encoded_categorical[:, index])
    else:
        value = pd.to_numeric(
            sample[feature],
            errors="coerce"
        ).fillna(0.0).to_numpy(dtype=float)

        columns.append(value)

x = np.column_stack(columns)

prediction = model.predict(x)[0]
confidence = float(model.predict_proba(x).max())

print("Prediction:", prediction)
print("Confidence:", round(confidence, 4))
print("Input feature count:", x.shape[1])
print("Label supplied to model: NO")
print("Source:", sample["source"].iloc[0])
print("Actual label used only for display:", sample["label"].iloc[0])
