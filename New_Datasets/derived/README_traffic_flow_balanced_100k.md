# Balanced Traffic-Flow Training View

This directory contains a separate legacy traffic-flow experiment. It is not a replacement for `New_Datasets/processed/packetin_valid_non_holdout_flow.csv` and must not be described as a `packetin_window` dataset.

## Artifacts

- `traffic_flow_balanced_100k_train.csv`: exactly 100,000 training rows, 25,000 per class.
- `traffic_flow_original_test.csv`: untouched 20% row-level test partition from the original source.
- `traffic_flow_balanced_100k_report.json`: reproducibility and provenance report.
- `../scripts/build_balanced_traffic_flow.py`: deterministic builder.

## Important provenance

The source is `labeled_traffic_features.csv`, which contains flow/traffic-monitor statistics. The 100,000-row training view is built **after** the train/test split. The test rows are never copied into training. Because the source contains only 13,691 `Malicious_POST` rows and 17,963 `SYN_Flood` rows, those two classes use replacement within training to reach 25,000 rows each. The output therefore has 100,000 rows but not 100,000 unique observations. The report records the exact reuse counts.

This is acceptable as a training-balance experiment, but it does not satisfy a claim of 100,000 unique labeled captures. To obtain that claim, additional real collection is still required.

## Preliminary evaluation

An ExtraTrees baseline trained on the 100,000-row balanced view and evaluated on the untouched original test partition produced:

- Accuracy: 97.8755%
- Balanced accuracy: 98.2994%
- Macro-F1: 95.0419%

The test partition remains naturally imbalanced, so balanced accuracy and per-class metrics should be reported alongside ordinary accuracy. This is a preliminary row-level result; a final claim requires restoring reliable `run_id` metadata for Normal runs and performing a true run-level split.
