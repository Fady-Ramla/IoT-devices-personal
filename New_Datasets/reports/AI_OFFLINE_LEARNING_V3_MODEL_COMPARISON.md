# TrustFlow AI Offline Learning V3 — Model Comparison Report

**Prepared:** 18 November 2026
**Dataset:** `packetin_window_4class_22features.csv`
**Scope:** Four individual classifiers plus the selected four-model weighted soft-voting ensemble. An equal-weight ensemble is included as a secondary reference.

## Executive summary

The V3 offline dataset contains **102,425 real, eligible observations** from completed runs and exactly **22 Ryu `packetin_window` flow features**. Observation IDs are unique, model features have no blank values, and the frozen generation range **550–709** is absent from the dataset and splits. Runs—not individual observations—were kept disjoint across Train, Validation, and Test.

On the held-out **Validation runs only** (186 runs), the weighted soft-voting ensemble was the strongest overall candidate among those evaluated: **94.09% run accuracy, 92.63% balanced accuracy, and 92.58% run Macro-F1**. Its per-class recall was **85.19% for `Malicious_POST`, 96.43% for `Normal`, 88.89% for `Port_Scan`, and 100.00% for `SYN_Flood`.

These are **development/selection results, not final independent test results**. The current 22-feature experiments did not read or score `test.csv`. However, the Test split had been examined in earlier experiments using a 20-feature contract; therefore it should not be presented as a completely untouched final holdout. Generations 550–709 are excluded, and no rows from that reserved range are available in this V3 dataset.

## 1. Dataset and feature contract

### Dataset facts

| Item | Value |
|---|---:|
| Eligible rows | 102,425 |
| Unique observation IDs | 102,425; 0 duplicates |
| Missing model-feature values | 0 |
| Source filter | `source == packetin_window` |
| Run-group holdout | Generations 550–709 excluded; 0 rows included |
| Labels | `Normal`, `Malicious_POST`, `Port_Scan`, `SYN_Flood` |

Row and run counts by label in the full dataset:

| Label | Rows | Runs |
|---|---:|---:|
| Normal | 27,224 | 747 |
| Port_Scan | 25,949 | 183 |
| SYN_Flood | 25,263 | 133 |
| Malicious_POST | 23,989 | 177 |
| **Total** | **102,425** | **1,240** |

The row distribution is reasonably balanced. The number of runs per class is not balanced, particularly because Normal contains 747 runs. This is why the report includes balanced accuracy, Macro-F1, and class-level recall in addition to overall accuracy.

### Split sizes

The split is grouped by `run_id`; observations from one run never cross split boundaries.

| Split | Rows | Runs | Run counts (Malicious_POST / Normal / Port_Scan / SYN_Flood) |
|---|---:|---:|---|
| Train | 71,470 | 868 | 124 / 523 / 128 / 93 |
| Validation | 15,114 | 186 | 27 / 112 / 27 / 20 |
| Test | 15,841 | 186 | 26 / 112 / 28 / 20 |

### Exact 22-feature list

The feature columns are preserved from Ryu's `packetin_window` output; no feature was added or removed for the V3 training CSV:

1. `protocol`
2. `src_port`
3. `dst_port`
4. `priority`
5. `packet_count`
6. `byte_count`
7. `packet_rate`
8. `byte_rate`
9. `duration_sec`
10. `avg_packet_size`
11. `syn_count`
12. `ack_count`
13. `rst_count`
14. `fin_count`
15. `syn_ack_ratio`
16. `rst_ratio`
17. `unique_dst_ports`
18. `failed_connection_count`
19. `tcp_fraction`
20. `udp_fraction`
21. `icmp_fraction`
22. `source`

`run_id` and `observation_id` are retained in CSVs for audit, grouping, and leakage checks; neither is a model input. `label` is the target.

### Encoding used by these experiments

The CSV preserves the original categorical fields. For these tree-model experiments, the scripts apply this deterministic mapping:

- `protocol`: TCP → 6, UDP → 17, ICMP → 1, ICMPv6 → 58, IGMP → 2; `other`/`unknown` → 0.
- `source`: `packetin_window` → 1.

Because the CSV is filtered to `source=packetin_window`, `source` is constant and has no class-discriminating information. It remains included to honor the 22-feature Ryu contract. Any reproduction or deployment must use the same feature order and encoding, or explicitly document a new model contract.

## 2. Training and evaluation methodology

- **Prediction/decision unit:** one complete run. For each run, the scripts average model class-probabilities across its observations and choose the class with the highest mean probability.
- **Leakage protection:** split by `run_id`, not by individual rows. Train, Validation, and Test run-ID sets are pairwise disjoint.
- **Sample weights:** each run has equal base total contribution (`1 / observations_in_run` per observation); Normal-run weights are multiplied by **1.30**. Weights are normalized to mean 1.
- **Selection:** Validation run-level Macro-F1 is the primary ranking metric, with balanced accuracy, attack recall, and accuracy used as tie-break/context metrics.
- **Resource settings:** model comparisons are run sequentially with one model thread where applicable. The four-model ensemble experiment retains only Validation probability arrays and saves metrics—not fitted model files.
- **Test discipline:** current V3 model-comparison scripts do not read or score `test.csv`.

### Metric definitions

- **Accuracy:** fraction of runs assigned the exact correct label; affected by the larger Normal-run count.
- **Balanced accuracy:** average recall over the four labels.
- **Macro-F1:** unweighted average of each class's F1, so each class has equal influence.
- **Attack-vs-Normal recall:** fraction of all attack runs predicted as any of the three attack labels; this does not require identifying the exact attack subtype.
- **Per-class recall:** fraction of runs of a specific class correctly identified. This is critical for detecting a model that has good overall attack recall while missing `Malicious_POST`.

## 3. Five model candidates and results

All scores below are **run-level Validation scores**. Percentage values are rounded to two decimal places.

| Candidate | Accuracy | Balanced accuracy | Macro-F1 | Any-attack recall | Normal recall |
|---|---:|---:|---:|---:|---:|
| Random Forest | 86.56% | 89.50% | 85.51% | **95.95%** | 83.93% |
| XGBoost | 89.78% | 83.81% | 85.36% | 81.08% | **98.21%** |
| ExtraTrees | 90.86% | **90.26%** | 88.82% | 94.59% | 91.96% |
| HistGradientBoosting (regularized) | 92.47% | 88.12% | 90.17% | 86.49% | **98.21%** |
| **Weighted soft-voting ensemble** | **94.09%** | 92.63% | **92.58%** | 93.24% | 96.43% |

The equal-weight ensemble was an additional comparison, not counted as a sixth standalone model: Accuracy 93.55%, balanced accuracy 91.70%, Macro-F1 91.93%, any-attack recall 91.89%, Normal recall 96.43%.

### 3.1 Random Forest

**Configuration:** 200 trees, `max_features=sqrt`, `min_samples_leaf=2`; one thread; seed 20261105. Training used the common run-based weights and Normal multiplier 1.30.

**Run-level validation:** Accuracy 86.56%, balanced accuracy 89.50%, Macro-F1 85.51%.

| Class | Precision | Recall | F1 | Validation runs |
|---|---:|---:|---:|---:|
| Malicious_POST | 58.54% | **88.89%** | 70.59% | 27 |
| Normal | 96.91% | 83.93% | 89.95% | 112 |
| Port_Scan | 92.00% | 85.19% | 88.46% | 27 |
| SYN_Flood | 86.96% | 100.00% | 93.02% | 20 |

**Interpretation:** strongest `Malicious_POST` recall among the four individual models in this comparison (24 of 27 runs), and perfect SYN_Flood recall. Its lower `Malicious_POST` precision (58.54%) means many runs predicted as Malicious_POST were actually another class, and its Normal recall was lower than the other leading candidates.

### 3.2 XGBoost

**Configuration:** 200 boosting rounds, max depth 3, learning rate 0.05, `min_child_weight=2`, row/column subsampling 0.9, L2 regularization 1.0, histogram tree method, max bin 64; one thread; seed 20261105. Same sample weights as other candidates.

**Run-level validation:** Accuracy 89.78%, balanced accuracy 83.81%, Macro-F1 85.36%.

| Class | Precision | Recall | F1 | Validation runs |
|---|---:|---:|---:|---:|
| Malicious_POST | 100.00% | 48.15% | 65.00% | 27 |
| Normal | 88.71% | **98.21%** | 93.22% | 112 |
| Port_Scan | 96.00% | 88.89% | 92.31% | 27 |
| SYN_Flood | 83.33% | 100.00% | 90.91% | 20 |

**Interpretation:** very high Normal recall and precision for Malicious_POST, but it detected only 13 of 27 Malicious_POST runs. This makes the specific evaluated XGBoost configuration a poor standalone choice if missing Malicious_POST is costly. The result does not prove all possible XGBoost settings will behave this way.

### 3.3 ExtraTrees

**Configuration:** 200 extremely randomized trees, `max_features=0.7`, `min_samples_leaf=2`; one thread; seed 20261105. Same sample weights.

**Run-level validation:** Accuracy 90.86%, balanced accuracy **90.26%**, Macro-F1 88.82%.

| Class | Precision | Recall | F1 | Validation runs |
|---|---:|---:|---:|---:|
| Malicious_POST | 71.88% | 85.19% | 77.97% | 27 |
| Normal | 96.26% | 91.96% | 94.06% | 112 |
| Port_Scan | 92.31% | 88.89% | 90.57% | 27 |
| SYN_Flood | 90.48% | 95.00% | 92.68% | 20 |

**Interpretation:** strongest individual-model balance in this comparison (best individual balanced accuracy), with relatively strong recall for all four classes. It is a reasonable single-model baseline if deployment simplicity or inference cost is important. It is not the top Validation score overall.

### 3.4 HistGradientBoosting

**Selected validation configuration:** 250 iterations, learning rate 0.06, 15 leaf nodes, minimum 30 samples per leaf, L2 regularization 2.0, `early_stopping=False`; one thread; seed 20261105. Same sample weights.

**Run-level validation:** Accuracy 92.47%, balanced accuracy 88.12%, Macro-F1 90.17%.

| Class | Precision | Recall | F1 | Validation runs |
|---|---:|---:|---:|---:|
| Malicious_POST | 95.00% | 70.37% | 80.85% | 27 |
| Normal | 91.67% | **98.21%** | 94.83% | 112 |
| Port_Scan | 96.00% | 88.89% | 92.31% | 27 |
| SYN_Flood | 90.48% | 95.00% | 92.68% | 20 |

**Interpretation:** strong overall accuracy/Macro-F1 and the best Normal recall among individual models, but it detected 19 of 27 Malicious_POST runs. It is an attractive low-resource individual candidate when Normal classification matters, but its attack-recall trade-off must be considered.

### 3.5 Weighted four-model soft-voting ensemble

**Components:** Random Forest, XGBoost, ExtraTrees, and HistGradientBoosting. Each model outputs a class-probability vector per observation. Probabilities are combined with fixed weights, then averaged across observations in each run.

| Component | Weight |
|---|---:|
| Random Forest | 0.30 |
| XGBoost | 0.10 |
| ExtraTrees | 0.35 |
| HistGradientBoosting | 0.25 |
| **Total** | **1.00** |

**Run-level validation:** Accuracy **94.09%**, balanced accuracy 92.63%, Macro-F1 **92.58%**. It correctly classified 175 of 186 Validation runs.

| Class | Precision | Recall | F1 | Validation runs |
|---|---:|---:|---:|---:|
| Malicious_POST | 88.46% | 85.19% | 86.79% | 27 |
| Normal | 95.58% | 96.43% | 96.00% | 112 |
| Port_Scan | 96.00% | 88.89% | 92.31% | 27 |
| SYN_Flood | 90.91% | 100.00% | 95.24% | 20 |

Confusion matrix (true labels = rows; predicted labels = columns; order: `Malicious_POST`, `Normal`, `Port_Scan`, `SYN_Flood`):

```text
[[23,  4,  0,  0],
 [ 3,108,  1,  0],
 [ 0,  1, 24,  2],
 [ 0,  0,  0, 20]]
```

**Interpretation:** best overall Validation candidate among these five by accuracy and Macro-F1. It correctly identified 23/27 Malicious_POST, 108/112 Normal, 24/27 Port_Scan, and 20/20 SYN_Flood. It still misses four Malicious_POST runs and confuses two Port_Scan runs as SYN_Flood. The ensemble requires running four models at inference time, so CPU latency and resource usage must be measured before any Ryu integration.

### Equal-weight ensemble reference

The equal-weight ensemble assigns 0.25 to each model. It achieved run accuracy 93.55%, balanced accuracy 91.70%, Macro-F1 91.93%, Malicious_POST recall 81.48%, Normal recall 96.43%, Port_Scan recall 88.89%, and SYN_Flood recall 100%. The downweighted-XGBoost ensemble improved run Macro-F1 by 0.65 percentage points and Malicious_POST recall by 3.70 percentage points on this Validation set.

## 4. Recommendation

For **four-class development evaluation**, carry the weighted ensemble forward as the leading candidate because it had the best observed run-level accuracy and Macro-F1 and stronger `Malicious_POST` recall than HistGradientBoosting and XGBoost.

Use the objective to choose the operational candidate:

- If exact four-class predictions and balanced aggregate quality are the goal: evaluate the weighted ensemble further.
- If a single model and lower inference complexity are important: retain ExtraTrees as the leading individual baseline.
- If missing any attack is the primary concern: compare false-positive costs and consider Random Forest/ExtraTrees or a separately calibrated detection threshold; do not select on attack recall alone.
- If distinguishing Normal is the priority: HistGradientBoosting performed strongly, but it missed more Malicious_POST runs than the ensemble.

Do not claim perfect prediction. Validation contains only 27 Malicious_POST runs and 20 SYN_Flood runs, so one run changes class recall by about 3.70 and 5.00 percentage points respectively. Any next optimization should use new run groups or a predeclared validation procedure, not repeatedly tune on the same set.

## 5. Reproduction guide for the AI track

1. Load `packetin_window_4class_22features.csv`; target column is `label`.
2. Use the exact 22-feature list in `model_features_packetin_22_v1.json` and the categorical mappings stated above.
3. Exclude `run_id` and `observation_id` from model input. Keep `run_id` for grouping and run-level aggregation.
4. Prefer the delivered run-disjoint `packet_splits/train.csv`, `validation.csv`, and `test.csv`; do not randomly split observations. If regenerating splits, group by `run_id` and document the seed/ratios.
5. Reproduce the shared weighting: inverse observations per run, with Normal-run weight multiplier 1.30.
6. Evaluate both row-level and run-level metrics, but use run-level metrics for model comparison. Include confusion matrix and precision/recall/F1 for each class.
7. The ensemble recipe is a soft probability average with weights RF 0.30, XGBoost 0.10, ExtraTrees 0.35, HistGradientBoosting 0.25. It is a candidate recipe, not a deployment-ready artifact.
8. Keep the reserved generation range 550–709 out of every training, tuning, and validation operation.

## 6. Artifacts and reproduction scripts

The `Final_OFFLINE_CSV` branch contains the versioned 22-feature builder/config and the validation scripts. Relevant files include:

- `New_Datasets/config/model_features_packetin_22_v1.json`
- `New_Datasets/scripts/build_packetin_window_22features_v1.py`
- `New_Datasets/scripts/compare_rf_xgb_extratrees_packetin22_validation_only.py`
- `New_Datasets/scripts/tune_histgradientboosting_packetin22_validation_only.py`
- `New_Datasets/scripts/compare_four_model_ensemble_packetin22_validation_only.py`

The ensemble comparison script stores metrics only, not fitted models. A reproducible final artifact would require fitting the chosen ensemble on the approved training data, recording software versions and feature encodings, saving all component models and a manifest, and then benchmarking inference latency. Do not connect it to Ryu or enable enforcement actions until the model artifact, interface contract, and shadow-mode behavior are validated.

## 7. Limitations and reporting statement

- All reported model and ensemble scores in this document come from **Validation**; the current V3 model scripts did not read or score Test.
- The Test split was evaluated historically with a prior 20-feature baseline. It is not a pristine final test for the overall project.
- Generations 550–709 are absent from this dataset; no final holdout result is available here.
- Reusing Validation for multiple candidate comparisons can lead to selection optimism. Treat 94.09% accuracy and 92.58% Macro-F1 as development results, not guaranteed deployment performance.
- Row-level predictions are not independent because many observations come from each run. Run-level evaluation is the appropriate decision metric for the current workflow.
- The four-model ensemble costs more inference time and memory than one model. No live Ryu integration or response-time test was performed by these offline comparisons.

**Recommended wording for a project report:** “On a run-disjoint Validation set of 186 runs, a four-model weighted soft-voting ensemble achieved 94.09% accuracy and 92.58% Macro-F1. Results are developmental; the current experiment did not score Test, and an independent final holdout evaluation remains necessary.”
