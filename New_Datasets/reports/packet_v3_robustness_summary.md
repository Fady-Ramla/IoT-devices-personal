# Packet v3 Robustness Evaluation

## Dataset

- Accepted balanced runs: 144
- Runs per class: 36
- Classes: Normal, SYN_Flood, Port_Scan, Malicious_POST
- Evaluation unit: one aggregated row per independent run
- Split policy: grouped by run_id
- Seeds: 7, 21, 42, 84, 123

## Results

| Metric | Mean | Std |
|---|---:|---:|
| Validation accuracy | 98.18% | 2.49% |
| Validation macro-F1 | 98.18% | 2.49% |
| Test accuracy | 92.73% | 4.07% |
| Test macro-F1 | 92.74% | 4.12% |

## Test range

- Minimum test accuracy: 86.36%
- Maximum test accuracy: 95.45%

## Decision

Packet v3 is accepted as a clean balanced candidate for shadow-only online inference.

It is not approved for automatic blocking, quarantine, rerouting, or any other security action. The main observed overlap is between Malicious_POST and Normal, with occasional SYN_Flood versus Port_Scan confusion.

The evaluation remains limited by the small number of test runs per seed. Additional accepted runs or repeated grouped cross-validation can improve confidence.
