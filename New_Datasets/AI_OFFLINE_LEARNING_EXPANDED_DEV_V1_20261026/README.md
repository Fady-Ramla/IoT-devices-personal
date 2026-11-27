# Expanded development Packet/Flow dataset

This package combines the prior repaired train/validation-only candidate (80 runs) with 160 verified expanded-development profiles. Six failed captures and eight completed captures without required application telemetry were excluded; fourteen verified replacements preserve their class/split assignments. Final test data is neither included nor read. Each of four classes has 48 training runs and 12 validation runs. Splits are run/profile-grouped; no oversampling or synthetic rows are used.

Validation metrics are for model development only and are not final-test performance.
