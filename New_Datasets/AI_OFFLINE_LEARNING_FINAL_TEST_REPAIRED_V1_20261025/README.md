# Corrected final test holdout (test-only)

Standalone test-only package: 80 runs, 20 per class. It retains eligible original V3 final_test rows, excludes MP031 and MP008 because every malicious POST curl attempt timed out and application telemetry was absent, and replaces them with MP047 and MP048 after application POST/auth/401 telemetry verification. The original V3 package and repaired V2 development package are unchanged.

Use only after model/hyperparameters are frozen. Primary evaluation should use network-only Packet/Flow models because application telemetry availability varies across test runs. Do not tune against these test results.
