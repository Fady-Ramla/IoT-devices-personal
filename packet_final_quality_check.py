import pandas as pd
import numpy as np
import os


# ============================================================
# CONFIG
# ============================================================

FILE = "labeled_packet_features_ML.csv"

VALID_LABELS = {
    "normal",
    "syn_flood",
    "malicious_post",
    "port_scan",
}

ATTACK_LABELS = {
    "syn_flood",
    "malicious_post",
    "port_scan",
}

NUMERIC_COLUMNS = [
    "src_port",
    "dst_port",
    "ip_proto",
    "ttl",
    "tcp",
    "udp",
    "icmp",
    "arp",
    "http",
    "https",
    "dns",
    "ssh",
    "telnet",
    "smtp",
    "syn_flag_number",
    "ack_flag_number",
    "fin_flag_number",
    "rst_flag_number",
    "psh_flag_number",
    "packet_length",
    "payload_length",
]


# ============================================================
# HEADER
# ============================================================

print()
print("=" * 70)
print("        PACKET FINAL QUALITY CHECK")
print("=" * 70)
print()


# ============================================================
# FILE CHECK
# ============================================================

if not os.path.exists(FILE):
    print(f"[ERROR] File not found: {FILE}")
    raise SystemExit(1)

print(f"File: {FILE}")

df = pd.read_csv(FILE)

print(f"Rows: {len(df):,}")
print(f"Columns: {len(df.columns)}")
print()


# ============================================================
# 1. REQUIRED COLUMNS
# ============================================================

print("-" * 70)
print("1. REQUIRED COLUMNS")
print("-" * 70)

required_columns = [
    "run_id",
    "label",
    "packet_length",
    "payload_length",
]

missing_required = [
    c for c in required_columns
    if c not in df.columns
]

if missing_required:
    print("[FAIL]")
    print("Missing required columns:")

    for c in missing_required:
        print(f"  - {c}")

else:
    print("[PASS] All required columns exist.")

print()


# ============================================================
# 2. LABEL CHECK
# ============================================================

print("-" * 70)
print("2. LABEL CHECK")
print("-" * 70)

if "label" not in df.columns:
    print("[FAIL] label column is missing.")
else:

    labels = set(
        df["label"]
        .dropna()
        .astype(str)
        .str.strip()
        .unique()
    )

    unexpected_labels = labels - VALID_LABELS

    print("Labels found:")

    for label in sorted(labels):
        count = (
            df["label"]
            .astype(str)
            .str.strip()
            .eq(label)
            .sum()
        )

        percentage = (
            count / len(df) * 100
            if len(df) > 0
            else 0
        )

        print(
            f"  {label:20s}"
            f"{count:10,}"
            f" ({percentage:6.2f}%)"
        )

    print()

    if unexpected_labels:
        print("[FAIL] Unexpected labels found:")

        for label in sorted(
            unexpected_labels
        ):
            print(f"  - {label}")

    else:
        print("[PASS] Only the expected 4 labels exist.")

print()


# ============================================================
# 3. LABEL MISSING VALUES
# ============================================================

print("-" * 70)
print("3. LABEL MISSING VALUES")
print("-" * 70)

if "label" in df.columns:

    missing_labels = df["label"].isna().sum()

    empty_labels = (
        df["label"]
        .astype(str)
        .str.strip()
        .eq("")
        .sum()
    )

    print(
        f"Missing label values: {missing_labels:,}"
    )

    print(
        f"Empty label values:   {empty_labels:,}"
    )

    if (
        missing_labels == 0
        and empty_labels == 0
    ):
        print("[PASS] No missing/empty labels.")

    else:
        print("[FAIL] Missing/empty labels detected.")

print()


# ============================================================
# 4. RUN_ID INTEGRITY
# ============================================================

print("-" * 70)
print("4. RUN_ID INTEGRITY")
print("-" * 70)

if (
    "run_id" not in df.columns
    or "label" not in df.columns
):

    print("[FAIL] run_id or label column is missing.")

else:

    run_id_clean = (
        df["run_id"]
        .fillna("")
        .astype(str)
        .str.strip()
    )

    label_clean = (
        df["label"]
        .fillna("")
        .astype(str)
        .str.strip()
    )

    attack_mask = label_clean.isin(
        ATTACK_LABELS
    )

    attack_rows = df[attack_mask]

    missing_attack_run_id = (
        run_id_clean[attack_mask]
        .eq("")
        .sum()
    )

    print(
        f"Attack rows: "
        f"{len(attack_rows):,}"
    )

    print(
        f"Attack rows with missing run_id: "
        f"{missing_attack_run_id:,}"
    )

    if missing_attack_run_id == 0:
        print(
            "[PASS] Every attack row has a valid run_id."
        )
    else:
        print(
            "[FAIL] Some attack rows have missing run_id."
        )

    print()

    # --------------------------------------------------------
    # Run IDs by label
    # --------------------------------------------------------

    print("Run-level inventory:")

    for label in sorted(
        ATTACK_LABELS
    ):

        mask = label_clean.eq(label)

        runs = sorted(
            run_id_clean[mask]
            .replace("", np.nan)
            .dropna()
            .unique()
        )

        print(
            f"  {label:20s}"
            f"{len(runs):5d} unique runs"
        )

print()


# ============================================================
# 5. NORMAL RUN_ID CHECK
# ============================================================

print("-" * 70)
print("5. NORMAL RUN_ID CHECK")
print("-" * 70)

if (
    "run_id" in df.columns
    and "label" in df.columns
):

    normal_mask = label_clean.eq(
        "normal"
    )

    normal_run_ids = (
        run_id_clean[normal_mask]
        .replace("", np.nan)
        .dropna()
        .unique()
    )

    normal_missing = (
        run_id_clean[normal_mask]
        .eq("")
        .sum()
    )

    print(
        f"Normal rows: "
        f"{normal_mask.sum():,}"
    )

    print(
        f"Normal rows with empty run_id: "
        f"{normal_missing:,}"
    )

    print(
        f"Normal unique run_ids: "
        f"{len(normal_run_ids):,}"
    )

    if normal_missing > 0:
        print(
            "[INFO] Normal run_id is empty for "
            "some/all normal rows."
        )

        print(
            "This is NOT treated as a packet-quality "
            "failure here."
        )

        print(
            "It will be handled later in the "
            "grouped-split strategy."
        )

    else:
        print(
            "[PASS] Normal rows have run_id values."
        )

print()


# ============================================================
# 6. DUPLICATE ROW CHECK
# ============================================================

print("-" * 70)
print("6. DUPLICATE ROW CHECK")
print("-" * 70)

duplicate_rows = df.duplicated().sum()

print(
    f"Exact duplicate rows: "
    f"{duplicate_rows:,}"
)

if duplicate_rows == 0:
    print("[PASS] No exact duplicate rows.")
else:
    print(
        "[INFO] Duplicate rows exist."
    )
    print(
        "This is reported only; "
        "the dataset will NOT be modified."
    )

print()


# ============================================================
# 7. NaN / INF CHECK
# ============================================================

print("-" * 70)
print("7. NaN / INF CHECK")
print("-" * 70)

nan_total = int(
    df.isna().sum().sum()
)

print(
    f"Total NaN / missing cells: "
    f"{nan_total:,}"
)

numeric_df = df.select_dtypes(
    include=[np.number]
)

if numeric_df.shape[1] > 0:

    inf_total = int(
        np.isinf(
            numeric_df.to_numpy()
        ).sum()
    )

else:

    inf_total = 0

print(
    f"Total numeric Inf cells: "
    f"{inf_total:,}"
)

if nan_total == 0 and inf_total == 0:
    print("[PASS] No NaN or Inf values.")

else:
    print(
        "[FAIL] NaN and/or Inf values detected."
    )

print()


# ============================================================
# 8. NUMERIC COLUMN CHECK
# ============================================================

print("-" * 70)
print("8. NUMERIC COLUMN CHECK")
print("-" * 70)

missing_numeric_columns = []
non_numeric_columns = []

for column in NUMERIC_COLUMNS:

    if column not in df.columns:

        missing_numeric_columns.append(
            column
        )

        continue

    if not pd.api.types.is_numeric_dtype(
        df[column]
    ):

        non_numeric_columns.append(
            column
        )

if missing_numeric_columns:

    print("Missing expected numeric columns:")

    for column in missing_numeric_columns:
        print(f"  - {column}")

else:

    print(
        "[PASS] All expected numeric columns exist."
    )

if non_numeric_columns:

    print()
    print("Columns expected to be numeric but are not:")

    for column in non_numeric_columns:
        print(f"  - {column}")

else:

    print(
        "[PASS] Numeric columns have numeric dtypes."
    )

print()


# ============================================================
# 9. PACKET LENGTH VALIDATION
# ============================================================

print("-" * 70)
print("9. PACKET LENGTH VALIDATION")
print("-" * 70)

for column in [
    "packet_length",
    "payload_length",
]:

    if column not in df.columns:
        print(
            f"[FAIL] Missing column: {column}"
        )
        continue

    negative_count = (
        pd.to_numeric(
            df[column],
            errors="coerce",
        )
        < 0
    ).sum()

    print(
        f"{column:20s}"
        f"negative values: "
        f"{negative_count:,}"
    )

    if negative_count == 0:
        print(
            f"  [PASS] No negative {column}."
        )
    else:
        print(
            f"  [FAIL] Negative {column} detected."
        )

print()


# ============================================================
# 10. PORT VALIDATION
# ============================================================

print("-" * 70)
print("10. PORT VALIDATION")
print("-" * 70)

for column in [
    "src_port",
    "dst_port",
]:

    if column not in df.columns:
        print(
            f"[INFO] {column} not present."
        )
        continue

    values = pd.to_numeric(
        df[column],
        errors="coerce",
    )

    invalid = (
        (values < 0)
        | (values > 65535)
    ).sum()

    print(
        f"{column:20s}"
        f"invalid values: "
        f"{invalid:,}"
    )

    if invalid == 0:
        print(
            f"  [PASS] {column} values are valid."
        )
    else:
        print(
            f"  [FAIL] Invalid {column} values detected."
        )

print()


# ============================================================
# 11. PROTOCOL VALIDATION
# ============================================================

print("-" * 70)
print("11. IP PROTOCOL VALIDATION")
print("-" * 70)

if "ip_proto" in df.columns:

    proto = pd.to_numeric(
        df["ip_proto"],
        errors="coerce",
    )

    invalid_proto = (
        (proto < 0)
        | (proto > 255)
    ).sum()

    print(
        f"Invalid protocol values: "
        f"{invalid_proto:,}"
    )

    if invalid_proto == 0:
        print(
            "[PASS] IP protocol values are valid."
        )
    else:
        print(
            "[FAIL] Invalid IP protocol values detected."
        )

else:

    print(
        "[INFO] ip_proto column not found."
    )

print()


# ============================================================
# 12. BASIC PACKET STATISTICS
# ============================================================

print("-" * 70)
print("12. BASIC PACKET STATISTICS")
print("-" * 70)

if "packet_length" in df.columns:

    print(
        "packet_length:"
    )

    print(
        f"  min  = "
        f"{df['packet_length'].min()}"
    )

    print(
        f"  max  = "
        f"{df['packet_length'].max()}"
    )

    print(
        f"  mean = "
        f"{df['packet_length'].mean():.2f}"
    )

if "payload_length" in df.columns:

    print()

    print(
        "payload_length:"
    )

    print(
        f"  min  = "
        f"{df['payload_length'].min()}"
    )

    print(
        f"  max  = "
        f"{df['payload_length'].max()}"
    )

    print(
        f"  mean = "
        f"{df['payload_length'].mean():.2f}"
    )

print()


# ============================================================
# 13. FINAL VERDICT
# ============================================================

print("=" * 70)
print("        FINAL PACKET QUALITY VERDICT")
print("=" * 70)

failures = []

if missing_required:
    failures.append(
        "Missing required columns"
    )

if (
    "label" in df.columns
    and unexpected_labels
):
    failures.append(
        "Unexpected labels"
    )

if (
    "label" in df.columns
    and (
        missing_labels > 0
        or empty_labels > 0
    )
):
    failures.append(
        "Missing/empty labels"
    )

if missing_attack_run_id > 0:
    failures.append(
        "Attack rows missing run_id"
    )

if nan_total > 0:
    failures.append(
        "NaN values"
    )

if inf_total > 0:
    failures.append(
        "Inf values"
    )

if non_numeric_columns:
    failures.append(
        "Invalid numeric dtypes"
    )

if missing_numeric_columns:
    failures.append(
        "Missing numeric columns"
    )

if "packet_length" in df.columns:

    if (
        pd.to_numeric(
            df["packet_length"],
            errors="coerce",
        )
        < 0
    ).sum() > 0:

        failures.append(
            "Negative packet_length"
        )

if "payload_length" in df.columns:

    if (
        pd.to_numeric(
            df["payload_length"],
            errors="coerce",
        )
        < 0
    ).sum() > 0:

        failures.append(
            "Negative payload_length"
        )

if "src_port" in df.columns:

    src_port = pd.to_numeric(
        df["src_port"],
        errors="coerce",
    )

    if (
        (src_port < 0)
        | (src_port > 65535)
    ).sum() > 0:

        failures.append(
            "Invalid src_port"
        )

if "dst_port" in df.columns:

    dst_port = pd.to_numeric(
        df["dst_port"],
        errors="coerce",
    )

    if (
        (dst_port < 0)
        | (dst_port > 65535)
    ).sum() > 0:

        failures.append(
            "Invalid dst_port"
        )

if "ip_proto" in df.columns:

    proto = pd.to_numeric(
        df["ip_proto"],
        errors="coerce",
    )

    if (
        (proto < 0)
        | (proto > 255)
    ).sum() > 0:

        failures.append(
            "Invalid ip_proto"
        )


if failures:

    print()
    print("[NOT READY]")
    print()
    print("Problems detected:")

    for problem in failures:
        print(f"  - {problem}")

    print()
    print(
        "Do NOT freeze the dataset yet."
    )

else:

    print()
    print("[PASS]")
    print()
    print(
        "No blocking packet-quality problems detected."
    )

    print()
    print(
        "The file was NOT modified."
    )

    print(
        "Next step can be Flow Final Quality Check."
    )

print()
print("=" * 70)
