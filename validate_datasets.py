#!/usr/bin/env python3

import csv
import os
from collections import Counter

PACKET_FILE = "/home/fady/IoT-devices/labeled_packet_features.csv"
FLOW_FILE = "/home/fady/IoT-devices/labeled_traffic_features.csv"


def validate_dataset(file_path, dataset_name, label_column):
    print("\n==============================================")
    print(f"       {dataset_name.upper()} VALIDATION")
    print("==============================================")

    if not os.path.exists(file_path):
        print("ERROR: File not found:", file_path)
        return

    with open(file_path, newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        columns = reader.fieldnames

    print("\nFile:", file_path)
    print("Total rows:", len(rows))
    print("Total columns:", len(columns))

    # ------------------------------------------
    # 1. Columns
    # ------------------------------------------
    print("\nColumns:")
    for i, col in enumerate(columns, start=1):
        print(f"  {i}: {col}")

    # ------------------------------------------
    # 2. Missing values
    # ------------------------------------------
    missing_total = 0
    missing_by_column = Counter()

    for row in rows:
        for col in columns:
            if row[col] is None or row[col].strip() == "":
                missing_total += 1
                missing_by_column[col] += 1

    print("\nMissing values:", missing_total)

    if missing_by_column:
        for col, count in missing_by_column.items():
            print(f"  {col}: {count}")

    # ------------------------------------------
    # 3. Label distribution
    # ------------------------------------------
    labels = Counter(row[label_column] for row in rows)

    print("\nLabel distribution:")

    for label, count in labels.items():
        percentage = (count / len(rows)) * 100
        print(f"  {label:20s} {count:8d} ({percentage:.2f}%)")

    # ------------------------------------------
    # 4. Duplicate rows
    # ------------------------------------------
    seen = set()
    duplicates = 0

    for row in rows:
        values = tuple(row[col] for col in columns)

        if values in seen:
            duplicates += 1
        else:
            seen.add(values)

    print("\nDuplicate rows:", duplicates)

    # ------------------------------------------
    # 5. Empty labels
    # ------------------------------------------
    empty_labels = sum(
        1 for row in rows
        if not row[label_column].strip()
    )

    print("Empty labels:", empty_labels)

    # ------------------------------------------
    # 6. Run ID statistics
    # ------------------------------------------
    run_ids = Counter(row["run_id"] for row in rows)

    print("\nUnique run IDs:", len(run_ids))

    print("\nRows per attack run:")

    for run_id, count in run_ids.items():
        print(f"  {run_id}: {count}")

    # ------------------------------------------
    # 7. Timestamp validation
    # ------------------------------------------
    invalid_timestamps = 0

    for row in rows:
        try:
            float(row["timestamp"])
        except (ValueError, TypeError):
            invalid_timestamps += 1

    print("\nInvalid timestamps:", invalid_timestamps)

    # ------------------------------------------
    # 8. Numeric validation
    # ------------------------------------------
    numeric_errors = Counter()

    skip_columns = {
        "src_mac",
        "dst_mac",
        "src_ip",
        "dst_ip",
        "label",
        "run_id"
    }

    for row in rows:

        for col in columns:

            if col in skip_columns:
                continue

            value = row[col].strip()

            if value == "":
                continue

            try:
                float(value)
            except ValueError:
                numeric_errors[col] += 1

    print("\nNumeric conversion errors:", sum(numeric_errors.values()))

    if numeric_errors:
        for col, count in numeric_errors.items():
            print(f"  {col}: {count}")

    print("\n==============================================")
    print(f"       {dataset_name.upper()} COMPLETE")
    print("==============================================")


# ==================================================
# Run validation
# ==================================================

validate_dataset(
    PACKET_FILE,
    "Packet Dataset",
    "label"
)

validate_dataset(
    FLOW_FILE,
    "Flow Dataset",
    "label"
)

