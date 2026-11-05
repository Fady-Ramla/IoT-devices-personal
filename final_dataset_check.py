#!/usr/bin/env python3

import csv
from collections import Counter, defaultdict

PACKET_FILE = "labeled_packet_features_FINAL.csv"
METADATA_FILE = "datasets/metadata/attack_metadata.csv"


def load_metadata():
    metadata = defaultdict(list)

    with open(METADATA_FILE, newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            run_id = row.get("run_id", "").strip()
            attack_type = row.get("attack_type", "").strip()

            if run_id:
                metadata[run_id].append(attack_type)

    return metadata


def load_dataset():
    run_packets = Counter()
    label_counts = Counter()

    dataset_run_ids = set()

    total_packets = 0

    with open(PACKET_FILE, newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            total_packets += 1

            run_id = row.get("run_id", "").strip()
            label = row.get("label", "").strip()

            label_counts[label] += 1

            if run_id:
                dataset_run_ids.add(run_id)
                run_packets[run_id] += 1

    return total_packets, run_packets, label_counts, dataset_run_ids


def main():

    print("\n" + "=" * 75)
    print("                 FINAL DATASET CHECK")
    print("=" * 75)

    # =========================================================
    # LOAD
    # =========================================================

    print("\nLoading files...")

    metadata = load_metadata()
    total_packets, run_packets, labels, dataset_runs = load_dataset()

    metadata_runs = set(metadata.keys())

    print("Metadata loaded.")
    print("Dataset loaded.")

    # =========================================================
    # 1. DATASET SIZE
    # =========================================================

    print("\n" + "=" * 75)
    print("1. DATASET SIZE")
    print("-" * 75)

    print(f"  Packet file       : {PACKET_FILE}")
    print(f"  Total packets     : {total_packets}")
    print(f"  Metadata runs     : {len(metadata_runs)}")
    print(f"  Dataset runs      : {len(dataset_runs)}")

    # =========================================================
    # 2. LABEL DISTRIBUTION
    # =========================================================

    print("\n" + "=" * 75)
    print("2. LABEL DISTRIBUTION")
    print("-" * 75)

    for label, count in labels.most_common():

        percentage = (count / total_packets * 100) if total_packets else 0

        print(
            f"  {label:20} "
            f"{count:8} packets "
            f"({percentage:6.2f}%)"
        )

    print("-" * 75)
    print(f"  {'TOTAL':20} {total_packets:8} packets (100.00%)")

    # =========================================================
    # 3. UNKNOWN / EMPTY LABEL CHECK
    # =========================================================

    print("\n" + "=" * 75)
    print("3. UNKNOWN / EMPTY LABEL CHECK")
    print("-" * 75)

    unknown_labels = []

    for label in labels:

        if label == "" or label.upper() == "UNKNOWN":
            unknown_labels.append(label)

    if unknown_labels:
        for label in unknown_labels:
            print(f"  PROBLEM: label [{label}] -> {labels[label]} packets")
    else:
        print("  No UNKNOWN or empty labels. OK")

    # =========================================================
    # 4. DUPLICATE METADATA RUN IDs
    # =========================================================

    print("\n" + "=" * 75)
    print("4. DUPLICATE METADATA RUN IDs")
    print("-" * 75)

    duplicate_metadata = {
        run_id: types
        for run_id, types in metadata.items()
        if len(types) > 1
    }

    if duplicate_metadata:

        print("  DUPLICATE RUN IDs FOUND:")

        for run_id, types in duplicate_metadata.items():
            print(f"    {run_id}")
            print(f"      attack types: {types}")

    else:
        print("  No duplicate metadata run IDs. OK")

    # =========================================================
    # 5. RUNS IN DATASET BUT NOT METADATA
    # =========================================================

    print("\n" + "=" * 75)
    print("5. DATASET RUNS WITHOUT METADATA")
    print("-" * 75)

    unexpected_runs = dataset_runs - metadata_runs

    if unexpected_runs:

        print(f"  FOUND {len(unexpected_runs)} unexpected runs:")

        for run_id in sorted(unexpected_runs):
            print(
                f"    {run_id:40} "
                f"{run_packets[run_id]:8} packets"
            )

    else:
        print("  Every dataset run exists in metadata. OK")

    # =========================================================
    # 6. METADATA RUNS MISSING FROM DATASET
    # =========================================================

    print("\n" + "=" * 75)
    print("6. METADATA RUNS MISSING FROM DATASET")
    print("-" * 75)

    missing_runs = metadata_runs - dataset_runs

    if missing_runs:

        print(f"  FOUND {len(missing_runs)} missing runs:")

        for run_id in sorted(missing_runs):

            print(
                f"    {run_id:40} "
                f"{metadata[run_id]}"
            )

    else:
        print("  Every metadata run exists in dataset. OK")

    # =========================================================
    # 7. RUN INVENTORY BY ATTACK TYPE
    # =========================================================

    print("\n" + "=" * 75)
    print("7. RUN INVENTORY BY ATTACK TYPE")
    print("-" * 75)

    by_type = defaultdict(list)

    for run_id in sorted(dataset_runs):

        if run_id in metadata:

            types = metadata[run_id]

            # If duplicated metadata, mark it as conflict
            if len(set(types)) > 1:
                attack_type = "CONFLICT"

            else:
                attack_type = types[0]

        else:
            attack_type = "UNKNOWN"

        by_type[attack_type].append(run_id)

    for attack_type in sorted(by_type):

        runs = by_type[attack_type]

        print(f"\n  {attack_type.upper()} : {len(runs)} runs")

        for run_id in runs:

            print(
                f"    {run_id:40} "
                f"{run_packets[run_id]:8} packets"
            )

    # =========================================================
    # 8. PACKETS BY ATTACK TYPE
    # =========================================================

    print("\n" + "=" * 75)
    print("8. PACKETS BY ATTACK TYPE")
    print("-" * 75)

    packets_by_type = Counter()

    for attack_type, run_list in by_type.items():

        for run_id in run_list:

            packets_by_type[attack_type] += run_packets[run_id]

    for attack_type, count in packets_by_type.most_common():

        percentage = (
            count / total_packets * 100
            if total_packets
            else 0
        )

        print(
            f"  {attack_type:20} "
            f"{count:8} packets "
            f"({percentage:6.2f}%)"
        )

    # =========================================================
    # 9. FINAL VERDICT
    # =========================================================

    print("\n" + "=" * 75)
    print("                     FINAL VERDICT")
    print("=" * 75)

    problems = []

    if unknown_labels:
        problems.append("UNKNOWN/empty labels")

    if duplicate_metadata:
        problems.append("duplicate metadata Run IDs")

    if unexpected_runs:
        problems.append("dataset runs without metadata")

    if missing_runs:
        problems.append("metadata runs missing from dataset")

    if any(
        attack_type == "CONFLICT"
        for attack_type in by_type
    ):
        problems.append("conflicting attack types")

    if problems:

        print("\n  ⚠ DATASET IS NOT READY YET\n")

        print("  Problems found:")

        for problem in problems:
            print(f"    - {problem}")

    else:

        print("\n  ✓ NO STRUCTURAL PROBLEMS FOUND")
        print("  ✓ All dataset runs have metadata")
        print("  ✓ All metadata runs exist in dataset")
        print("  ✓ No duplicate metadata Run IDs")
        print("  ✓ No UNKNOWN labels")
        print("\n  Dataset passed the structural final check.")

    print("\n" + "=" * 75)
    print()


if __name__ == "__main__":
    main()
