#!/usr/bin/env python3

import csv
from collections import Counter, defaultdict


PACKET_FILE = "labeled_packet_features.csv"


def load_data(file_path):
    data = []
    with open(file_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            data.append(row)
    return data


def analyze_labels(data):
    print("\n" + "="*60)
    print("1. LABEL DISTRIBUTION")
    print("="*60)

    labels = Counter(row["label"] for row in data)
    total = len(data)

    for label, count in labels.most_common():
        percentage = (count / total) * 100
        print(f"  {label:20} {count:8} ({percentage:.2f}%)")

    print(f"\n  Total: {total}")


def analyze_runs(data):
    print("\n" + "="*60)
    print("2. PACKETS PER ATTACK RUN")
    print("="*60)

    run_counts = defaultdict(int)
    for row in data:
        run_id = row["run_id"]
        if run_id and run_id != "normal":
            run_counts[run_id] += 1

    if not run_counts:
        print("  No attack runs found.")
        return

    print(f"  {'Run ID':40} {'Packets':>10}")
    print("  " + "-"*52)

    for run_id, count in sorted(run_counts.items(), key=lambda x: -x[1]):
        print(f"  {run_id:40} {count:>10}")

    avg = sum(run_counts.values()) / len(run_counts)
    print(f"\n  Average packets per run: {avg:.1f}")


def analyze_duplicates(data):
    print("\n" + "="*60)
    print("3. DUPLICATE ANALYSIS")
    print("="*60)

    # تجاهل الـ timestamp والـ run_id
    seen = Counter()
    for row in data:
        key = (
            row["src_ip"],
            row["dst_ip"],
            row["src_port"],
            row["dst_port"],
            row["ip_proto"],
            row["packet_length"],
            row["label"]
        )
        seen[key] += 1

    duplicates = {k: v for k, v in seen.items() if v > 1}

    if not duplicates:
        print("  No duplicates found.")
        return

    print(f"  Duplicate combinations: {len(duplicates)}")

    # اعرض أعلى 5 تكرارات
    for key, count in sorted(duplicates.items(), key=lambda x: -x[1])[:5]:
        print(f"    {key} -> {count} times")


def analyze_features(data):
    print("\n" + "="*60)
    print("4. FEATURE VARIABILITY (Attacks Only)")
    print("="*60)

    attacks = [row for row in data if row["label"] != "normal"]

    if not attacks:
        print("  No attacks found.")
        return

    features = [
        "packet_length",
        "payload_length",
        "ttl"
    ]

    print(f"  {'Feature':20} {'Min':>8} {'Max':>8} {'Avg':>10}")
    print("  " + "-"*50)

    for feature in features:
        values = []
        for row in attacks:
            try:
                values.append(float(row[feature]))
            except ValueError:
                continue

        if values:
            print(
                f"  {feature:20} "
                f"{min(values):>8.2f} "
                f"{max(values):>8.2f} "
                f"{sum(values)/len(values):>10.2f}"
            )


def analyze_timestamps(data):
    print("\n" + "="*60)
    print("5. TIMESTAMP RANGE")
    print("="*60)

    timestamps = []
    for row in data:
        try:
            timestamps.append(float(row["timestamp"]))
        except ValueError:
            continue

    if not timestamps:
        print("  No timestamps found.")
        return

    start = min(timestamps)
    end = max(timestamps)

    print(f"  First packet: {start}")
    print(f"  Last packet : {end}")
    print(f"  Duration    : {end - start:.2f} seconds")


def main():
    print("\n" + "="*60)
    print("        DATASET QUALITY ANALYSIS")
    print("="*60)

    print(f"\n  File: {PACKET_FILE}")

    data = load_data(PACKET_FILE)

    print(f"  Loaded: {len(data)} packets")

    analyze_labels(data)
    analyze_runs(data)
    analyze_duplicates(data)
    analyze_features(data)
    analyze_timestamps(data)

    print("\n" + "="*60)
    print("        ANALYSIS COMPLETE")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
