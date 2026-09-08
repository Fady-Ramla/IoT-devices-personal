import csv
from collections import Counter

FILE = "/home/fady/IoT-devices/datasets/metadata/attack_metadata.csv"

with open(FILE, newline="") as f:
    rows = list(csv.DictReader(f))

print("\n==============================================")
print("        METADATA VALIDATION")
print("==============================================")

# 1. Total runs
print("\nTotal attack runs:", len(rows))

# 2. Attack distribution
counts = Counter(row["attack_type"] for row in rows)

print("\nAttack distribution:")
for attack, count in counts.items():
    print(f"  {attack}: {count}")

# 3. Duplicate run IDs
run_ids = [row["run_id"] for row in rows]
duplicates = [
    run_id for run_id, count in Counter(run_ids).items()
    if count > 1
]

print("\nDuplicate run IDs:")
if duplicates:
    for run_id in duplicates:
        print("  DUPLICATE:", run_id)
else:
    print("  None")

# 4. Missing fields
required = [
    "run_id",
    "attack_type",
    "start_timestamp",
    "end_timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol"
]

print("\nMissing fields:")
missing_found = False

for i, row in enumerate(rows, start=2):
    for field in required:
        if not row[field].strip():
            print(f"  Row {i}: missing {field}")
            missing_found = True

if not missing_found:
    print("  None")

# 5. Invalid time windows
print("\nInvalid time windows:")
invalid_found = False

for row in rows:
    start = float(row["start_timestamp"])
    end = float(row["end_timestamp"])

    if end < start:
        print("  INVALID:", row["run_id"])
        invalid_found = True

if not invalid_found:
    print("  None")

# 6. Overlapping attack windows
print("\nOverlapping attack windows:")
overlap_found = False

for i in range(len(rows)):
    for j in range(i + 1, len(rows)):

        a = rows[i]
        b = rows[j]

        a_start = float(a["start_timestamp"])
        a_end = float(a["end_timestamp"])

        b_start = float(b["start_timestamp"])
        b_end = float(b["end_timestamp"])

        if a_start <= b_end and b_start <= a_end:
            print("  OVERLAP:")
            print("   ", a["run_id"], a["attack_type"])
            print("   ", b["run_id"], b["attack_type"])
            overlap_found = True

if not overlap_found:
    print("  None")

# 7. Attack durations
print("\nAttack durations:")

for row in rows:
    start = float(row["start_timestamp"])
    end = float(row["end_timestamp"])

    duration = end - start

    print(
        f"  {row['attack_type']:16s}"
        f" {row['run_id']} : "
        f"{duration:.3f} sec"
    )

print("\n==============================================")
print("        VALIDATION COMPLETE")
print("==============================================")
