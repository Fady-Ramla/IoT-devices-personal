# check_normal_groups_ml_final.py
# ============================================================
# NORMAL GROUPING ANALYSIS - FROZEN ML DATASETS
#
# IMPORTANT:
#   READ-ONLY
#   Does NOT modify ML_FINAL
#   Does NOT create train/test split
#   Does NOT create groups
#
# We analyze the ORIGINAL frozen ML datasets because
# preprocessing removed metadata such as timestamp/src_ip/dst_ip.
# ============================================================

import os
import pandas as pd


BASE_DIR = "/home/fady/IoT-devices"

PACKET_FILE = os.path.join(
    BASE_DIR,
    "ML_FINAL",
    "labeled_packet_features_ML.csv"
)

FLOW_FILE = os.path.join(
    BASE_DIR,
    "ML_FINAL",
    "labeled_traffic_features_ML.csv"
)


def separator(char="=", length=75):
    print(char * length)


def analyze_normal(file_path, name):

    print()
    separator()
    print(f"        {name} - NORMAL GROUP ANALYSIS")
    separator()

    if not os.path.exists(file_path):

        print(f"\nERROR: File not found:")
        print(file_path)

        return

    print(f"\nFile:")
    print(file_path)

    df = pd.read_csv(
        file_path,
        low_memory=False
    )

    print(
        f"\nTotal rows: {len(df):,}"
    )

    print(
        f"Columns: {len(df.columns)}"
    )

    # --------------------------------------------------------
    # NORMAL
    # --------------------------------------------------------

    normal = df[
        df["label"].astype(str).str.lower()
        == "normal"
    ].copy()

    print(
        f"Normal rows: {len(normal):,}"
    )

    # ========================================================
    # RUN ID
    # ========================================================

    print()
    separator("-")
    print("1. RUN_ID")
    separator("-")

    if "run_id" in normal.columns:

        run_ids = (
            normal["run_id"]
            .fillna("")
            .astype(str)
            .str.strip()
        )

        non_empty = run_ids[
            run_ids != ""
        ]

        print(
            f"Normal rows with run_id: "
            f"{len(non_empty):,}"
        )

        print(
            f"Normal rows without run_id: "
            f"{(run_ids == '').sum():,}"
        )

    # ========================================================
    # TIMESTAMP
    # ========================================================

    print()
    separator("-")
    print("2. TIMESTAMP")
    separator("-")

    if "timestamp" not in normal.columns:

        print(
            "\nERROR: timestamp not found."
        )

        return

    normal["timestamp_parsed"] = pd.to_datetime(
        normal["timestamp"],
        errors="coerce"
    )

    valid = normal[
        normal["timestamp_parsed"].notna()
    ].copy()

    invalid = (
        normal["timestamp_parsed"].isna()
    ).sum()

    print(
        f"Valid timestamps: {len(valid):,}"
    )

    print(
        f"Invalid timestamps: {invalid:,}"
    )

    if valid.empty:

        print(
            "\nNo valid timestamps."
        )

        return

    first = valid[
        "timestamp_parsed"
    ].min()

    last = valid[
        "timestamp_parsed"
    ].max()

    print(
        f"\nFirst timestamp:"
        f" {first}"
    )

    print(
        f"Last timestamp:"
        f"  {last}"
    )

    print(
        f"Overall span:"
        f" {last - first}"
    )

    # ========================================================
    # BY DATE
    # ========================================================

    print()
    separator("-")
    print("3. NORMAL TRAFFIC BY DATE")
    separator("-")

    valid["date"] = (
        valid["timestamp_parsed"].dt.date
    )

    date_counts = (
        valid["date"]
        .value_counts()
        .sort_index()
    )

    print(
        f"Unique dates: "
        f"{len(date_counts)}"
    )

    for date, count in date_counts.items():

        print(
            f"  {date}: "
            f"{count:,} rows"
        )

    # ========================================================
    # BY HOUR
    # ========================================================

    print()
    separator("-")
    print("4. NORMAL TRAFFIC BY HOUR")
    separator("-")

    valid["hour"] = (
        valid["timestamp_parsed"].dt.hour
    )

    hour_counts = (
        valid["hour"]
        .value_counts()
        .sort_index()
    )

    for hour, count in hour_counts.items():

        print(
            f"  {int(hour):02d}:00 -> "
            f"{count:,} rows"
        )

    # ========================================================
    # TIMESTAMP GAPS
    # ========================================================

    print()
    separator("-")
    print("5. TIMESTAMP GAP ANALYSIS")
    separator("-")

    valid = valid.sort_values(
        "timestamp_parsed"
    )

    gaps = (
        valid["timestamp_parsed"]
        .diff()
        .dt.total_seconds()
        .dropna()
    )

    if gaps.empty:

        print(
            "\nNot enough timestamps."
        )

    else:

        print(
            f"Number of gaps: "
            f"{len(gaps):,}"
        )

        print(
            f"Minimum gap: "
            f"{gaps.min():.6f} sec"
        )

        print(
            f"Median gap: "
            f"{gaps.median():.6f} sec"
        )

        print(
            f"Mean gap: "
            f"{gaps.mean():.6f} sec"
        )

        print(
            f"Maximum gap: "
            f"{gaps.max():.6f} sec"
        )

        print()

        for threshold in [
            1,
            5,
            10,
            30,
            60,
            120,
            300,
            600,
        ]:

            count = (
                gaps > threshold
            ).sum()

            print(
                f"Gaps > "
                f"{threshold:>3} sec: "
                f"{count:,}"
            )

    # ========================================================
    # SOURCE IP
    # ========================================================

    print()
    separator("-")
    print("6. SOURCE IP")
    separator("-")

    if "src_ip" in normal.columns:

        src = (
            normal["src_ip"]
            .fillna("")
            .astype(str)
            .str.strip()
        )

        src = src[src != ""]

        print(
            f"Unique src_ip: "
            f"{src.nunique():,}"
        )

        for value, count in (
            src.value_counts()
            .head(20)
            .items()
        ):

            print(
                f"  {value}: "
                f"{count:,}"
            )

    # ========================================================
    # DESTINATION IP
    # ========================================================

    print()
    separator("-")
    print("7. DESTINATION IP")
    separator("-")

    if "dst_ip" in normal.columns:

        dst = (
            normal["dst_ip"]
            .fillna("")
            .astype(str)
            .str.strip()
        )

        dst = dst[dst != ""]

        print(
            f"Unique dst_ip: "
            f"{dst.nunique():,}"
        )

        for value, count in (
            dst.value_counts()
            .head(20)
            .items()
        ):

            print(
                f"  {value}: "
                f"{count:,}"
            )

    # ========================================================
    # PORT COMBINATIONS
    # ========================================================

    print()
    separator("-")
    print("8. COMMON CONNECTIONS")
    separator("-")

    required = {
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "ip_proto"
    }

    if required.issubset(normal.columns):

        connections = (
            normal.groupby(
                [
                    "src_ip",
                    "dst_ip",
                    "src_port",
                    "dst_port",
                    "ip_proto"
                ]
            )
            .size()
            .sort_values(
                ascending=False
            )
            .head(20)
        )

        for index, count in connections.items():

            (
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                proto
            ) = index

            print(
                f"  "
                f"{src_ip}:{src_port}"
                f" -> "
                f"{dst_ip}:{dst_port}"
                f" proto={proto}"
                f" : {count:,}"
            )

    # ========================================================
    # POTENTIAL GROUPS
    # ========================================================

    print()
    separator("-")
    print("9. POTENTIAL TIME-BASED GROUPS")
    separator("-")

    print(
        "\nThese are ONLY observations."
    )

    print(
        "No groups are being created."
    )

    if not gaps.empty:

        for threshold in [
            30,
            60,
            120,
            300,
            600,
        ]:

            groups = (
                1
                + (gaps > threshold).sum()
            )

            print(
                f"  If gap > "
                f"{threshold:>3} sec "
                f"starts a new group:"
                f" {groups:,} groups"
            )

    print()
    separator()
    print(f"        END OF {name}")
    separator()


def main():

    separator()

    print(
        "        NORMAL GROUPING CHECK"
    )

    print(
        "        FROZEN ML_FINAL DATASETS"
    )

    separator()

    print(
        "\nREAD-ONLY ANALYSIS"
    )

    print(
        "No files will be modified."
    )

    print(
        "No groups will be created."
    )

    print(
        "No train/test split will be performed."
    )

    analyze_normal(
        PACKET_FILE,
        "PACKET"
    )

    analyze_normal(
        FLOW_FILE,
        "FLOW"
    )

    print()
    separator()

    print(
        "NEXT STEP:"
    )

    print(
        "Review the timestamp/gap results"
    )

    print(
        "before deciding the final grouping strategy."
    )

    separator()


if __name__ == "__main__":
    main()
