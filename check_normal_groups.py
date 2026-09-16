# check_normal_groups.py
# ============================================================
# NORMAL TRAFFIC GROUPING ANALYSIS
#
# Purpose:
#   Analyze NORMAL traffic before Grouped Train/Val/Test Split.
#
# IMPORTANT:
#   - READ-ONLY
#   - Does NOT modify ML_FINAL
#   - Does NOT modify preprocessing files
#   - Does NOT create train/test datasets
#
# Input:
#   preprocessing/packet_preprocessed.csv
#   preprocessing/flow_preprocessed.csv
#
# Goal:
#   Understand how NORMAL traffic was collected so we can
#   determine whether meaningful groups/sessions/captures
#   can be created for grouped splitting.
# ============================================================

import os
import pandas as pd


# ============================================================
# CONFIG
# ============================================================

BASE_DIR = "/home/fady/IoT-devices"

PACKET_FILE = os.path.join(
    BASE_DIR,
    "preprocessing",
    "packet_preprocessed.csv"
)

FLOW_FILE = os.path.join(
    BASE_DIR,
    "preprocessing",
    "flow_preprocessed.csv"
)


# ============================================================
# HELPERS
# ============================================================

def print_separator(char="=", length=72):
    print(char * length)


def analyze_dataset(file_path, dataset_name):
    """
    Analyze NORMAL rows in one dataset.
    """

    print()
    print_separator()
    print(f"        {dataset_name} NORMAL GROUP ANALYSIS")
    print_separator()

    if not os.path.exists(file_path):

        print(f"\nERROR: File not found:")
        print(file_path)

        return None

    print(f"\nFile:")
    print(file_path)

    # --------------------------------------------------------
    # Load
    # --------------------------------------------------------

    try:

        df = pd.read_csv(
            file_path,
            low_memory=False
        )

    except Exception as e:

        print("\nERROR while reading file:")
        print(e)

        return None

    print(f"\nTotal rows: {len(df):,}")
    print(f"Columns: {len(df.columns)}")

    # --------------------------------------------------------
    # Check label
    # --------------------------------------------------------

    if "label" not in df.columns:

        print("\nERROR: 'label' column not found.")

        return None

    # --------------------------------------------------------
    # Normal rows
    # --------------------------------------------------------

    normal = df[
        df["label"].astype(str).str.lower()
        == "normal"
    ].copy()

    print(
        f"\nNormal rows: {len(normal):,}"
    )

    if normal.empty:

        print("\nNo normal rows found.")

        return None

    # ========================================================
    # RUN_ID ANALYSIS
    # ========================================================

    print()
    print_separator("-")
    print("1. RUN_ID ANALYSIS")
    print_separator("-")

    if "run_id" in normal.columns:

        run_id = (
            normal["run_id"]
            .fillna("")
            .astype(str)
            .str.strip()
        )

        non_empty = run_id[
            run_id != ""
        ]

        empty_count = (
            run_id == ""
        ).sum()

        print(
            f"Normal rows with run_id    : "
            f"{len(non_empty):,}"
        )

        print(
            f"Normal rows with empty run_id: "
            f"{empty_count:,}"
        )

        if len(non_empty) > 0:

            print(
                f"Unique normal run_ids      : "
                f"{non_empty.nunique():,}"
            )

            print("\nNormal run_id distribution:")

            counts = (
                non_empty
                .value_counts()
                .sort_index()
            )

            for run_id_value, count in counts.items():

                print(
                    f"  {run_id_value}: "
                    f"{count:,} rows"
                )

        else:

            print(
                "\nAll normal rows have empty "
                "run_id."
            )

    else:

        print(
            "\nWARNING: run_id column "
            "does not exist."
        )

    # ========================================================
    # TIMESTAMP ANALYSIS
    # ========================================================

    print()
    print_separator("-")
    print("2. TIMESTAMP ANALYSIS")
    print_separator("-")

    if "timestamp" not in normal.columns:

        print(
            "\nWARNING: timestamp column "
            "does not exist."
        )

    else:

        normal["timestamp_parsed"] = pd.to_datetime(
            normal["timestamp"],
            errors="coerce"
        )

        valid_ts = normal[
            normal["timestamp_parsed"].notna()
        ].copy()

        invalid_ts = (
            normal["timestamp_parsed"].isna()
        ).sum()

        print(
            f"Valid timestamps  : "
            f"{len(valid_ts):,}"
        )

        print(
            f"Invalid timestamps: "
            f"{invalid_ts:,}"
        )

        if not valid_ts.empty:

            first_ts = (
                valid_ts["timestamp_parsed"]
                .min()
            )

            last_ts = (
                valid_ts["timestamp_parsed"]
                .max()
            )

            print(
                f"\nFirst timestamp: "
                f"{first_ts}"
            )

            print(
                f"Last timestamp : "
                f"{last_ts}"
            )

            span = (
                last_ts - first_ts
            )

            print(
                f"Overall time span: "
                f"{span}"
            )

            # ------------------------------------------------
            # Rows by date
            # ------------------------------------------------

            valid_ts["date"] = (
                valid_ts[
                    "timestamp_parsed"
                ].dt.date
            )

            date_counts = (
                valid_ts["date"]
                .value_counts()
                .sort_index()
            )

            print("\nRows by date:")

            for date_value, count in date_counts.items():

                print(
                    f"  {date_value}: "
                    f"{count:,} rows"
                )

            # ------------------------------------------------
            # Rows by hour
            # ------------------------------------------------

            valid_ts["hour"] = (
                valid_ts[
                    "timestamp_parsed"
                ].dt.hour
            )

            hour_counts = (
                valid_ts["hour"]
                .value_counts()
                .sort_index()
            )

            print("\nRows by hour:")

            for hour, count in hour_counts.items():

                print(
                    f"  {int(hour):02d}:00 -> "
                    f"{count:,} rows"
                )

    # ========================================================
    # SOURCE / DESTINATION ANALYSIS
    # ========================================================

    print()
    print_separator("-")
    print("3. SOURCE / DESTINATION ANALYSIS")
    print_separator("-")

    if "src_ip" in normal.columns:

        src_ips = (
            normal["src_ip"]
            .dropna()
            .astype(str)
            .str.strip()
        )

        src_ips = src_ips[
            src_ips != ""
        ]

        print(
            f"Unique src_ip: "
            f"{src_ips.nunique():,}"
        )

        print("\nTop src_ip values:")

        for value, count in (
            src_ips.value_counts()
            .head(15)
            .items()
        ):

            print(
                f"  {value}: "
                f"{count:,}"
            )

    else:

        print(
            "\nNo src_ip column."
        )

    if "dst_ip" in normal.columns:

        dst_ips = (
            normal["dst_ip"]
            .dropna()
            .astype(str)
            .str.strip()
        )

        dst_ips = dst_ips[
            dst_ips != ""
        ]

        print(
            f"\nUnique dst_ip: "
            f"{dst_ips.nunique():,}"
        )

        print("\nTop dst_ip values:")

        for value, count in (
            dst_ips.value_counts()
            .head(15)
            .items()
        ):

            print(
                f"  {value}: "
                f"{count:,}"
            )

    else:

        print(
            "\nNo dst_ip column."
        )

    # ========================================================
    # PORT ANALYSIS
    # ========================================================

    print()
    print_separator("-")
    print("4. PORT ANALYSIS")
    print_separator("-")

    for column in [
        "src_port",
        "dst_port"
    ]:

        if column not in normal.columns:

            continue

        ports = pd.to_numeric(
            normal[column],
            errors="coerce"
        )

        ports = ports.dropna()

        print(
            f"\n{column}:"
        )

        print(
            f"  Unique values: "
            f"{ports.nunique():,}"
        )

        print(
            "  Top values:"
        )

        for value, count in (
            ports.value_counts()
            .head(15)
            .items()
        ):

            print(
                f"    {int(value)}: "
                f"{count:,}"
            )

    # ========================================================
    # PROTOCOL ANALYSIS
    # ========================================================

    print()
    print_separator("-")
    print("5. PROTOCOL ANALYSIS")
    print_separator("-")

    if "ip_proto" in normal.columns:

        protocols = pd.to_numeric(
            normal["ip_proto"],
            errors="coerce"
        )

        protocols = protocols.dropna()

        print(
            f"Unique ip_proto: "
            f"{protocols.nunique():,}"
        )

        print("\nProtocol distribution:")

        for value, count in (
            protocols.value_counts()
            .sort_index()
            .items()
        ):

            print(
                f"  {int(value)}: "
                f"{count:,}"
            )

    # ========================================================
    # SWITCH ANALYSIS
    # ========================================================

    print()
    print_separator("-")
    print("6. SWITCH ANALYSIS")
    print_separator("-")

    if "switch" in normal.columns:

        switches = (
            normal["switch"]
            .fillna("")
            .astype(str)
            .str.strip()
        )

        switches = switches[
            switches != ""
        ]

        print(
            f"Unique switches: "
            f"{switches.nunique():,}"
        )

        print("\nSwitch distribution:")

        for value, count in (
            switches.value_counts()
            .head(20)
            .items()
        ):

            print(
                f"  {value}: "
                f"{count:,}"
            )

    # ========================================================
    # TIMESTAMP GAP ANALYSIS
    # ========================================================

    print()
    print_separator("-")
    print("7. TIMESTAMP GAP ANALYSIS")
    print_separator("-")

    if "timestamp_parsed" in normal.columns:

        valid_ts = normal[
            normal["timestamp_parsed"].notna()
        ].copy()

        if len(valid_ts) > 1:

            valid_ts = valid_ts.sort_values(
                "timestamp_parsed"
            )

            gaps = (
                valid_ts[
                    "timestamp_parsed"
                ]
                .diff()
                .dt.total_seconds()
                .dropna()
            )

            if not gaps.empty:

                print(
                    f"Number of timestamp gaps: "
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

                # Important large gaps
                for threshold in [
                    1,
                    5,
                    10,
                    30,
                    60,
                    300,
                ]:

                    count = (
                        gaps > threshold
                    ).sum()

                    print(
                        f"  Gaps > "
                        f"{threshold:>3} sec: "
                        f"{count:,}"
                    )

    # ========================================================
    # POTENTIAL SESSION WINDOWS
    # ========================================================

    print()
    print_separator("-")
    print("8. POTENTIAL TIME-BASED GROUPS")
    print_separator("-")

    if "timestamp_parsed" in normal.columns:

        valid_ts = normal[
            normal["timestamp_parsed"].notna()
        ].copy()

        if len(valid_ts) > 1:

            valid_ts = valid_ts.sort_values(
                "timestamp_parsed"
            )

            gaps = (
                valid_ts[
                    "timestamp_parsed"
                ]
                .diff()
                .dt.total_seconds()
            )

            # ------------------------------------------------
            # We DO NOT create groups here.
            #
            # We only show how many possible groups
            # would appear under different inactivity
            # thresholds.
            # ------------------------------------------------

            for threshold in [
                30,
                60,
                120,
                300,
                600,
            ]:

                potential_groups = (
                    1
                    + (
                        gaps > threshold
                    ).sum()
                )

                print(
                    f"If inactivity > "
                    f"{threshold:>3} sec "
                    f"starts a new group: "
                    f"{potential_groups:,} "
                    f"potential groups"
                )

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print_separator("=")
    print(
        f"        END OF {dataset_name} ANALYSIS"
    )
    print_separator("=")

    return normal


# ============================================================
# MAIN
# ============================================================

def main():

    print_separator("=")

    print(
        "        NORMAL TRAFFIC GROUPING CHECK"
    )

    print_separator("=")

    print(
        "\nIMPORTANT:"
    )

    print(
        "This script is READ-ONLY."
    )

    print(
        "No dataset will be modified."
    )

    print(
        "No train/test split will be created."
    )

    # --------------------------------------------------------
    # Packet
    # --------------------------------------------------------

    packet_normal = analyze_dataset(
        PACKET_FILE,
        "PACKET",
    )

    # --------------------------------------------------------
    # Flow
    # --------------------------------------------------------

    flow_normal = analyze_dataset(
        FLOW_FILE,
        "FLOW",
    )

    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    print()
    print_separator("=")
    print(
        "        FINAL INTERPRETATION"
    )
    print_separator("=")

    print(
        """
We are NOT creating groups yet.

The purpose of this script is only to
understand how the normal traffic was
captured.

We need to determine whether the normal
traffic contains meaningful independent
captures/sessions before performing a
Grouped Train/Validation/Test split.

DO NOT randomly create groups just to make
the split work.

After reviewing this output, we will decide
the correct grouping strategy.
"""
    )

    print_separator("=")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
