#!/usr/bin/env python3

import csv
import os


BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

FLOW_CSV = os.path.join(
    BASE_DIR,
    "traffic_features.csv"
)

METADATA_CSV = os.path.join(
    BASE_DIR,
    "datasets",
    "metadata",
    "attack_metadata.csv"
)

OUTPUT_CSV = os.path.join(
    BASE_DIR,
    "labeled_traffic_features.csv"
)


def load_metadata():

    metadata = []

    with open(
        METADATA_CSV,
        "r",
        newline=""
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:

            metadata.append({
                "run_id": row["run_id"],
                "attack_type": row["attack_type"],
                "start": float(row["start_timestamp"]),
                "end": float(row["end_timestamp"]),
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "src_port": row["src_port"],
                "dst_port": row["dst_port"],
                "protocol": row["protocol"]
            })

    return metadata


def matches(flow, attack):

    # Flow information
    flow_src_ip = flow["src_ip"]
    flow_dst_ip = flow["dst_ip"]

    flow_src_port = str(flow["src_port"])
    flow_dst_port = str(flow["dst_port"])

    flow_protocol = str(flow["ip_proto"])

    flow_end = float(flow["timestamp"])

    flow_duration = float(
        flow["flow_duration"]
    )

    flow_start = flow_end - flow_duration

    # Attack window
    attack_start = attack["start"]
    attack_end = attack["end"]

    # ------------------------------------------
    # 1. Check time overlap
    # ------------------------------------------

    time_overlap = (
        flow_start <= attack_end
        and
        flow_end >= attack_start
    )

    if not time_overlap:
        return False

    # ------------------------------------------
    # 2. Check source IP
    # ------------------------------------------

    if (
        attack["src_ip"] != "*"
        and
        flow_src_ip != attack["src_ip"]
    ):
        return False

    # ------------------------------------------
    # 3. Check destination IP
    # ------------------------------------------

    if (
        attack["dst_ip"] != "*"
        and
        flow_dst_ip != attack["dst_ip"]
    ):
        return False

    # ------------------------------------------
    # 4. Check source port
    # ------------------------------------------

    if (
        attack["src_port"] != "*"
        and
        flow_src_port != attack["src_port"]
    ):
        return False

    # ------------------------------------------
    # 5. Check destination port
    # ------------------------------------------

    if (
        attack["dst_port"] != "*"
        and
        flow_dst_port != attack["dst_port"]
    ):
        return False

    # ------------------------------------------
    # 6. Check protocol
    # ------------------------------------------

    protocol_map = {
        "TCP": "6",
        "UDP": "17",
        "ICMP": "1"
    }

    expected_protocol = protocol_map.get(
        attack["protocol"],
        attack["protocol"]
    )

    if flow_protocol != expected_protocol:
        return False

    return True


def label_flows():

    print()
    print("==============================================")
    print("       FLOW DATASET PREPARATION")
    print("==============================================")

    print(
        "Flow dataset    :",
        FLOW_CSV
    )

    print(
        "Metadata        :",
        METADATA_CSV
    )

    print(
        "Output          :",
        OUTPUT_CSV
    )

    print("==============================================")
    print()

    metadata = load_metadata()

    print(
        "Attack metadata loaded:",
        len(metadata)
    )

    total_flows = 0
    attack_flows = 0
    normal_flows = 0

    attack_counts = {}

    with open(
        FLOW_CSV,
        "r",
        newline=""
    ) as input_file:

        reader = csv.DictReader(input_file)

        fieldnames = reader.fieldnames + [
            "label",
            "run_id"
        ]

        with open(
            OUTPUT_CSV,
            "w",
            newline=""
        ) as output_file:

            writer = csv.DictWriter(
                output_file,
                fieldnames=fieldnames
            )

            writer.writeheader()

            for flow in reader:

                total_flows += 1

                label = "normal"
                run_id = ""

                for attack in metadata:

                    if matches(flow, attack):

                        label = attack[
                            "attack_type"
                        ]

                        run_id = attack[
                            "run_id"
                        ]

                        attack_counts[
                            label
                        ] = attack_counts.get(
                            label,
                            0
                        ) + 1

                        attack_flows += 1

                        break

                if label == "normal":

                    normal_flows += 1

                row = dict(flow)

                row["label"] = label
                row["run_id"] = run_id

                writer.writerow(row)

    print()
    print("==============================================")
    print("             LABELING COMPLETE")
    print("==============================================")

    print(
        "Total flows   :",
        total_flows
    )

    print(
        "Attack flows  :",
        attack_flows
    )

    print(
        "Normal flows  :",
        normal_flows
    )

    print()
    print("Attack breakdown:")

    for attack_type, count in attack_counts.items():

        print(
            "  ",
            attack_type,
            ":",
            count
        )

    print()
    print(
        "Output dataset:",
        OUTPUT_CSV
    )

    print("==============================================")


if __name__ == "__main__":

    label_flows()
