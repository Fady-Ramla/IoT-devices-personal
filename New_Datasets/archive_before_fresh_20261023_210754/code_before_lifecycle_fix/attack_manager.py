#!/usr/bin/env python3

import os
import csv
import time
from datetime import datetime


# ============================================================
# Metadata file
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

METADATA_DIR = os.path.join(
    BASE_DIR,
    "datasets",
    "metadata"
)

METADATA_FILE = os.path.join(
    METADATA_DIR,
    "attack_metadata.csv"
)


# ============================================================
# Timestamp
# ============================================================

def get_timestamp():
    """
    Return current timestamp with high precision.
    """
    return time.time()


# ============================================================
# Run ID
# ============================================================

def get_run_id():
    """
    Generate a unique ID for every attack run.
    """

    return "run_" + datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )


# ============================================================
# Prepare metadata file
# ============================================================

def prepare_metadata_file():
    """
    Create datasets/metadata directory and CSV file
    if they do not already exist.
    """

    os.makedirs(
        METADATA_DIR,
        exist_ok=True
    )

    if not os.path.exists(METADATA_FILE):

        with open(
            METADATA_FILE,
            "w",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "run_id",
                "attack_type",
                "start_timestamp",
                "end_timestamp",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "protocol"
            ])


# ============================================================
# Save metadata
# ============================================================

def save_metadata(
    run_id,
    attack_type,
    start_timestamp,
    end_timestamp,
    src_ip,
    dst_ip,
    src_port="*",
    dst_port="*",
    protocol="TCP"
):
    """
    Save one attack record into attack_metadata.csv.
    """

    prepare_metadata_file()

    with open(
        METADATA_FILE,
        "a",
        newline=""
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            run_id,
            attack_type,
            start_timestamp,
            end_timestamp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol
        ])

    print()
    print("==============================================")
    print(" Attack Metadata Saved")
    print("==============================================")
    print("Run ID       :", run_id)
    print("Attack Type  :", attack_type)
    print("Source IP    :", src_ip)
    print("Destination  :", dst_ip)
    print("Source Port  :", src_port)
    print("Destination Port:", dst_port)
    print("Protocol     :", protocol)
    print("Start        :", start_timestamp)
    print("End          :", end_timestamp)
    print("Metadata     :", METADATA_FILE)
    print("==============================================")
    print()


# ============================================================
# Run Attack
# ============================================================

def run_attack(
    attacker,
    attack_type,
    dst_ip,
    command,
    dst_port="*",
    src_port="*",
    protocol="TCP"
):
    """
    Execute an attack from a Mininet host
    and automatically generate attack metadata.
    """

    prepare_metadata_file()

    # Get attacker IP automatically
    src_ip = attacker.IP()

    # Generate unique run ID
    run_id = get_run_id()

    print()
    print("==============================================")
    print(" Starting Attack")
    print("==============================================")
    print("Run ID       :", run_id)
    print("Attack Type  :", attack_type)
    print("Attacker     :", attacker.name)
    print("Source IP    :", src_ip)
    print("Destination  :", dst_ip)
    print("Command      :", command)
    print("==============================================")
    print()

    # Start timestamp
    start_timestamp = get_timestamp()

    # Execute command inside Mininet host
    attacker.cmd(command)

    # End timestamp
    end_timestamp = get_timestamp()

    # Save metadata
    save_metadata(
        run_id=run_id,
        attack_type=attack_type,
        start_timestamp=start_timestamp,
        end_timestamp=end_timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol
    )

    print("Attack finished successfully.")
