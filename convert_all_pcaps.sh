#!/bin/bash

cd /home/fady/IoT-devices

mkdir -p captures/csv

for pcap in captures/*.pcap; do

    filename=$(basename "$pcap" .pcap)

    output="captures/csv/${filename}.csv"

    echo "Converting: $pcap -> $output"

    python3 mininet/pcap_to_csv.py "$pcap" "$output"

    echo ""

done

echo "All PCAPs converted."
