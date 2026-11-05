#!/bin/bash

cd /home/fady/IoT-devices

OUTPUT="pcap_packet_features_v2.csv"

rm -f "$OUTPUT"

first=1

for csv in captures/csv/*.csv; do

    if [ $first -eq 1 ]; then

        head -1 "$csv" > "$OUTPUT"
        first=0

    fi

    tail -n +2 "$csv" >> "$OUTPUT"

done

echo "Merged into: $OUTPUT"
wc -l "$OUTPUT"
