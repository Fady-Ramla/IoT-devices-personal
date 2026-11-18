#!/usr/bin/env python3
"""Generate a sequential Mininet CLI batch for real Packet-In collection.

The generated file is consumed inside the Mininet CLI with:
    source New_Datasets/scripts/packetin_batch.cli
Each command is synchronous in the existing CLI, so the next run starts only
after the preceding run has completed. No rows are duplicated or synthesized.
"""
from __future__ import annotations

import argparse
import math
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=10,
                    help="number of varied rounds per class; default: 10")
    ap.add_argument("--output", type=Path,
                    default=Path("New_Datasets/scripts/packetin_batch.cli"))
    args = ap.parse_args()
    if args.rounds < 1:
        raise SystemExit("--rounds must be >= 1")

    normal_rates = [0.5, 1.0, 1.5, 2.0, 0.75, 1.25, 1.75, 2.5, 0.6, 1.4]
    scan_rates = [25, 50, 75, 100, 125, 150, 175, 200, 60, 140]
    syn_rates = [25, 50, 75, 100, 125, 150, 175, 200, 40, 160]
    post_counts = [25, 50, 75, 100, 125, 150, 175, 200, 40, 160]
    post_rates = [25, 50, 75, 100, 125, 150, 175, 200, 40, 160]
    post_delays_ms = [math.ceil(1000 / rate) for rate in post_rates]
    ports = ["1-1000", "100-1100", "1-1500", "200-1200", "1-2000",
             "400-1400", "1-2500", "500-1500", "1-3000", "250-1750"]
    durations = [10, 12, 15, 18, 20]

    # Mininet's CLI source command does not treat '#' as a comment. Keep the
    # generated file command-only so every line is executable by ``source``.
    lines = []
    for i in range(args.rounds):
        j = i % len(normal_rates)
        duration = durations[i % len(durations)]
        delay_ms = post_delays_ms[j]
        max_requests = (1000.0 / delay_ms) * duration
        if post_counts[j] > max_requests:
            raise SystemExit(
                "invalid malicious_post plan: count exceeds delay/duration capacity"
            )
        lines.append(f"normal h5 http_api h2 {duration} {normal_rates[j]}")
        lines.append(f"attack h5 port_scan h2 {ports[j]} {scan_rates[j]} {duration}")
        lines.append(f"attack h5 syn_flood h2 5000 {syn_rates[j]} {duration}")
        lines.append(
            f"attack h5 malicious_post h2 /api/iot/telemetry "
            f"{post_counts[j]} {delay_ms} 1 {duration}"
        )
        lines.append("")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {args.output} with {args.rounds * 4} sequential runs")


if __name__ == "__main__":
    main()
