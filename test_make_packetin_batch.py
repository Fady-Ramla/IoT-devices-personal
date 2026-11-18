#!/usr/bin/env python3
"""Offline validation of generated Packet-In collection batch commands."""
import math
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
GENERATOR = ROOT / "New_Datasets" / "scripts" / "make_packetin_batch.py"


def main():
    with tempfile.TemporaryDirectory(prefix="packetin_batch_test_") as temp:
        output = Path(temp) / "batch.cli"
        subprocess.run(
            [sys.executable, str(GENERATOR), "--rounds", "10", "--output", str(output)],
            check=True,
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        commands = [
            shlex.split(line) for line in output.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    assert len(commands) == 40
    post_commands = [
        command for command in commands
        if len(command) > 2 and command[0] == "attack" and command[2] == "malicious_post"
    ]
    assert len(post_commands) == 10
    for command in post_commands:
        count, delay_ms, workers, duration = map(int, command[5:9])
        assert 1 <= delay_ms <= 60000
        assert 1 <= workers <= 50
        assert 1000.0 / delay_ms <= 200
        assert count <= math.floor((1000.0 / delay_ms) * duration)

    print("PASS: generated 40 sequential commands across 10 rounds")
    print("PASS: all 10 Malicious_POST commands satisfy the CLI rate-duration limit")


if __name__ == "__main__":
    main()
