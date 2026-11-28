#!/usr/bin/env python3
"""Safely raise VIP directional-flow priority above SSH policy/deny-cache flows.

Run from the repository root:
    python3 patch_vip_steering_priority.py

The script is idempotent. It creates a timestamped backup before changing the
file and refuses to modify the file if the expected source structure is absent.
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import shutil
import sys
from pathlib import Path

DEFAULT_FILE = Path("topology_monitor.py")
CONSTANT_MARKER = "VIP_STEERING_PRIORITY = 50002"
OLD_PRIORITY = "priority=self.VIP_TAKEOVER_PRIORITY + 1,"
NEW_PRIORITY = "priority=self.VIP_STEERING_PRIORITY,"
CLASS_ANCHOR = "    VIP_TAKEOVER_PRIORITY = 49990\n"
NEW_CONSTANT = (
    "    VIP_TAKEOVER_PRIORITY = 49990\n"
    "    # Directional takeover flows must beat SSH policy (49999) and the\n"
    "    # deny-cache flows (50001), while dispatch PacketIns stay at 49990.\n"
    "    VIP_STEERING_PRIORITY = 50002\n"
)


def backup_path(path: Path) -> Path:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    candidate = path.with_name(f"{path.name}.bak-vip-priority-{stamp}")
    index = 1
    while candidate.exists():
        candidate = path.with_name(
            f"{path.name}.bak-vip-priority-{stamp}-{index}"
        )
        index += 1
    return candidate


def replace_in_function(text: str) -> tuple[str, int]:
    """Replace only inside def _vip_direction_flows(...), not elsewhere."""
    start_match = re.search(
        r"^    def _vip_direction_flows\s*\(", text, flags=re.MULTILINE
    )
    if not start_match:
        raise RuntimeError(
            "Could not find _vip_direction_flows(). No changes were made."
        )

    next_method = re.search(
        r"^    def \w+\s*\(",
        text[start_match.end():],
        flags=re.MULTILINE,
    )
    end = (
        start_match.end() + next_method.start()
        if next_method
        else len(text)
    )
    block = text[start_match.start():end]
    count = block.count(OLD_PRIORITY)
    if count != 1:
        raise RuntimeError(
            "Expected exactly one directional priority inside "
            f"_vip_direction_flows(), found {count}. No changes were made."
        )

    patched_block = block.replace(OLD_PRIORITY, NEW_PRIORITY, 1)
    return text[:start_match.start()] + patched_block + text[end:], count


def patch_text(text: str) -> tuple[str, bool]:
    if CONSTANT_MARKER in text and NEW_PRIORITY in text:
        return text, False

    if text.count(CLASS_ANCHOR) != 1:
        raise RuntimeError(
            "Expected exactly one VIP_TAKEOVER_PRIORITY class anchor. "
            "No changes were made."
        )

    # Ensure dispatch priority remains separate and unchanged.
    dispatch_matches = re.findall(
        r"def _vip_dispatch_mod\(.*?priority=self\.VIP_TAKEOVER_PRIORITY,",
        text,
        flags=re.DOTALL,
    )
    if len(dispatch_matches) != 1:
        raise RuntimeError(
            "Could not validate _vip_dispatch_mod priority. No changes were made."
        )

    patched, _ = replace_in_function(text)
    patched = patched.replace(CLASS_ANCHOR, NEW_CONSTANT, 1)

    if patched.count(CONSTANT_MARKER) != 1:
        raise RuntimeError("Post-check failed for VIP_STEERING_PRIORITY.")
    if patched.count(NEW_PRIORITY) < 1:
        raise RuntimeError("Post-check failed for directional priority.")
    if "priority=self.VIP_TAKEOVER_PRIORITY," not in patched:
        raise RuntimeError("Dispatch priority was unexpectedly changed.")

    return patched, True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "file", nargs="?", type=Path, default=DEFAULT_FILE,
        help="topology_monitor.py path (default: ./topology_monitor.py)",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="only verify whether the file is patched; do not modify it",
    )
    args = parser.parse_args()
    path = args.file.resolve()

    if not path.is_file():
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        return 2

    original = path.read_text(encoding="utf-8")
    if CONSTANT_MARKER in original and NEW_PRIORITY in original:
        print(f"Already patched: {path}")
        return 0

    if args.check:
        print(f"Not patched yet: {path}")
        return 1

    try:
        patched, changed = patch_text(original)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3

    if not changed:
        print(f"No changes needed: {path}")
        return 0

    backup = backup_path(path)
    shutil.copy2(path, backup)
    path.write_text(patched, encoding="utf-8")

    print(f"Patched: {path}")
    print(f"Backup : {backup}")
    print("Directional VIP flows now use priority 50002.")
    print("Dispatch PacketIn flows remain at priority 49990.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
