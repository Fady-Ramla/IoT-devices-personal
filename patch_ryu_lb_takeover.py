#!/usr/bin/env python3
"""Safely patch Ryu VIP takeover constants and None-safe LB result handling.

Run from the project directory:
    python3 patch_ryu_lb_takeover.py [path/to/topology_monitor.py]
The script creates a timestamped backup before modifying the target file.
"""
import ast
import datetime
import sys
from pathlib import Path

DEFAULT_TARGET = Path("topology_monitor.py")
CONSTANTS = {
    "VIP_TAKEOVER_PRIORITY": 49990,
    "VIP_FLOW_IDLE_TIMEOUT": 60,
    "VIP_FLOW_HARD_TIMEOUT": 300,
}
OLD_EXPR = 'result.get("vip_takeover", {}).get("success")'
NEW_EXPR = '(result.get("vip_takeover") or {}).get("success")'


def find_topology_class(tree):
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "TopologyMonitor":
            return node
    raise RuntimeError("class TopologyMonitor was not found")


def class_assigned_names(class_node):
    names = set()
    for node in class_node.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


def find_method(class_node, method_name):
    for node in class_node.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == method_name:
            return node
    raise RuntimeError(f"TopologyMonitor.{method_name} was not found")


def main():
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_TARGET
    if len(sys.argv) > 2:
        print("Usage: python3 patch_ryu_lb_takeover.py [path/to/topology_monitor.py]")
        return 2
    target = target.resolve()
    if not target.is_file():
        print(f"ERROR: file not found: {target}")
        return 2

    original = target.read_text(encoding="utf-8")
    try:
        tree = ast.parse(original, filename=str(target))
        topology = find_topology_class(tree)
        block_method = find_method(topology, "block_load_balancer")
    except (SyntaxError, RuntimeError) as exc:
        print(f"ERROR: source structure check failed; file unchanged: {exc}")
        return 1

    # Add any missing class constants at the top of TopologyMonitor.
    assigned = class_assigned_names(topology)
    missing = [(name, value) for name, value in CONSTANTS.items() if name not in assigned]
    lines = original.splitlines(keepends=True)
    insert_after = topology.lineno  # immediately after `class TopologyMonitor:`
    if topology.body and isinstance(topology.body[0], ast.Expr):
        value = topology.body[0].value
        if isinstance(value, (ast.Str, ast.Constant)) and isinstance(getattr(value, "value", None), str):
            insert_after = topology.body[0].end_lineno
    indent = " " * 4
    additions = [f"{indent}{name} = {value}\n" for name, value in missing]
    if additions:
        lines[insert_after:insert_after] = additions
    updated = "".join(lines)

    # Make emergency_failover calculation safe when block_device reports no takeover result.
    old_count = updated.count(OLD_EXPR)
    if old_count:
        updated = updated.replace(OLD_EXPR, NEW_EXPR, 1)
    elif NEW_EXPR in updated:
        pass  # already patched
    else:
        print("ERROR: expected vip_takeover expression not found; file unchanged")
        return 1

    if updated == original:
        print("No changes needed; target is already patched:", target)
        return 0

    try:
        ast.parse(updated, filename=str(target))
    except SyntaxError as exc:
        print(f"ERROR: patched source would not parse; file unchanged: {exc}")
        return 1

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = target.with_name(f"{target.name}.bak-{stamp}")
    if backup.exists():
        print(f"ERROR: backup already exists: {backup}; file unchanged")
        return 1
    backup.write_text(original, encoding="utf-8")
    target.write_text(updated, encoding="utf-8")

    changed = [name for name, _ in missing]
    if old_count:
        changed.append("None-safe vip_takeover result")
    print("Patched:", target)
    print("Backup:", backup)
    print("Changes:", ", ".join(changed) if changed else "none")
    print("Syntax validation: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
