#!/usr/bin/env python3
"""Offline regression checks for Packet-In dataset-run flow reset."""
import ast
from pathlib import Path


SOURCE = Path("traffic_monitor_merged.py")
tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
monitor = next(
    node for node in tree.body
    if isinstance(node, ast.ClassDef) and node.name == "TrafficMonitorMerged"
)
methods = {
    node.name: node for node in monitor.body
    if isinstance(node, ast.FunctionDef)
}


class FakeTopology:
    def __init__(self):
        self.clear_calls = 0

    def clear_all_flows(self):
        self.clear_calls += 1


def main():
    helper = methods["_reset_topology_forwarding_flows"]
    harness = ast.ClassDef(
        name="Harness", bases=[], keywords=[], body=[helper], decorator_list=[]
    )
    module = ast.fix_missing_locations(ast.Module(body=[harness], type_ignores=[]))
    namespace = {}
    exec(compile(module, "<packetin-flow-reset-test>", "exec"), namespace)
    obj = namespace["Harness"]()
    topology = FakeTopology()
    obj._get_topology_monitor = lambda: topology
    obj._reset_topology_forwarding_flows()
    assert topology.clear_calls == 1

    start = methods["start_dataset_run"]
    reset_calls = [
        node.lineno for node in ast.walk(start)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_reset_topology_forwarding_flows"
    ]
    open_calls = [
        node.lineno for node in ast.walk(start)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_open_run_csvs_locked"
    ]
    assert reset_calls and open_calls and min(reset_calls) < min(open_calls)

    obj._get_topology_monitor = lambda: object()
    try:
        obj._reset_topology_forwarding_flows()
    except RuntimeError as exc:
        assert "clear_all_flows" in str(exc)
    else:
        raise AssertionError("reset must fail closed if TopologyMonitor is unavailable")

    print("PASS: owned forwarding flows are reset before dataset run files open")
    print("PASS: missing TopologyMonitor reset support fails closed")


if __name__ == "__main__":
    main()
