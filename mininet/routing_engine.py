#!/usr/bin/env python3
"""CLI smoke test for the shared traffic-aware PathEngine."""

import sys

import networkx as nx

from path_engine import PathEngine


DEFAULT_LINKS = [
    (1, 2),
    (2, 3),
    (3, 4),
    (4, 5),
    (1, 3),
    (2, 4),
    (3, 5),
]


def build_graph():
    graph = nx.Graph()
    graph.add_edges_from(DEFAULT_LINKS)
    return graph


def find_path(graph, src, dst):
    result = PathEngine().get_best_path(
        src=int(src),
        dst=int(dst),
        graph=graph,
    )
    return result.get("path") if result.get("success") else None


def reroute(src, dst, failed_src, failed_dst):
    graph = build_graph()
    src, dst = int(src), int(dst)
    failed = (int(failed_src), int(failed_dst))

    engine = PathEngine()
    normal = engine.get_best_path(src=src, dst=dst, graph=graph)

    print("\nSource:", src)
    print("Destination:", dst)
    print("Failed link:", failed[0], "<->", failed[1])
    print("Normal path:", " -> ".join(map(str, normal.get("path") or [])))

    if not graph.has_edge(*failed):
        print("ERROR: Link does not exist.")
        return
    if not normal.get("success"):
        print("Status: NO INITIAL PATH")
        return

    graph.remove_edge(*failed)
    backup = engine.get_backup_path(
        current_path=normal["path"],
        src=src,
        dst=dst,
        graph=graph,
        unavailable_links=[failed],
    )

    if backup.get("success"):
        print("Rerouted path:", " -> ".join(map(str, backup["path"])))
        print("Reason:", backup.get("reason"))
        print("Status: SUCCESS")
    else:
        print("Status: NO ALTERNATIVE PATH")


def main():
    if len(sys.argv) != 5:
        print(
            "Usage: python3 routing_engine_final.py "
            "<source> <destination> <failed_src> <failed_dst>"
        )
        return 2
    reroute(*sys.argv[1:])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
