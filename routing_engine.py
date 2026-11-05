#!/usr/bin/env python3
"""Compatibility CLI for the shared traffic-aware PathEngine."""

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
    return PathEngine(graph).find_path(int(src), int(dst))


def reroute(src, dst, failed_src, failed_dst):
    graph = build_graph()
    src = int(src)
    dst = int(dst)
    failed_src = int(failed_src)
    failed_dst = int(failed_dst)

    engine = PathEngine(graph)
    normal_path = engine.find_path(src, dst)

    print("\nSource:", src)
    print("Destination:", dst)
    print("Failed link:", failed_src, "<->", failed_dst)
    print("Normal path:", " -> ".join(map(str, normal_path or [])))

    if not graph.has_edge(failed_src, failed_dst):
        print("ERROR: Link does not exist.")
        return

    graph.remove_edge(failed_src, failed_dst)
    engine.set_graph(graph)
    new_path = engine.find_path(src, dst)

    if new_path:
        print("Rerouted path:", " -> ".join(map(str, new_path)))
        print("Status: SUCCESS")
    else:
        print("Status: NO ALTERNATIVE PATH")


def main():
    if len(sys.argv) != 5:
        print(
            "Usage: python3 routing_engine.py "
            "<source> <destination> <failed_src> <failed_dst>"
        )
        return

    reroute(*sys.argv[1:])


if __name__ == "__main__":
    main()
