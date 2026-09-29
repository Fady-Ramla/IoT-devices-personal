import sys
import networkx as nx


def build_graph():
    G = nx.Graph()

    links = [
        ("s1", "s2"),
        ("s2", "s3"),
        ("s3", "s4"),
        ("s4", "s5"),
        ("s1", "s3"),
        ("s2", "s4"),
        ("s3", "s5")
    ]

    for src, dst in links:
        G.add_edge(src, dst, weight=1)

    return G


def find_path(G, src, dst):
    return nx.shortest_path(
        G,
        source=src,
        target=dst,
        weight="weight"
    )


def reroute(src, dst, failed_src, failed_dst):

    G = build_graph()

    normal_path = find_path(G, src, dst)

    print("\nSource:", src)
    print("Destination:", dst)
    print("Failed link:", failed_src, "<->", failed_dst)
    print("Normal path:", " -> ".join(normal_path))

    if not G.has_edge(failed_src, failed_dst):
        print("ERROR: Link does not exist.")
        return

    G.remove_edge(failed_src, failed_dst)

    try:
        new_path = find_path(G, src, dst)

        print("Rerouted path:", " -> ".join(new_path))
        print("Status: SUCCESS")

    except nx.NetworkXNoPath:
        print("Status: NO ALTERNATIVE PATH")


def main():

    if len(sys.argv) != 5:
        print(
            "Usage: python3 mininet/routing_engine.py "
            "<source> <destination> <failed_src> <failed_dst>"
        )
        return

    src = sys.argv[1]
    dst = sys.argv[2]
    failed_src = sys.argv[3]
    failed_dst = sys.argv[4]

    reroute(
        src,
        dst,
        failed_src,
        failed_dst
    )


if __name__ == "__main__":
    main()
