# =============================================================
# CLFF Engine — Controller-Based Loop-Free Forwarding
#
# Purpose:
#   Provide controller-based loop-free forwarding for
#   unknown / broadcast traffic without using OFPP_FLOOD.
#
# Design:
#   - One BFS shortest-path tree is built from EVERY switch.
#   - No single global root.
#   - Each switch can therefore act as the ingress/root
#     of its own forwarding tree.
#   - Physical topology remains separate from CLFF trees.
#
# Used by:
#   - TopologyMonitor       -> owns topology and rebuilds CLFF
#   - TrafficMonitorMerged  -> uses CLFF for broadcast/unknown
#
# Important:
#   - No OFPP_FLOOD
#   - No STP
#   - Physical links are NOT removed by CLFF
#   - Dijkstra remains responsible for known unicast/rerouting
# =============================================================

import networkx as nx


class CLFFEngine:

    def __init__(self, logger=None):

        self.logger = logger

        # -----------------------------------------------------
        # BFS trees
        #
        # trees[root] = NetworkX directed BFS tree
        # -----------------------------------------------------
        self.trees = {}

        # -----------------------------------------------------
        # tree_ports[root][(parent, child)] = parent out port
        # -----------------------------------------------------
        self.tree_ports = {}

        # -----------------------------------------------------
        # parent_map[root][child] = parent
        # -----------------------------------------------------
        self.parent_map = {}

        # -----------------------------------------------------
        # children_map[root][parent] = [child1, child2, ...]
        # -----------------------------------------------------
        self.children_map = {}

        # -----------------------------------------------------
        # broadcast_ports[root][node] =
        #       [ports leading from node to its children]
        #
        # IMPORTANT:
        # This is NOT all physical ports.
        # It contains only CLFF tree child ports.
        # -----------------------------------------------------
        self.broadcast_ports = {}

        # -----------------------------------------------------
        # Physical graph used for the last successful build
        # -----------------------------------------------------
        self.last_graph = None

        # -----------------------------------------------------
        # CLFF readiness
        # -----------------------------------------------------
        self.ready = False

    # =========================================================
    # PORT MAPPING
    # =========================================================

    def _get_port_from_mapping(
        self,
        link_to_port,
        parent,
        child
    ):
        """
        Return the physical output port on 'parent' that reaches
        'child'.

        TopologyMonitor uses:

            link_to_port[(parent_dpid, child_dpid)]
                = (parent_port, child_port)

        Example:

            link_to_port[(1, 2)] = (3, 4)

        means:

            switch s1 -> s2 uses port 3
            switch s2 -> s1 uses port 4

        CLFF only needs the parent-side port, so this method
        returns 3.

        We intentionally use the exact representation used by
        TopologyMonitor instead of guessing other formats.
        """

        if link_to_port is None:
            return None

        # -----------------------------------------------------
        # Exact TopologyMonitor key
        # -----------------------------------------------------

        key = (parent, child)

        if key not in link_to_port:
            return None

        value = link_to_port[key]

        # -----------------------------------------------------
        # Expected format:
        #
        #     (parent_port, child_port)
        #
        # -----------------------------------------------------

        if isinstance(value, (tuple, list)):

            if len(value) < 1:
                return None

            try:
                return int(value[0])

            except (TypeError, ValueError):
                return None

        # -----------------------------------------------------
        # Also support direct scalar values safely
        # -----------------------------------------------------

        try:
            return int(value)

        except (TypeError, ValueError):
            return None

    # =========================================================
    # BUILD ALL TREES
    # =========================================================

    def build_trees(self, graph, link_to_port):
        """
        Build one BFS shortest-path tree from every switch.

        For N switches:
            N trees are created.

        Example:

            s1 -> Tree rooted at s1
            s2 -> Tree rooted at s2
            s3 -> Tree rooted at s3
            s4 -> Tree rooted at s4
            s5 -> Tree rooted at s5
            s6 -> Tree rooted at s6

        Each tree is loop-free because it is a tree.
        """

        # -----------------------------------------------------
        # Validate graph
        # -----------------------------------------------------

        if graph is None or len(graph.nodes()) == 0:

            self._log(
                "CLFF: cannot build trees - empty graph"
            )

            self.ready = False

            return False

        # -----------------------------------------------------
        # Validate port mapping
        # -----------------------------------------------------

        if link_to_port is None:

            self._log(
                "CLFF: cannot build trees - "
                "link_to_port is None"
            )

            self.ready = False

            return False

        # -----------------------------------------------------
        # Reset old CLFF state
        # -----------------------------------------------------

        self.ready = False

        self.trees.clear()
        self.tree_ports.clear()
        self.parent_map.clear()
        self.children_map.clear()
        self.broadcast_ports.clear()

        # -----------------------------------------------------
        # Save physical graph
        # -----------------------------------------------------

        self.last_graph = graph.copy()

        # -----------------------------------------------------
        # Build one BFS tree from EVERY switch
        # -----------------------------------------------------

        for root in graph.nodes():

            try:

                tree = nx.bfs_tree(
                    graph,
                    source=root
                )

            except Exception as e:

                self._log(
                    "CLFF: failed to build tree from s%d: %s"
                    % (root, e)
                )

                self.ready = False

                return False

            # -------------------------------------------------
            # Save tree
            # -------------------------------------------------

            self.trees[root] = tree

            # -------------------------------------------------
            # Per-root structures
            # -------------------------------------------------

            ports_for_root = {}
            parent_for_root = {}
            children_for_root = {}
            broadcast_for_root = {}

            # -------------------------------------------------
            # Initialize every node
            # -------------------------------------------------

            for node in tree.nodes():

                children_for_root[node] = []
                broadcast_for_root[node] = []

            # -------------------------------------------------
            # Process BFS tree edges
            # -------------------------------------------------

            for parent, child in tree.edges():

                # ---------------------------------------------
                # Parent relationship
                # ---------------------------------------------

                parent_for_root[child] = parent

                # ---------------------------------------------
                # Child relationship
                # ---------------------------------------------

                children_for_root[parent].append(child)

                # ---------------------------------------------
                # Resolve physical output port
                # ---------------------------------------------

                out_port = self._get_port_from_mapping(
                    link_to_port,
                    parent,
                    child
                )

                # ---------------------------------------------
                # Missing mapping
                # ---------------------------------------------

                if out_port is None:

                    self._log(
                        "CLFF: missing port mapping "
                        "s%d -> s%d"
                        % (
                            parent,
                            child
                        )
                    )

                    self.ready = False

                    return False

                # ---------------------------------------------
                # Save tree edge -> port
                # ---------------------------------------------

                ports_for_root[
                    (parent, child)
                ] = out_port

                # ---------------------------------------------
                # Save child forwarding port
                # ---------------------------------------------

                broadcast_for_root[parent].append(
                    out_port
                )

            # -------------------------------------------------
            # Save all structures for this root
            # -------------------------------------------------

            self.tree_ports[root] = ports_for_root

            self.parent_map[root] = parent_for_root

            self.children_map[root] = children_for_root

            self.broadcast_ports[root] = broadcast_for_root

            # -------------------------------------------------
            # Log
            # -------------------------------------------------

            self._log(
                "CLFF: Tree(s%d) built with %d nodes "
                "and %d edges"
                % (
                    root,
                    len(tree.nodes()),
                    len(tree.edges())
                )
            )

        # -----------------------------------------------------
        # Verify number of trees
        # -----------------------------------------------------

        expected_trees = len(graph.nodes())

        if len(self.trees) != expected_trees:

            self._log(
                "CLFF: tree count mismatch"
            )

            self.ready = False

            return False

        # -----------------------------------------------------
        # CLFF ready
        # -----------------------------------------------------

        self.ready = True

        self._log(
            "CLFF: successfully built %d trees"
            % len(self.trees)
        )

        return True

    # =========================================================
    # GET ROOT BROADCAST PORTS
    # =========================================================

    def get_broadcast_ports(self, dpid):

        if not self.ready:
            return []

        root_broadcast = self.broadcast_ports.get(dpid)

        if root_broadcast is None:
            return []

        return list(
            root_broadcast.get(
                dpid,
                []
            )
        )

    # =========================================================
    # GET FORWARDING PORTS FROM A NODE
    # =========================================================

    def get_forward_ports(
        self,
        root_dpid,
        current_dpid
    ):
        """
        Return CLFF child ports for current_dpid inside
        the tree rooted at root_dpid.

        Example:

            root = s1

            s1
           /  \
          s2  s3
          |
          s4

        Then:

            get_forward_ports(1, 1)
                -> ports s1->s2 and s1->s3

            get_forward_ports(1, 2)
                -> port s2->s4

            get_forward_ports(1, 3)
                -> ports leading to s3's children

        The parent port is intentionally NOT included.
        """

        if not self.ready:
            return []

        root_broadcast = self.broadcast_ports.get(
            root_dpid
        )

        if root_broadcast is None:
            return []

        return list(
            root_broadcast.get(
                current_dpid,
                []
            )
        )

    # =========================================================
    # GET FORWARDING PORTS EXCLUDING INCOMING PORT
    # =========================================================

    def get_forward_ports_excluding(
        self,
        root_dpid,
        current_dpid,
        incoming_port
    ):
        """
        Return CLFF child ports except the port from which the
        packet entered.

        Normally the incoming port is the parent-side port, so
        it is already absent from the child-port list.

        The explicit filtering makes the method safe if the
        topology/tree representation changes later.
        """

        ports = self.get_forward_ports(
            root_dpid,
            current_dpid
        )

        return [
            port
            for port in ports
            if port != incoming_port
        ]

    # =========================================================
    # GET TREE PORT
    # =========================================================

    def get_tree_port(
        self,
        dpid,
        child_dpid
    ):
        """
        Return the physical port on dpid that reaches
        child_dpid in the tree rooted at dpid.
        """

        if not self.ready:
            return None

        ports = self.tree_ports.get(dpid)

        if ports is None:
            return None

        return ports.get(
            (dpid, child_dpid)
        )

    # =========================================================
    # GET PARENT
    # =========================================================

    def get_parent(
        self,
        dpid,
        node_dpid
    ):

        if not self.ready:
            return None

        parents = self.parent_map.get(dpid)

        if parents is None:
            return None

        return parents.get(
            node_dpid
        )

    # =========================================================
    # GET CHILDREN
    # =========================================================

    def get_children(
        self,
        root_dpid,
        node_dpid
    ):

        if not self.ready:
            return []

        children = self.children_map.get(
            root_dpid
        )

        if children is None:
            return []

        return list(
            children.get(
                node_dpid,
                []
            )
        )

    # =========================================================
    # GET TREE
    # =========================================================

    def get_tree(self, root_dpid):

        if not self.ready:
            return None

        return self.trees.get(
            root_dpid
        )

    # =========================================================
    # IS READY
    # =========================================================

    def is_ready(self):

        return self.ready

    # =========================================================
    # REBUILD ON TOPOLOGY CHANGE
    # =========================================================

    def rebuild(
        self,
        graph,
        link_to_port
    ):

        self._log(
            "CLFF: rebuilding trees - topology changed"
        )

        self.ready = False

        return self.build_trees(
            graph,
            link_to_port
        )

    # =========================================================
    # SUMMARY
    # =========================================================

    def summary(self):

        if not self.ready:

            return {
                "ready": False,
                "trees": 0,
                "broadcast_ports": 0
            }

        total_broadcast_ports = 0

        for root in self.broadcast_ports:

            for node in self.broadcast_ports[root]:

                total_broadcast_ports += len(
                    self.broadcast_ports[root][node]
                )

        return {
            "ready": True,
            "trees": len(self.trees),
            "broadcast_ports": total_broadcast_ports
        }

    # =========================================================
    # LOGGING
    # =========================================================

    def _log(self, message):

        if self.logger is not None:

            self.logger.info(message)

        else:

            print(message)
	
