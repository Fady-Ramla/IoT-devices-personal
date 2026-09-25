# topology_monitor.py
# =============================================================
# Ryu Topology Monitor
#
# Responsibilities:
#   - Discover and maintain switch-to-switch topology
#   - Learn host locations
#   - Track active host-to-host flows
#   - Detect physical link failures
#   - Calculate shortest paths using NetworkX / Dijkstra
#   - Install dynamic rerouting rules using OpenFlow 1.3
#
# Reroute integration:
#   TrafficMonitorMerged
#          |
#          v
#   EventRerouteHost
#          |
#          v
#   TopologyMonitor
#
# TrafficMonitorMerged does NOT calculate topology or Dijkstra.
# =============================================================

from ryu.base import app_manager

from ryu.controller import event as controller_event
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.controller.handler import (
    MAIN_DISPATCHER,
    DEAD_DISPATCHER
)

from ryu.topology import event
from ryu.topology.api import get_switch, get_link

from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4

from ryu.ofproto import ofproto_v1_3

import networkx as nx


# =============================================================
# CUSTOM REROUTE EVENT
# =============================================================

class EventRerouteHost(controller_event.EventBase):
    """
    Custom event sent by TrafficMonitorMerged to request
    rerouting of traffic associated with a specific host.
    """

    def __init__(self, host_ip, request_id=None):

        super(EventRerouteHost, self).__init__()

        self.host_ip = host_ip
        self.request_id = request_id


# =============================================================
# TOPOLOGY MONITOR
# =============================================================

class TopologyMonitor(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):

        super(TopologyMonitor, self).__init__(*args, **kwargs)

        # -----------------------------------------------------
        # Expected project topology
        # -----------------------------------------------------

        self.EXPECTED_SWITCHES = 5
        self.EXPECTED_PHYSICAL_LINKS = 7

        # -----------------------------------------------------
        # Topology state
        # -----------------------------------------------------

        self.topology_ready = False

        # -----------------------------------------------------
        # Physical switch-to-switch links.
        #
        # Each physical link is stored only once:
        #
        #     (1, 2)
        #     (1, 3)
        #     (2, 3)
        #
        # The reverse direction is NOT stored separately.
        # -----------------------------------------------------

        self.edges = set()

        # -----------------------------------------------------
        # Port mapping:
        #
        #     (dpid, port_no) -> physical edge
        #
        # Example:
        #
        #     (1, 3) -> (1, 2)
        # -----------------------------------------------------

        self.port_to_link = {}

        # -----------------------------------------------------
        # Output port mapping:
        #
        #     ("s1", "s2") -> 3
        #
        # Means:
        #
        #     To go from s1 to s2,
        #     use port 3 on s1.
        # -----------------------------------------------------

        self.link_to_port = {}

        # -----------------------------------------------------
        # Host state
        # -----------------------------------------------------

        # MAC -> (switch_dpid, host_port)
        self.host_location = {}

        # IP -> MAC
        self.ip_to_mac = {}

        # -----------------------------------------------------
        # Datapaths
        # -----------------------------------------------------

        # DPID -> datapath
        self.datapaths = {}

        # -----------------------------------------------------
        # Active flows
        # -----------------------------------------------------

        # Set of:
        #
        #     (src_mac, dst_mac)
        #
        self.active_flows = set()

        # -----------------------------------------------------
        # Background topology initialization
        # -----------------------------------------------------

        self.topology_thread = hub.spawn(
            self.initialize_topology
        )

        self.logger.info(
            "TopologyMonitor initialized"
        )

    # =========================================================
    # SWITCH STATE
    # =========================================================

    @handler.set_ev_cls(
        ofp_event.EventOFPStateChange,
        [MAIN_DISPATCHER, DEAD_DISPATCHER]
    )
    def state_change_handler(self, ev):

        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:

            if datapath.id not in self.datapaths:

                self.datapaths[datapath.id] = datapath

                self.logger.info(
                    "Switch connected: s%d",
                    datapath.id
                )

        elif ev.state == DEAD_DISPATCHER:

            if datapath.id in self.datapaths:

                del self.datapaths[datapath.id]

                self.logger.info(
                    "Switch disconnected: s%d",
                    datapath.id
                )

                self.topology_ready = False

    # =========================================================
    # TOPOLOGY EVENTS
    # =========================================================

    @handler.set_ev_cls(event.EventSwitchEnter)
    def switch_enter(self, ev):

        self.logger.info(
            "Switch entered topology"
        )

    # ---------------------------------------------------------
    # LINK ADD
    # ---------------------------------------------------------

    @handler.set_ev_cls(event.EventLinkAdd)
    def link_add(self, ev):

        try:

            link = ev.link

            src = link.src
            dst = link.dst

            edge = tuple(
                sorted(
                    (
                        src.dpid,
                        dst.dpid
                    )
                )
            )

            self.logger.info(
                "TOPOLOGY LINK ADD: s%d:%d -> s%d:%d",
                src.dpid,
                src.port_no,
                dst.dpid,
                dst.port_no
            )

            # -------------------------------------------------
            # Add the new physical edge.
            #
            # A set prevents duplicate reverse-direction
            # entries.
            # -------------------------------------------------

            self.edges.add(
                edge
            )

            # -------------------------------------------------
            # Update port mappings immediately.
            # -------------------------------------------------

            self.port_to_link[
                (
                    src.dpid,
                    src.port_no
                )
            ] = edge

            self.port_to_link[
                (
                    dst.dpid,
                    dst.port_no
                )
            ] = edge

            src_name = "s%d" % src.dpid
            dst_name = "s%d" % dst.dpid

            self.link_to_port[
                (
                    src_name,
                    dst_name
                )
            ] = src.port_no

            self.link_to_port[
                (
                    dst_name,
                    src_name
                )
            ] = dst.port_no

            # -------------------------------------------------
            # Check whether the complete project topology
            # is now available.
            # -------------------------------------------------

            if (
                len(self.datapaths) >= self.EXPECTED_SWITCHES
                and len(self.edges) >= self.EXPECTED_PHYSICAL_LINKS
            ):

                self.topology_ready = True

                self.logger.info(
                    "Topology is ready after link addition: "
                    "%d switches, %d physical links",
                    len(self.datapaths),
                    len(self.edges)
                )

        except Exception as exc:

            self.logger.exception(
                "Failed to process topology link addition: %s",
                exc
            )

    # ---------------------------------------------------------
    # SWITCH LEAVE
    # ---------------------------------------------------------

    @handler.set_ev_cls(event.EventSwitchLeave)
    def switch_leave(self, ev):

        self.logger.warning(
            "Switch left topology"
        )

        self.topology_ready = False

    # ---------------------------------------------------------
    # LINK DELETE
    # ---------------------------------------------------------

    @handler.set_ev_cls(event.EventLinkDelete)
    def link_delete(self, ev):

        """
        Handle Ryu topology link-delete events directly.

        EventLinkDelete is the primary topology failure path.

        The failed physical edge is removed from:
            - self.edges
            - self.port_to_link
            - self.link_to_port

        Then active flows are rerouted.
        """

        try:

            link = ev.link

            src = link.src
            dst = link.dst

            failed_edge = tuple(
                sorted(
                    (
                        src.dpid,
                        dst.dpid
                    )
                )
            )

            self.logger.warning(
                "TOPOLOGY LINK DELETE: s%d:%d -> s%d:%d",
                src.dpid,
                src.port_no,
                dst.dpid,
                dst.port_no
            )

            self.logger.warning(
                "Mapped failed physical edge: %s",
                failed_edge
            )

            self.handle_link_failure(
                failed_edge
            )

        except Exception as exc:

            self.logger.exception(
                "Failed to process topology link deletion: %s",
                exc
            )

    # =========================================================
    # PACKET IN
    # =========================================================

    @handler.set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER
    )
    def packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath

        dpid = datapath.id

        in_port = msg.match.get(
            "in_port"
        )

        if in_port is None:
            return

        pkt = packet.Packet(
            msg.data
        )

        eth = pkt.get_protocol(
            ethernet.ethernet
        )

        if eth is None:
            return

        src_mac = eth.src
        dst_mac = eth.dst

        # -----------------------------------------------------
        # Ignore LLDP
        # -----------------------------------------------------

        if eth.ethertype == 0x88cc:
            return

        # -----------------------------------------------------
        # Ignore broadcast / multicast source
        # -----------------------------------------------------

        if src_mac.startswith(
            "01:00:00"
        ):
            return

        if src_mac.lower() == (
            "ff:ff:ff:ff:ff:ff"
        ):
            return

        # -----------------------------------------------------
        # Check whether packet arrived from switch link.
        #
        # If this is a known inter-switch port, do not learn
        # the source as a host.
        # -----------------------------------------------------

        if (
            dpid,
            in_port
        ) in self.port_to_link:

            return

        # -----------------------------------------------------
        # Learn host MAC location
        # -----------------------------------------------------

        self.host_location[
            src_mac
        ] = (
            dpid,
            in_port
        )

        # -----------------------------------------------------
        # Learn IPv4 -> MAC
        # -----------------------------------------------------

        ip_pkt = pkt.get_protocol(
            ipv4.ipv4
        )

        if ip_pkt is not None:

            self.ip_to_mac[
                ip_pkt.src
            ] = src_mac

        # -----------------------------------------------------
        # Track known-unicast flows
        # -----------------------------------------------------

        if dst_mac in self.host_location:

            self.active_flows.add(
                (
                    src_mac,
                    dst_mac
                )
            )

    # =========================================================
    # CUSTOM REROUTE EVENT
    # =========================================================

    @handler.set_ev_cls(
        EventRerouteHost
    )
    def handle_reroute_request(self, ev):

        self.logger.info(
            "Reroute request received: host=%s request_id=%s",
            ev.host_ip,
            ev.request_id
        )

        result = self.reroute_host(
            ev.host_ip
        )

        if result:

            self.logger.info(
                "Reroute completed for host=%s request_id=%s",
                ev.host_ip,
                ev.request_id
            )

        else:

            self.logger.warning(
                "Reroute could not be completed for host=%s "
                "request_id=%s",
                ev.host_ip,
                ev.request_id
            )

    # =========================================================
    # REROUTE HOST
    # =========================================================

    def reroute_host(self, host_ip):

        if not self.topology_ready:

            self.logger.warning(
                "Cannot reroute %s: topology is not ready",
                host_ip
            )

            return False

        # -----------------------------------------------------
        # Resolve host IP -> MAC
        # -----------------------------------------------------

        host_mac = self.ip_to_mac.get(
            host_ip
        )

        if host_mac is None:

            self.logger.warning(
                "Cannot reroute %s: MAC address unknown",
                host_ip
            )

            return False

        # -----------------------------------------------------
        # Find active flows involving host
        # -----------------------------------------------------

        related_flows = []

        for src_mac, dst_mac in self.active_flows:

            if (
                src_mac == host_mac
                or dst_mac == host_mac
            ):

                related_flows.append(
                    (
                        src_mac,
                        dst_mac
                    )
                )

        if not related_flows:

            self.logger.warning(
                "No active flows found for %s",
                host_ip
            )

            return False

        self.logger.info(
            "Found %d active flow(s) for %s",
            len(related_flows),
            host_ip
        )

        # -----------------------------------------------------
        # Reroute every related flow
        # -----------------------------------------------------

        success = False

        for src_mac, dst_mac in related_flows:

            src_location = self.host_location.get(
                src_mac
            )

            dst_location = self.host_location.get(
                dst_mac
            )

            if (
                src_location is None
                or dst_location is None
            ):

                self.logger.warning(
                    "Cannot reroute flow %s -> %s: "
                    "host location unknown",
                    src_mac,
                    dst_mac
                )

                continue

            src_dpid, src_port = src_location
            dst_dpid, dst_port = dst_location

            self.logger.info(
                "Rerouting flow %s -> %s",
                src_mac,
                dst_mac
            )

            result = self.install_dynamic_path(
                src_dpid,
                src_port,
                dst_dpid,
                dst_port,
                src_mac,
                dst_mac
            )

            if result:
                success = True

        return success

    # =========================================================
    # INITIALIZE TOPOLOGY
    # =========================================================

    def initialize_topology(self):

        while True:

            try:

                switches = get_switch(
                    self,
                    None
                )

                links = get_link(
                    self,
                    None
                )

                # -------------------------------------------------
                # Convert Ryu directional link objects into
                # unique physical switch-to-switch edges.
                #
                # Example:
                #
                #   s1 -> s2
                #   s2 -> s1
                #
                # become one physical edge:
                #
                #   (1, 2)
                # -------------------------------------------------

                discovered_edges = self.get_unique_edges(
                    links
                )

                # -------------------------------------------------
                # Debug information
                # -------------------------------------------------

                self.logger.info(
                    "Topology discovery: switches=%d "
                    "link_objects=%d unique_physical_links=%d",
                    len(switches),
                    len(links),
                    len(discovered_edges)
                )

                for link in links:

                    self.logger.info(
                        "DISCOVERED LINK: s%d:%d -> s%d:%d",
                        link.src.dpid,
                        link.src.port_no,
                        link.dst.dpid,
                        link.dst.port_no
                    )

                self.logger.info(
                    "Unique physical edges: %s",
                    sorted(discovered_edges)
                )

                # -------------------------------------------------
                # Expected project topology:
                #
                #   5 switches
                #   7 physical switch-to-switch links
                # -------------------------------------------------

                if (
                    len(switches) >= self.EXPECTED_SWITCHES
                    and len(discovered_edges)
                    >= self.EXPECTED_PHYSICAL_LINKS
                ):

                    self.build_topology_maps(
                        switches,
                        links
                    )

                    self.topology_ready = True

                    self.logger.info(
                        "Topology ready: %d switches, "
                        "%d physical links",
                        len(switches),
                        len(self.edges)
                    )

                    break

                else:

                    self.topology_ready = False

                    self.logger.info(
                        "Waiting for topology... "
                        "switches=%d "
                        "link_objects=%d "
                        "unique_physical_links=%d "
                        "expected=%d",
                        len(switches),
                        len(links),
                        len(discovered_edges),
                        self.EXPECTED_PHYSICAL_LINKS
                    )

            except Exception as exc:

                self.logger.exception(
                    "Topology initialization error: %s",
                    exc
                )

            hub.sleep(2)

    # =========================================================
    # GET UNIQUE PHYSICAL EDGES
    # =========================================================

    def get_unique_edges(self, links):

        edges = set()

        for link in links:

            src_dpid = link.src.dpid
            dst_dpid = link.dst.dpid

            # -------------------------------------------------
            # Ignore invalid self-links.
            # -------------------------------------------------

            if src_dpid == dst_dpid:
                continue

            edge = tuple(
                sorted(
                    (
                        src_dpid,
                        dst_dpid
                    )
                )
            )

            edges.add(
                edge
            )

        return edges

    # =========================================================
    # BUILD TOPOLOGY MAPS
    # =========================================================

    def build_topology_maps(
        self,
        switches,
        links
    ):

        # -----------------------------------------------------
        # Rebuild everything from the current Ryu topology.
        #
        # This prevents stale mappings after topology changes.
        # -----------------------------------------------------

        self.edges.clear()
        self.port_to_link.clear()
        self.link_to_port.clear()

        # -----------------------------------------------------
        # Build switch edges and port mappings.
        #
        # Ryu can provide both directions of a physical link.
        # Both directions are useful here because each side
        # has its own OpenFlow output port.
        # -----------------------------------------------------

        for link in links:

            src = link.src
            dst = link.dst

            src_dpid = src.dpid
            dst_dpid = dst.dpid

            # -------------------------------------------------
            # Ignore invalid self-links.
            # -------------------------------------------------

            if src_dpid == dst_dpid:
                continue

            # -------------------------------------------------
            # Store one physical edge only.
            # -------------------------------------------------

            edge = tuple(
                sorted(
                    (
                        src_dpid,
                        dst_dpid
                    )
                )
            )

            self.edges.add(
                edge
            )

            # -------------------------------------------------
            # Port mapping.
            #
            # Each direction has a different physical port.
            # -------------------------------------------------

            self.port_to_link[
                (
                    src_dpid,
                    src.port_no
                )
            ] = edge

            self.port_to_link[
                (
                    dst_dpid,
                    dst.port_no
                )
            ] = edge

            # -------------------------------------------------
            # Output port mapping.
            # -------------------------------------------------

            src_name = "s%d" % src_dpid
            dst_name = "s%d" % dst_dpid

            self.link_to_port[
                (
                    src_name,
                    dst_name
                )
            ] = src.port_no

            self.link_to_port[
                (
                    dst_name,
                    src_name
                )
            ] = dst.port_no

        self.logger.info(
            "Topology maps rebuilt"
        )

        self.logger.info(
            "Physical edges: %s",
            sorted(self.edges)
        )

        self.logger.info(
            "Port mappings: %d",
            len(self.port_to_link)
        )

        self.logger.info(
            "Link-to-port mappings: %d",
            len(self.link_to_port)
        )

    # =========================================================
    # PORT STATUS / LINK FAILURE
    # =========================================================

    @handler.set_ev_cls(
        ofp_event.EventOFPPortStatus,
        MAIN_DISPATCHER
    )
    def port_status_change(self, ev):

        msg = ev.msg
        datapath = msg.datapath

        desc = msg.desc

        ofp = datapath.ofproto

        # -----------------------------------------------------
        # Only process link-down events.
        # -----------------------------------------------------

        if not (
            desc.state & ofp.OFPPS_LINK_DOWN
        ):

            return

        failed_dpid = datapath.id
        failed_port = desc.port_no

        physical_link = self.port_to_link.get(
            (
                failed_dpid,
                failed_port
            )
        )

        # -----------------------------------------------------
        # EventLinkDelete is normally the primary failure
        # detection path.
        #
        # This handler remains a fallback.
        # -----------------------------------------------------

        if physical_link is None:

            self.logger.warning(
                "Link-down detected but physical link "
                "could not be mapped by port status: "
                "s%d port=%d",
                failed_dpid,
                failed_port
            )

            return

        self.logger.warning(
            "LINK FAILURE detected by port status: %s",
            physical_link
        )

        self.handle_link_failure(
            physical_link
        )

    # =========================================================
    # HANDLE LINK FAILURE
    # =========================================================

    def handle_link_failure(
        self,
        failed_edge
    ):

        # -----------------------------------------------------
        # Prevent duplicate processing.
        # -----------------------------------------------------

        if failed_edge not in self.edges:

            self.logger.info(
                "Failed edge %s is already removed "
                "or not present",
                failed_edge
            )

            return False

        # -----------------------------------------------------
        # Remove failed edge from topology graph.
        # -----------------------------------------------------

        self.edges.remove(
            failed_edge
        )

        self.logger.warning(
            "Removed failed edge from topology graph: %s",
            failed_edge
        )

        # -----------------------------------------------------
        # Remove port mappings belonging to failed link.
        # -----------------------------------------------------

        ports_to_remove = []

        for key, edge in list(
            self.port_to_link.items()
        ):

            if edge == failed_edge:

                ports_to_remove.append(
                    key
                )

        for key in ports_to_remove:

            del self.port_to_link[
                key
            ]

        # -----------------------------------------------------
        # Remove logical link mappings.
        # -----------------------------------------------------

        dpid_a, dpid_b = failed_edge

        names = [
            (
                "s%d" % dpid_a,
                "s%d" % dpid_b
            ),
            (
                "s%d" % dpid_b,
                "s%d" % dpid_a
            )
        ]

        for key in names:

            self.link_to_port.pop(
                key,
                None
            )

        # -----------------------------------------------------
        # Update topology state.
        # -----------------------------------------------------

        self.topology_ready = (
            len(self.datapaths)
            >= self.EXPECTED_SWITCHES
            and len(self.edges)
            >= self.EXPECTED_PHYSICAL_LINKS
        )

        self.logger.info(
            "Removed port and logical mappings "
            "for failed edge %s",
            failed_edge
        )

        self.logger.info(
            "Remaining physical edges: %s",
            sorted(self.edges)
        )

        # -----------------------------------------------------
        # Reroute active flows.
        # -----------------------------------------------------

        self.reroute_active_flows()

        return True

    # =========================================================
    # REROUTE ACTIVE FLOWS
    # =========================================================

    def reroute_active_flows(self):

        self.logger.info(
            "Rerouting active flows after topology change"
        )

        rerouted = 0

        for src_mac, dst_mac in list(
            self.active_flows
        ):

            src_location = self.host_location.get(
                src_mac
            )

            dst_location = self.host_location.get(
                dst_mac
            )

            if (
                src_location is None
                or dst_location is None
            ):

                self.logger.warning(
                    "Skipping flow %s -> %s: "
                    "host location unknown",
                    src_mac,
                    dst_mac
                )

                continue

            src_dpid, src_port = src_location
            dst_dpid, dst_port = dst_location

            result = self.install_dynamic_path(
                src_dpid,
                src_port,
                dst_dpid,
                dst_port,
                src_mac,
                dst_mac
            )

            if result:

                rerouted += 1

        self.logger.info(
            "Active flow rerouting completed: %d flow(s)",
            rerouted
        )

    # =========================================================
    # BUILD NETWORKX GRAPH
    # =========================================================

    def build_graph(self):

        graph = nx.Graph()

        # -----------------------------------------------------
        # Add currently connected switches.
        # -----------------------------------------------------

        for dpid in self.datapaths:

            graph.add_node(
                dpid
            )

        # -----------------------------------------------------
        # Add currently active physical links.
        # -----------------------------------------------------

        for src, dst in self.edges:

            graph.add_edge(
                src,
                dst,
                weight=1
            )

        return graph

    # =========================================================
    # DIJKSTRA
    # =========================================================

    def calculate_path(
        self,
        src_dpid,
        dst_dpid
    ):

        graph = self.build_graph()

        try:

            path = nx.shortest_path(
                graph,
                source=src_dpid,
                target=dst_dpid,
                weight="weight"
            )

            self.logger.info(
                "Calculated path: %s",
                path
            )

            return path

        except nx.NetworkXNoPath:

            self.logger.warning(
                "No path available: s%d -> s%d",
                src_dpid,
                dst_dpid
            )

            return None

        except nx.NodeNotFound:

            self.logger.warning(
                "Unknown switch in path calculation"
            )

            return None

    # =========================================================
    # INSTALL DYNAMIC PATH
    # =========================================================

    def install_dynamic_path(
        self,
        src_dpid,
        src_port,
        dst_dpid,
        dst_port,
        src_mac,
        dst_mac
    ):

        path = self.calculate_path(
            src_dpid,
            dst_dpid
        )

        if not path:

            self.logger.warning(
                "Cannot install dynamic path: "
                "no path available"
            )

            return False

        self.logger.info(
            "Installing dynamic path %s -> %s: %s",
            src_mac,
            dst_mac,
            path
        )

        # -----------------------------------------------------
        # Remove previous reroute rules.
        # -----------------------------------------------------

        self.clear_path_flows(
            src_mac,
            dst_mac
        )

        # -----------------------------------------------------
        # Forward direction.
        # -----------------------------------------------------

        forward_ok = self.install_one_direction(
            path,
            src_port,
            dst_port,
            src_mac,
            dst_mac
        )

        # -----------------------------------------------------
        # Reverse direction.
        # -----------------------------------------------------

        reverse_ok = self.install_one_direction(
            list(reversed(path)),
            dst_port,
            src_port,
            dst_mac,
            src_mac
        )

        return (
            forward_ok
            and reverse_ok
        )

    # =========================================================
    # INSTALL ONE DIRECTION
    # =========================================================

    def install_one_direction(
        self,
        path,
        host_src_port,
        host_dst_port,
        src_mac,
        dst_mac
    ):

        if len(path) == 1:

            dpid = path[0]

            return self.install_flow(
                dpid,
                host_src_port,
                host_dst_port,
                src_mac,
                dst_mac
            )

        # -----------------------------------------------------
        # First switch.
        # -----------------------------------------------------

        first_dpid = path[0]
        first_next = path[1]

        first_out_port = self.link_to_port.get(
            (
                "s%d" % first_dpid,
                "s%d" % first_next
            )
        )

        if first_out_port is None:

            self.logger.warning(
                "No output port for s%d -> s%d",
                first_dpid,
                first_next
            )

            return False

        if not self.install_flow(
            first_dpid,
            host_src_port,
            first_out_port,
            src_mac,
            dst_mac
        ):

            return False

        # -----------------------------------------------------
        # Middle switches.
        # -----------------------------------------------------

        for index in range(
            1,
            len(path) - 1
        ):

            current_dpid = path[index]

            previous_dpid = path[index - 1]
            next_dpid = path[index + 1]

            in_port = self.link_to_port.get(
                (
                    "s%d" % current_dpid,
                    "s%d" % previous_dpid
                )
            )

            out_port = self.link_to_port.get(
                (
                    "s%d" % current_dpid,
                    "s%d" % next_dpid
                )
            )

            if (
                in_port is None
                or out_port is None
            ):

                self.logger.warning(
                    "Missing port mapping at s%d",
                    current_dpid
                )

                return False

            if not self.install_flow(
                current_dpid,
                in_port,
                out_port,
                src_mac,
                dst_mac
            ):

                return False

        # -----------------------------------------------------
        # Last switch.
        # -----------------------------------------------------

        last_dpid = path[-1]
        previous_dpid = path[-2]

        last_in_port = self.link_to_port.get(
            (
                "s%d" % last_dpid,
                "s%d" % previous_dpid
            )
        )

        if last_in_port is None:

            self.logger.warning(
                "Missing destination input port"
            )

            return False

        return self.install_flow(
            last_dpid,
            last_in_port,
            host_dst_port,
            src_mac,
            dst_mac
        )

    # =========================================================
    # INSTALL FLOW
    # =========================================================

    def install_flow(
        self,
        dpid,
        in_port,
        out_port,
        src_mac,
        dst_mac
    ):

        datapath = self.datapaths.get(
            dpid
        )

        if datapath is None:

            self.logger.warning(
                "Datapath s%d not available",
                dpid
            )

            return False

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            in_port=in_port,
            eth_src=src_mac,
            eth_dst=dst_mac
        )

        actions = [
            parser.OFPActionOutput(
                out_port
            )
        ]

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=instructions
        )

        datapath.send_msg(
            mod
        )

        self.logger.info(
            "Installed priority=100 flow on s%d: "
            "%s -> %s | in=%s out=%s",
            dpid,
            src_mac,
            dst_mac,
            in_port,
            out_port
        )

        return True

    # =========================================================
    # CLEAR REROUTE FLOWS
    # =========================================================

    def clear_path_flows(
        self,
        src_mac,
        dst_mac
    ):

        for dpid, datapath in list(
            self.datapaths.items()
        ):

            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            match = parser.OFPMatch(
                eth_src=src_mac,
                eth_dst=dst_mac
            )

            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=100,
                match=match
            )

            datapath.send_msg(
                mod
            )

    # =========================================================
    # DELETE ALL REROUTE FLOWS
    # =========================================================

    def clear_all_flows(self):

        for dpid, datapath in list(
            self.datapaths.items()
        ):

            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            match = parser.OFPMatch()

            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=100,
                match=match
            )

            datapath.send_msg(
                mod
            )

    # =========================================================
    # HOST LOCATION
    # =========================================================

    def get_host_location(
        self,
        mac
    ):

        return self.host_location.get(
            mac
        )

    # =========================================================
    # GET PATH BETWEEN HOSTS
    # =========================================================

    def get_path_between_hosts(
        self,
        src_mac,
        dst_mac
    ):

        src_location = self.host_location.get(
            src_mac
        )

        dst_location = self.host_location.get(
            dst_mac
        )

        if (
            src_location is None
            or dst_location is None
        ):

            return None

        src_dpid = src_location[0]
        dst_dpid = dst_location[0]

        return self.calculate_path(
            src_dpid,
            dst_dpid
        )

    # =========================================================
    # CLEANUP
    # =========================================================

    def close(self):

        try:

            self.clear_all_flows()

        except Exception:

            pass

        super(
            TopologyMonitor,
            self
        ).close()
