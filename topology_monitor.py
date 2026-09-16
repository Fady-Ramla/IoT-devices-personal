from ryu.base import app_manager
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER

from ryu.topology import event
from ryu.topology.api import get_switch, get_link

from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

import networkx as nx


class TopologyMonitor(app_manager.RyuApp):

    OFP_VERSIONS = [4]

    def __init__(self, *args, **kwargs):
        super(TopologyMonitor, self).__init__(*args, **kwargs)

        # ========================================================
        # TOPOLOGY STATE
        # ========================================================

        self.topology_ready = False

        # Active physical switch-to-switch links.
        self.edges = set()

        # ========================================================
        # SWITCH LINK PORT MAPPING
        # ========================================================

        # (switch_dpid, port_no) -> ('sX', 'sY')
        self.port_to_link = {}

        # ('sX', 'sY') -> output port on sX
        self.link_to_port = {}

        # ========================================================
        # HOST LEARNING
        # ========================================================

        # host MAC -> (switch_dpid, host_port)
        self.host_location = {}

        # ========================================================
        # DATAPATHS
        # ========================================================

        # switch DPID -> Ryu datapath object
        self.datapaths = {}

        # ========================================================
        # ACTIVE FLOWS
        # ========================================================

        # Set of learned unicast communication pairs.
        #
        # Example:
        # (h5_mac, h9_mac)
        #
        # These flows will be rerouted automatically
        # when a physical link fails.
        self.active_flows = set()

        # ========================================================
        # TOPOLOGY MONITOR THREAD
        # ========================================================

        self.monitor_thread = hub.spawn(
            self.initialize_topology
        )

    # ============================================================
    # DATAPATH STATE
    # ============================================================

    @handler.set_ev_cls(
        ofp_event.EventOFPStateChange,
        [MAIN_DISPATCHER, DEAD_DISPATCHER]
    )
    def state_change_handler(self, ev):

        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:

            self.datapaths[datapath.id] = datapath

            print(
                "Datapath connected:",
                "s" + str(datapath.id)
            )

        elif ev.state == DEAD_DISPATCHER:

            self.datapaths.pop(
                datapath.id,
                None
            )

            print(
                "Datapath disconnected:",
                "s" + str(datapath.id)
            )

    # ============================================================
    # SWITCH DISCOVERY
    # ============================================================

    @handler.set_ev_cls(event.EventSwitchEnter)
    def switch_enter(self, ev):

        print("Switch detected")

    # ============================================================
    # LINK DISCOVERY
    # ============================================================

    @handler.set_ev_cls(event.EventLinkAdd)
    def link_add(self, ev):

        print("Link detected")

    # ============================================================
    # PACKET-IN / HOST LEARNING
    # ============================================================

    @handler.set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER
    )
    def packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath

        switch_dpid = datapath.id

        in_port = msg.match.get('in_port')

        if in_port is None:
            return

        # --------------------------------------------------------
        # Do not learn switch-to-switch traffic as a host.
        # --------------------------------------------------------

        if (switch_dpid, in_port) in self.port_to_link:
            return

        # --------------------------------------------------------
        # Parse Ethernet frame.
        # --------------------------------------------------------

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(
            ethernet.ethernet
        )

        if eth is None:
            return

        # --------------------------------------------------------
        # Ignore LLDP.
        # --------------------------------------------------------

        if eth.ethertype == 0x88cc:
            return

        src_mac = eth.src
        dst_mac = eth.dst

        # --------------------------------------------------------
        # Ignore multicast/broadcast source MACs.
        # --------------------------------------------------------

        first_octet = int(
            src_mac.split(':')[0],
            16
        )

        if first_octet & 1:
            return

        # --------------------------------------------------------
        # Learn source host location.
        # --------------------------------------------------------

        current_location = (
            switch_dpid,
            in_port
        )

        previous_location = self.host_location.get(
            src_mac
        )

        if previous_location != current_location:

            self.host_location[src_mac] = current_location

            print(
                "\n========== HOST LEARNING =========="
            )

            print(
                "Host MAC:",
                src_mac
            )

            print(
                "Switch:",
                "s" + str(switch_dpid)
            )

            print(
                "Port:",
                in_port
            )

            print(
                "Location:",
                "s" + str(switch_dpid),
                "port",
                in_port
            )

        # --------------------------------------------------------
        # Only process known unicast destinations.
        # --------------------------------------------------------

        if dst_mac == "ff:ff:ff:ff:ff:ff":
            return

        dst_location = self.host_location.get(
            dst_mac
        )

        if dst_location is None:
            return

        # --------------------------------------------------------
        # Register active flow.
        #
        # IMPORTANT:
        # Do NOT install dynamic OpenFlow rules here.
        #
        # Normal forwarding is handled by simple_switch_13.
        # Custom priority-100 rules are installed ONLY after
        # a real link failure.
        # --------------------------------------------------------

        flow = (
            src_mac,
            dst_mac
        )

        self.active_flows.add(flow)
        
        print(
            "\n========== ACTIVE FLOW REGISTERED =========="
        )
        
        print(
            "Flow:",
            src_mac,
            "->",
            dst_mac
        )
        
        print(
            "Total active flows:",
            len(self.active_flows)
        )

    # ============================================================
    # REAL LINK FAILURE DETECTION
    # ============================================================

    @handler.set_ev_cls(
        ofp_event.EventOFPPortStatus,
        MAIN_DISPATCHER
    )
    def port_status_change(self, ev):

        if not self.topology_ready:
            return

        msg = ev.msg

        datapath = msg.datapath
        ofproto = datapath.ofproto

        port_no = msg.desc.port_no
        state = msg.desc.state
        reason = msg.reason

        # --------------------------------------------------------
        # We only care about LINK DOWN.
        # --------------------------------------------------------

        if not (state & ofproto.OFPPS_LINK_DOWN):
            return

        key = (
            datapath.id,
            port_no
        )

        # --------------------------------------------------------
        # Check whether this is a known switch-to-switch port.
        # --------------------------------------------------------

        if key not in self.port_to_link:
            return

        # --------------------------------------------------------
        # Get failed physical link.
        # --------------------------------------------------------

        src, dst = self.port_to_link[key]

        failed_edge = tuple(
            sorted((src, dst))
        )

        # --------------------------------------------------------
        # Ignore duplicate event from the other side.
        # --------------------------------------------------------

        if failed_edge not in self.edges:
            return

        print(
            "\n========== PORT STATUS =========="
        )

        print(
            "Switch:",
            "s" + str(datapath.id)
        )

        print(
            "Port:",
            port_no
        )

        print(
            "Reason:",
            reason
        )

        print(
            "State:",
            state
        )

        print(
            "\n!!! REAL LINK DOWN DETECTED !!!"
        )

        print(
            "Failed link:",
            src,
            "<->",
            dst
        )

        self.handle_link_failure(
            src,
            dst
        )

    # ============================================================
    # INITIAL TOPOLOGY DISCOVERY
    # ============================================================

    def initialize_topology(self):

        print(
            "\nWaiting for initial topology discovery..."
        )

        while True:

            switches = get_switch(
                self,
                None
            )

            links = get_link(
                self,
                None
            )

            discovered_edges = set()

            # ----------------------------------------------------
            # Ryu reports directional links.
            # Convert them to unique physical edges.
            # ----------------------------------------------------

            for link in links:

                src = "s" + str(
                    link.src.dpid
                )

                dst = "s" + str(
                    link.dst.dpid
                )

                edge = tuple(
                    sorted((src, dst))
                )

                discovered_edges.add(edge)

            print(
                "Discovered:",
                len(switches),
                "switches,",
                len(links),
                "Ryu links,",
                len(discovered_edges),
                "unique switch links"
            )

            # ----------------------------------------------------
            # Expected topology:
            # 5 switches
            # 7 physical switch links
            # ----------------------------------------------------

            if (
                len(switches) >= 5
                and
                len(discovered_edges) >= 7
            ):
                break

            hub.sleep(2)

        # ========================================================
        # BUILD TOPOLOGY MAPS
        # ========================================================

        self.edges = set()
        self.port_to_link = {}
        self.link_to_port = {}

        # --------------------------------------------------------
        # Build mappings from directional Ryu links.
        # --------------------------------------------------------

        for link in links:

            src_dpid = link.src.dpid
            dst_dpid = link.dst.dpid

            src = "s" + str(src_dpid)
            dst = "s" + str(dst_dpid)

            edge = tuple(
                sorted((src, dst))
            )

            self.edges.add(edge)

            # ----------------------------------------------------
            # Port -> physical link
            # ----------------------------------------------------

            self.port_to_link[
                (src_dpid, link.src.port_no)
            ] = edge

            self.port_to_link[
                (dst_dpid, link.dst.port_no)
            ] = edge

            # ----------------------------------------------------
            # Directional switch -> switch output port
            # ----------------------------------------------------

            self.link_to_port[
                (src, dst)
            ] = link.src.port_no

            self.link_to_port[
                (dst, src)
            ] = link.dst.port_no

        self.topology_ready = True

        # ========================================================
        # INITIAL NETWORKX GRAPH
        # ========================================================

        print(
            "\n========== INITIAL NETWORKX GRAPH =========="
        )

        self.calculate_path(
            self.edges,
            "s1",
            "s5"
        )

        # ========================================================
        # PRINT SWITCH LINK PORTS
        # ========================================================

        print(
            "\n========== SWITCH LINK PORTS =========="
        )

        for (
            src,
            dst
        ), port in sorted(
            self.link_to_port.items()
        ):

            print(
                src,
                "->",
                dst,
                "via port",
                port
            )

        print(
            "\nTopology monitoring is now ACTIVE."
        )

        print(
            "Waiting for real link failures..."
        )

    # ============================================================
    # HANDLE LINK FAILURE (المعدل - منغير مسح port_to_link)
    # ============================================================

    def handle_link_failure(
        self,
        src,
        dst
    ):

        failed_edge = tuple(
            sorted((src, dst))
        )

        if failed_edge not in self.edges:

            print(
                "Link already removed:",
                src,
                "<->",
                dst
            )

            return

        print(
            "\n========== LINK FAILURE =========="
        )

        print(
            "Removing:",
            src,
            "<->",
            dst
        )

        # --------------------------------------------------------
        # Remove failed edge from active graph.
        # --------------------------------------------------------

        self.edges.remove(
            failed_edge
        )

        # --------------------------------------------------------
        # Remove directional switch-to-switch output mappings.
        # --------------------------------------------------------

        self.link_to_port.pop(
            (src, dst),
            None
        )

        self.link_to_port.pop(
            (dst, src),
            None
        )

        # --------------------------------------------------------
        # IMPORTANT:
        #
        # We DO NOT remove port_to_link.
        #
        # This allows the opposite switch to report the same
        # physical failure and be ignored cleanly as a duplicate.
        # --------------------------------------------------------

        # ========================================================
        # CALCULATE NEW PATHS FOR ACTIVE FLOWS
        # ========================================================

        self.reroute_active_flows()

    # ============================================================
    # REROUTE ACTIVE FLOWS
    # ============================================================

    def reroute_active_flows(self):

        if not self.active_flows:

            print(
                "\nNo active flows to reroute."
            )

            return

        print(
            "\n========== REROUTING ACTIVE FLOWS =========="
        )

        print(
            "Active flows:",
            len(self.active_flows)
        )
        
        # Print active flows for debugging
        print("\nActive flows list:")
        for src_mac, dst_mac in self.active_flows:
            print("  🔹 Flow:", src_mac, "->", dst_mac)

        # --------------------------------------------------------
        # Make a copy because the set may change later.
        # --------------------------------------------------------

        flows = list(
            self.active_flows
        )

        for src_mac, dst_mac in flows:

            src_location = self.host_location.get(
                src_mac
            )

            dst_location = self.host_location.get(
                dst_mac
            )

            if (
                src_location is None
                or
                dst_location is None
            ):

                print(
                    "❌ Cannot reroute flow:",
                    src_mac,
                    "->",
                    dst_mac,
                    "- host location unknown"
                )

                continue

            src_dpid, src_port = src_location
            dst_dpid, dst_port = dst_location

            print(
                "\n🔄 Rerouting:",
                src_mac,
                "->",
                dst_mac,
                "from s" + str(src_dpid),
                "to s" + str(dst_dpid)
            )

            self.install_dynamic_path(
                src_mac,
                dst_mac,
                src_dpid,
                src_port,
                dst_dpid,
                dst_port
            )

    # ============================================================
    # BUILD NETWORKX GRAPH
    # ============================================================

    def build_graph(self, edges):

        switches = get_switch(
            self,
            None
        )

        G = nx.Graph()

        # --------------------------------------------------------
        # Add all discovered switches.
        # --------------------------------------------------------

        for switch in switches:

            switch_name = "s" + str(
                switch.dp.id
            )

            G.add_node(
                switch_name
            )

        # --------------------------------------------------------
        # Add currently active links.
        # --------------------------------------------------------

        for src, dst in edges:

            G.add_edge(
                src,
                dst,
                weight=1
            )

        return G

    # ============================================================
    # NETWORKX / DIJKSTRA
    # ============================================================

    def calculate_path(
        self,
        edges,
        source_switch,
        destination_switch
    ):

        G = self.build_graph(
            edges
        )

        print(
            "\n========== NETWORKX GRAPH =========="
        )

        print(
            "Nodes:",
            list(G.nodes())
        )

        print(
            "Edges:",
            list(G.edges())
        )

        # --------------------------------------------------------
        # Check source and destination.
        # --------------------------------------------------------

        if (
            source_switch not in G
            or
            destination_switch not in G
        ):

            print(
                "❌ Source or destination switch not discovered."
            )

            return None

        # --------------------------------------------------------
        # Calculate shortest path.
        # --------------------------------------------------------

        try:

            path = nx.shortest_path(
                G,
                source=source_switch,
                target=destination_switch,
                weight="weight"
            )

            print(
                "✅ Shortest path",
                source_switch,
                "->",
                destination_switch,
                ":",
                " -> ".join(path)
            )

            return path

        except nx.NetworkXNoPath:

            print(
                "❌ NO ALTERNATIVE PATH:",
                source_switch,
                "->",
                destination_switch
            )

            return None

    # ============================================================
    # INSTALL DYNAMIC PATH
    # ============================================================

    def install_dynamic_path(
        self,
        src_mac,
        dst_mac,
        src_dpid,
        src_port,
        dst_dpid,
        dst_port
    ):

        source_switch = "s" + str(
            src_dpid
        )

        destination_switch = "s" + str(
            dst_dpid
        )

        print(
            "\n========== INSTALLING DYNAMIC PATH =========="
        )
        
        print(
            "Source switch:", source_switch
        )
        
        print(
            "Destination switch:", destination_switch
        )
        
        print(
            "Active edges:", self.edges
        )

        # --------------------------------------------------------
        # Calculate path dynamically.
        # --------------------------------------------------------

        path = self.calculate_path(
            self.edges,
            source_switch,
            destination_switch
        )

        if path is None:

            print(
                "❌ No path available for:",
                src_mac,
                "->",
                dst_mac
            )

            return

        print(
            "✅ Path found:",
            " -> ".join(path)
        )

        print(
            "\n========== DYNAMIC PATH =========="
        )

        print(
            "Source MAC:",
            src_mac
        )

        print(
            "Destination MAC:",
            dst_mac
        )

        print(
            "Path:",
            " -> ".join(path)
        )

        # --------------------------------------------------------
        # Remove old custom rules for this flow.
        # --------------------------------------------------------

        self.clear_path_flows(
            src_mac,
            dst_mac
        )

        # --------------------------------------------------------
        # Install forward direction.
        # --------------------------------------------------------

        self.install_one_direction(
            src_mac,
            dst_mac,
            src_dpid,
            src_port,
            dst_dpid,
            dst_port,
            path
        )

        # --------------------------------------------------------
        # Install reverse direction.
        # --------------------------------------------------------

        reverse_path = list(
            reversed(path)
        )

        self.install_one_direction(
            dst_mac,
            src_mac,
            dst_dpid,
            dst_port,
            src_dpid,
            src_port,
            reverse_path
        )

    # ============================================================
    # INSTALL ONE DIRECTION (المعدل - التصحيح النهائي)
    # ============================================================

    def install_one_direction(
        self,
        src_mac,
        dst_mac,
        src_dpid,
        src_host_port,
        dst_dpid,
        dst_host_port,
        path
    ):

        print(
            "\n========== INSTALL ONE DIRECTION =========="
        )
        
        print(
            "Path:", " -> ".join(path)
        )
        
        print(
            "Source MAC:", src_mac
        )
        
        print(
            "Destination MAC:", dst_mac
        )
        
        print(
            "Source host port:", src_host_port
        )
        
        print(
            "Destination host port:", dst_host_port
        )

        # --------------------------------------------------------
        # Same-switch communication.
        # --------------------------------------------------------

        if len(path) == 1:

            switch_name = path[0]

            dpid = int(
                switch_name[1:]
            )

            self.install_flow(
                dpid,
                src_host_port,
                dst_host_port,
                src_mac,
                dst_mac
            )

            return

        # ========================================================
        # MULTI-SWITCH PATH
        # ========================================================

        for index, switch_name in enumerate(path):

            dpid = int(
                switch_name[1:]
            )

            print(
                "\n--- Processing switch:", switch_name,
                "(index:", index, "of", len(path) - 1, ")"
            )

            # ----------------------------------------------------
            # FIRST SWITCH
            # Host -> next switch
            # ----------------------------------------------------

            if index == 0:

                next_switch = path[
                    index + 1
                ]

                # in_port = port where host is connected
                in_port = src_host_port
                
                # out_port = port to next switch
                out_port = self.link_to_port.get(
                    (
                        switch_name,
                        next_switch
                    )
                )

                print(
                    "  First switch:",
                    "in_port = host port (",
                    in_port,
                    "), out_port ->",
                    next_switch,
                    "=",
                    out_port
                )

            # ----------------------------------------------------
            # LAST SWITCH
            # Previous switch -> host
            # ----------------------------------------------------

            elif index == len(path) - 1:

                previous_switch = path[
                    index - 1
                ]

                # FIX: in_port = port from previous switch 
                # (current switch -> previous switch)
                in_port = self.link_to_port.get(
                    (
                        switch_name,      # current switch
                        previous_switch   # previous switch
                    )
                )

                # out_port = port where host is connected
                out_port = dst_host_port

                print(
                    "  Last switch:",
                    "in_port from",
                    previous_switch,
                    "=",
                    in_port,
                    ", out_port = host port (",
                    out_port,
                    ")"
                )

            # ----------------------------------------------------
            # INTERMEDIATE SWITCH
            # Previous switch -> next switch
            # ----------------------------------------------------

            else:

                previous_switch = path[
                    index - 1
                ]

                next_switch = path[
                    index + 1
                ]

                # FIX: in_port = port from previous switch
                # (current switch -> previous switch)
                in_port = self.link_to_port.get(
                    (
                        switch_name,      # current switch
                        previous_switch   # previous switch
                    )
                )

                # out_port = port to next switch
                out_port = self.link_to_port.get(
                    (
                        switch_name,
                        next_switch
                    )
                )

                print(
                    "  Intermediate switch:",
                    "in_port from",
                    previous_switch,
                    "=",
                    in_port,
                    ", out_port ->",
                    next_switch,
                    "=",
                    out_port
                )

            # ----------------------------------------------------
            # Verify port mapping.
            # ----------------------------------------------------

            if (
                in_port is None
                or
                out_port is None
            ):

                print(
                    "\n❌ Port mapping missing!"
                )

                print(
                    "Switch:",
                    switch_name
                )

                print(
                    "Input port:",
                    in_port
                )

                print(
                    "Output port:",
                    out_port
                )

                print(
                    "Path:", path
                )
                
                print(
                    "link_to_port mappings:",
                    self.link_to_port
                )

                return

            # ----------------------------------------------------
            # Install OpenFlow rule.
            # ----------------------------------------------------

            self.install_flow(
                dpid,
                in_port,
                out_port,
                src_mac,
                dst_mac
            )

    # ============================================================
    # INSTALL OPENFLOW FLOW
    # ============================================================

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

            print(
                "❌ Datapath not found:",
                "s" + str(dpid)
            )

            return

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # --------------------------------------------------------
        # Match:
        #
        # Input port
        # Source MAC
        # Destination MAC
        # --------------------------------------------------------

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

        # --------------------------------------------------------
        # Priority 100:
        #
        # simple_switch_13 normally installs priority 1 rules.
        # Therefore our dynamic path rules take precedence.
        # --------------------------------------------------------

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=instructions
        )

        datapath.send_msg(
            flow_mod
        )

        print(
            "✅ Installed flow:",
            "s" + str(dpid),
            "| in:",
            in_port,
            "| out:",
            out_port,
            "|",
            src_mac,
            "->",
            dst_mac
        )

    # ============================================================
    # CLEAR OLD CUSTOM FLOW RULES
    # ============================================================

    def clear_path_flows(
        self,
        src_mac,
        dst_mac
    ):

        print(
            "\n========== CLEARING OLD FLOWS =========="
        )
        
        print(
            "Clearing flows for:",
            src_mac,
            "->",
            dst_mac
        )

        for datapath in self.datapaths.values():

            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto

            match = parser.OFPMatch(
                eth_src=src_mac,
                eth_dst=dst_mac
            )

            flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=100,
                match=match
            )

            datapath.send_msg(
                flow_mod
            )
            
        print(
            "✅ Old flows cleared."
        )

    # ============================================================
    # DELETE SPECIFIC FLOW RULE (اختياري)
    # ============================================================
    
    def delete_flow(
        self,
        dpid,
        in_port,
        src_mac,
        dst_mac
    ):
        """
        حذف قاعدة محددة من سويتش معين
        """
        datapath = self.datapaths.get(dpid)
        
        if datapath is None:
            print("❌ Datapath not found:", "s" + str(dpid))
            return
        
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        match = parser.OFPMatch(
            in_port=in_port,
            eth_src=src_mac,
            eth_dst=dst_mac
        )
        
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=100,
            match=match
        )
        
        datapath.send_msg(flow_mod)
        
        print(
            "✅ Deleted flow:",
            "s" + str(dpid),
            "|",
            src_mac,
            "->",
            dst_mac
        )

    # ============================================================
    # CLEAR ALL CUSTOM FLOWS (اختياري)
    # ============================================================
    
    def clear_all_flows(self):
        """
        حذف كل القواعد المخصصة (priority 100) من كل السويتشات
        """
        print("\n========== CLEARING ALL FLOWS ==========")
        
        for datapath in self.datapaths.values():
            
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            
            # حذف كل القواعد ذات Priority 100
            match = parser.OFPMatch()
            
            flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=100,
                match=match
            )
            
            datapath.send_msg(flow_mod)
            
            print(
                "✅ Cleared flows on:",
                "s" + str(datapath.id)
            )
        
        # مسح التدفقات المسجلة
        self.active_flows.clear()
        print("✅ All active flows cleared.")

    # ============================================================
    # GET HOST LOCATION (اختياري)
    # ============================================================
    
    def get_host_location(self, mac):
        """
        استرجاع موقع host معين
        """
        location = self.host_location.get(mac)
        if location:
            dpid, port = location
            return {
                'switch': 's' + str(dpid),
                'port': port
            }
        return None

    # ============================================================
    # GET PATH BETWEEN HOSTS (اختياري)
    # ============================================================
    
    def get_path_between_hosts(self, src_mac, dst_mac):
        """
        حساب المسار بين مضيفين باستخدام الطوبولوجيا الحالية
        """
        src_loc = self.host_location.get(src_mac)
        dst_loc = self.host_location.get(dst_mac)
        
        if not src_loc or not dst_loc:
            print("❌ Host location not found.")
            return None
        
        src_dpid, _ = src_loc
        dst_dpid, _ = dst_loc
        
        source_switch = "s" + str(src_dpid)
        destination_switch = "s" + str(dst_dpid)
        
        return self.calculate_path(
            self.edges,
            source_switch,
            destination_switch
        )

    # ============================================================
    # CLEANUP ON EXIT (اختياري)
    # ============================================================
    
    def close(self):
        """
        تنظيف عند إغلاق التطبيق
        """
        print("\n========== CLEANING UP ==========")
        self.clear_all_flows()
        print("✅ Application closed.")
