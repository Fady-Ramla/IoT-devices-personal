from mininet.topo import Topo
from mininet.node import OVSSwitch


class STPSwitch(OVSSwitch):

    def start(self, controllers):
        OVSSwitch.start(self, controllers)
        self.cmd('ovs-vsctl set Bridge %s stp_enable=true' % self)


class PartialMeshTopo(Topo):

    def build(self):

        # =========================
        # Switches
        # =========================

        s1 = self.addSwitch('s1', cls=STPSwitch)
        s2 = self.addSwitch('s2', cls=STPSwitch)
        s3 = self.addSwitch('s3', cls=STPSwitch)
        s4 = self.addSwitch('s4', cls=STPSwitch)
        s5 = self.addSwitch('s5', cls=STPSwitch)

        # =========================
        # Hosts
        # =========================

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')
        h7 = self.addHost('h7')
        h8 = self.addHost('h8')
        h9 = self.addHost('h9')
        h10 = self.addHost('h10')

        # =========================
        # Host Connections
        # =========================

        self.addLink(h1, s1)
        self.addLink(h2, s1)

        self.addLink(h3, s2)
        self.addLink(h4, s2)

        self.addLink(h5, s3)
        self.addLink(h6, s3)

        self.addLink(h7, s4)
        self.addLink(h8, s4)

        self.addLink(h9, s5)
        self.addLink(h10, s5)

        # =========================
        # Main Chain
        # =========================

        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)
        self.addLink(s4, s5)

        # =========================
        # Redundant Links
        # =========================

        self.addLink(s1, s3)
        self.addLink(s2, s4)
        self.addLink(s3, s5)


topos = {
    'partialmesh': PartialMeshTopo
}
