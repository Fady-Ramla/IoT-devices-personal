"""Loopback-free tests for the Ryu VIP takeover controller contract.

Ryu itself is not required: the production method AST is bound to a minimal
OpenFlow parser/datapath double so match tuples, action order, and rollback can
be tested without a live controller or Mininet network.
"""
import ast
import importlib.util
import pathlib
import unittest
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "topology_monitor.py"
TEXT = SOURCE.read_text(encoding="utf-8")
TREE = ast.parse(TEXT)


def class_method(name, extra_globals=None):
    topology = next(node for node in TREE.body
                    if isinstance(node, ast.ClassDef)
                    and node.name == "TopologyMonitor")
    method = next(node for node in reversed(topology.body)
                  if isinstance(node, ast.FunctionDef) and node.name == name)
    module = ast.Module(body=[method], type_ignores=[])
    namespace = {"OFPVID_PRESENT": 0x1000, "OFPVID_NONE": 0,
                 "EXPECTED_SWITCHES": 6}
    namespace.update(extra_globals or {})
    exec(compile(ast.fix_missing_locations(module), str(SOURCE), "exec"), namespace)
    return namespace[name]


def class_value(name):
    topology = next(node for node in TREE.body
                    if isinstance(node, ast.ClassDef)
                    and node.name == "TopologyMonitor")
    assignment = next(node for node in topology.body
                      if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == name
                              for target in node.targets))
    return ast.literal_eval(assignment.value)


class FakeParser:
    def OFPMatch(self, **kwargs):
        return kwargs

    def OFPActionSetField(self, **kwargs):
        return ("set_field", kwargs)

    def OFPActionOutput(self, port, max_len=None):
        return ("output", port, max_len)

    def OFPActionPushVlan(self, ethertype):
        return ("push_vlan", ethertype)

    def OFPActionPopVlan(self):
        return ("pop_vlan",)

    def OFPInstructionActions(self, instruction, actions):
        return ("instructions", instruction, actions)

    def OFPFlowMod(self, **kwargs):
        return SimpleNamespace(**kwargs)

    def OFPPacketOut(self, **kwargs):
        return SimpleNamespace(**kwargs)


class FakeDatapath:
    def __init__(self, dpid):
        self.id = dpid
        self.ofproto_parser = FakeParser()
        self.ofproto = SimpleNamespace(
            OFPFC_DELETE_STRICT=4, OFPP_ANY=0xFFFFFFFC,
            OFPG_ANY=0xFFFFFFFC, OFPP_CONTROLLER=0xFFFFFFFD,
            OFPCML_NO_BUFFER=0xFFFF, OFPIT_APPLY_ACTIONS=4,
            OFP_NO_BUFFER=0xFFFFFFFF)
        self.sent = []

    def send_msg(self, message):
        self.sent.append(message)
        return True


class FakeIPv4Protocol:
    pass


class FakeTCPProtocol:
    pass


class FakeUDPProtocol:
    pass


class FakeEthernetProtocol:
    pass


class FlowHarness:
    VIP_TAKEOVER_PRIORITY = 49990
    VIP_FLOW_IDLE_TIMEOUT = 60
    VIP_FLOW_HARD_TIMEOUT = 300
    VIP_SERVICES = class_value("VIP_SERVICES")
    VIP_DISPATCH_SERVICES = class_value("VIP_DISPATCH_SERVICES")
    _vip_direction_flows = class_method("_vip_direction_flows")
    _vip_flow_output_actions = class_method("_vip_flow_output_actions")
    _handle_vip_packet = class_method("_handle_vip_packet", {
        "ipv4": SimpleNamespace(ipv4=FakeIPv4Protocol),
        "tcp": SimpleNamespace(tcp=FakeTCPProtocol),
        "udp": SimpleNamespace(udp=FakeUDPProtocol),
        "ethernet": SimpleNamespace(ethernet=FakeEthernetProtocol),
    })

    def __init__(self):
        self.datapaths = {1: FakeDatapath(1), 2: FakeDatapath(2)}
        self.link_to_port = {(1, 2): (12, 21), (2, 1): (21, 12)}
        self.vlan_port_map = {
            (1, 10): {"kind": "trunk", "allowed_vlans": frozenset({20, 30})},
            (1, 11): {"kind": "access", "vlan_id": 20},
            (1, 12): {"kind": "trunk", "allowed_vlans": frozenset({20, 30})},
            (2, 21): {"kind": "trunk", "allowed_vlans": frozenset({20, 30})},
            (2, 22): {"kind": "access", "vlan_id": 20},
            (2, 23): {"kind": "access", "vlan_id": 30},
            (2, 24): {"kind": "access", "role": "gateway", "vlan_id": 30},
        }
        self.vip_takeover_active = True
        self.vip_takeover_flows = {}
        self.host_location = {
            "client-mac": (1, 11),
            "backend-mac": (2, 22),
            "gateway-mac": (1, 10),
            "gateway-vlan30-mac": (2, 24),
            "dns-backend-mac": (2, 23),
        }
        self.mac_vlan = {
            "client-mac": 20,
            "backend-mac": 20,
            "gateway-mac": 20,
            "gateway-vlan30-mac": 30,
            "dns-backend-mac": 30,
        }
        self.logger = SimpleNamespace(
            info=lambda *args, **kwargs: None,
            warning=lambda *args, **kwargs: None,
            error=lambda *args, **kwargs: None,
            exception=lambda *args, **kwargs: None,
        )

    def _port_allows_vlan(self, dpid, port, vlan):
        entry = self.vlan_port_map.get((int(dpid), int(port)))
        if not entry:
            return False
        if entry["kind"] == "trunk":
            return vlan in entry["allowed_vlans"]
        return entry.get("vlan_id") == vlan

    def _shortest_path(self, src, dst):
        return [src] if src == dst else [src, dst]

    def _vip_backend(self, service):
        if int(service[3]) == 53:
            return "10.10.30.2", "dns-backend-mac", 53
        return "10.10.20.2", "backend-mac", 5000

    def _send_security_flow_batch(self, datapath, messages):
        for message in messages:
            datapath.send_msg(message)
        return {"success": True, "status": "confirmed"}


class TakeoverHarness:
    VIP_TAKEOVER_PRIORITY = 49990
    VIP_SERVICES = class_value("VIP_SERVICES")
    VIP_DISPATCH_SERVICES = class_value("VIP_DISPATCH_SERVICES")
    _vip_dispatch_mod = class_method("_vip_dispatch_mod")
    activate_vip_takeover = class_method("activate_vip_takeover")
    deactivate_vip_takeover = class_method("deactivate_vip_takeover")

    def __init__(self, fail_dpid=None, fail_cleanup_dpid=None):
        self.datapaths = {i: FakeDatapath(i) for i in range(1, 7)}
        self.vlan_map_ready = True
        self.full_topology_discovered = True
        self.vip_takeover_active = False
        self.vip_takeover_dispatch = {}
        self.vip_takeover_flows = {}
        self.blocked_devices = {"00:00:00:00:00:27": {
            "ip": "10.10.20.100", "enforcement_status": "executed",
            "confirmed_switches": [1, 2, 3, 4, 5, 6],
            "macs": ["00:00:00:00:00:27"],
        }}
        self.fail_dpid = fail_dpid
        self.fail_cleanup_dpid = fail_cleanup_dpid
        self.batch_log = []

    def _send_security_flow_batch(self, dp, messages):
        self.batch_log.append((dp.id, messages))
        has_delete = any(getattr(message, "command", None) == 4
                         for message in messages)
        return {"success": not (
            (dp.id == self.fail_dpid and not has_delete)
            or (dp.id == self.fail_cleanup_dpid and has_delete))}


class BackendHarness:
    VIP_SERVICES = class_value("VIP_SERVICES")
    _vip_backend = class_method("_vip_backend")

    def __init__(self):
        self.ip_to_mac = {
            "10.10.20.2": "m2", "10.10.20.8": "m8",
            "10.10.30.2": "m1", "10.10.30.17": "m17",
            "10.10.20.4": "m4", "10.10.20.20": "m20",
        }
        self.host_location = {
            "m2": (1, 1), "m8": (2, 2),
            "m1": (1, 3), "m17": (2, 4),
            "m4": (1, 5), "m20": (2, 6),
        }
        self.mac_vlan = {
            "m2": 20, "m8": 20, "m1": 30, "m17": 30,
            "m4": 20, "m20": 20,
        }
        self.blocked_devices = {"m2": {"macs": ["m2"]}}

    def is_device_blocked(self, mac):
        return any(mac in rec.get("macs", [key])
                   for key, rec in self.blocked_devices.items())


class TopologyVipTakeoverTests(unittest.TestCase):
    def test_inventory_and_frontend_metadata(self):
        spec = importlib.util.spec_from_file_location(
            "vlan_config_38host_test", ROOT / "mininet" / "vlan_config_38host.py")
        config = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(config)
        self.assertEqual(len(config.HOSTS), 38)
        self.assertEqual(set(config.SERVICE_PAIRS), {"dns", "http_api", "https", "ssh"})
        self.assertEqual(config.LOAD_BALANCER["frontends"], (5000, 443, 2222))
        self.assertEqual(config.SERVICE_PAIRS["dns"]["port"], 53)
        self.assertEqual(config.SERVICE_PAIRS["dns"]["vlan"], 30)

    def test_dispatch_match_covers_tcp_and_both_dns_transports(self):
        services = class_value("VIP_SERVICES")
        self.assertEqual(set(services), {
            ("10.10.20.100", 20, 6, 5000),
            ("10.10.20.100", 20, 6, 443),
            ("10.10.20.100", 20, 6, 2222),
            ("10.10.30.100", 30, 6, 53),
            ("10.10.30.100", 30, 17, 53),
        })

        dispatch = class_value("VIP_DISPATCH_SERVICES")
        self.assertEqual(set(dispatch), {
            ("10.10.20.100", 20, 6, 5000),
            ("10.10.20.100", 20, 6, 443),
            ("10.10.20.100", 20, 6, 2222),
            ("10.10.20.100", 20, 6, 53),
            ("10.10.20.100", 20, 17, 53),
        })

        mod = TakeoverHarness()._vip_dispatch_mod(
            FakeDatapath(1), ("10.10.20.100", 20, 17, 53)
        )
        self.assertEqual(mod.match["ipv4_dst"], "10.10.20.100")
        self.assertEqual(mod.match["vlan_vid"], 0x1000 | 20)
        self.assertEqual(mod.match["ip_proto"], 17)
        self.assertEqual(mod.match["udp_dst"], 53)

    def test_activation_requires_confirmed_h38_block_and_rolls_back(self):
        no_block = TakeoverHarness()
        no_block.blocked_devices.clear()
        self.assertEqual(no_block.activate_vip_takeover()["status"],
                         "h38_block_not_fully_confirmed")
        partial = TakeoverHarness(fail_dpid=3)
        result = partial.activate_vip_takeover()
        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "dispatch_install_failed")
        self.assertFalse(partial.vip_takeover_active)
        self.assertTrue(any(dpid == 1 and any(
            getattr(msg, "command", None) == 4 for msg in mods)
            for dpid, mods in partial.batch_log))
        cleanup_failure = TakeoverHarness(fail_dpid=3, fail_cleanup_dpid=2)
        failed = cleanup_failure.activate_vip_takeover()
        self.assertEqual(failed["status"], "dispatch_rollback_failed")
        self.assertIn(2, failed["cleanup_failed_switches"])
        self.assertFalse(cleanup_failure.vip_takeover_active)

    def test_activation_and_deactivation_cleanup(self):
        harness = TakeoverHarness()
        self.assertTrue(harness.activate_vip_takeover()["success"])
        self.assertTrue(harness.vip_takeover_active)
        result = harness.deactivate_vip_takeover()
        self.assertTrue(result["success"])
        self.assertFalse(harness.vip_takeover_active)
        self.assertEqual(harness.vip_takeover_dispatch, {})

    def test_backend_selection_skips_blocked_primary(self):
        service = ("10.10.20.100", 20, 6, 5000)
        backend = BackendHarness()._vip_backend(service)
        self.assertEqual(backend, ("10.10.20.8", "m8", 5000))

    def test_ssh_frontend_maps_to_backend_port_22(self):
        service = ("10.10.20.100", 20, 6, 2222)
        backend = BackendHarness()._vip_backend(service)
        self.assertEqual(backend, ("10.10.20.4", "m4", 22))

    def test_dns_backend_selection_uses_vlan30_after_gateway_dnat(self):
        harness = BackendHarness()
        service = ("10.10.20.100", 20, 17, 53)

        self.assertEqual(
            harness._vip_backend(service),
            ("10.10.30.2", "m1", 53),
        )

        harness.blocked_devices["m1"] = {"macs": ["m1"]}

        self.assertEqual(
            harness._vip_backend(service),
            ("10.10.30.17", "m17", 53),
        )

    def test_forward_and_reverse_flow_tuples_match_nat_rewrites(self):
        harness = FlowHarness()
        forward, _ = harness._vip_direction_flows(
            [1, 2], 11, 22, 20, "client-mac", "vip-mac", "backend-mac",
            "10.10.10.5", "10.10.20.100", "10.10.20.2", 6,
            41000, 5000, rewrite_dst="10.10.20.2",
            rewrite_eth_dst="backend-mac")
        self.assertEqual(forward[0][1].match["ipv4_dst"], "10.10.20.100")
        self.assertEqual(forward[1][1].match["ipv4_dst"], "10.10.20.2")
        self.assertEqual(forward[0][1].priority, 49991)
        reverse, _ = harness._vip_direction_flows(
            [2, 1], 22, 11, 20, "backend-mac", "client-mac", "client-mac",
            "10.10.20.2", "10.10.10.5", "10.10.10.5", 6,
            5000, 41000, rewrite_src="10.10.20.100",
            ip_src_rest="10.10.20.100")
        self.assertEqual(reverse[0][1].match["ipv4_src"], "10.10.20.2")
        self.assertEqual(reverse[1][1].match["ipv4_src"], "10.10.20.100")
        self.assertEqual(reverse[0][1].match["ipv4_dst"], "10.10.10.5")
        self.assertEqual(reverse[1][1].match["ipv4_dst"], "10.10.10.5")
        self.assertTrue(any(action == ("set_field", {"ipv4_src": "10.10.20.100"})
                            for action in reverse[0][1].instructions[0][2]))

    def test_packetin_installs_reply_flows_and_rewrites_first_packet(self):
        harness = FlowHarness()
        dp = harness.datapaths[1]
        msg = SimpleNamespace(datapath=dp, match={"in_port": 11}, data=b"original-packet")

        class FakePacket:
            def get_protocol(self, protocol_type):
                return {
                    FakeIPv4Protocol: SimpleNamespace(src="10.10.10.5", dst="10.10.20.100"),
                    FakeTCPProtocol: SimpleNamespace(src_port=41000, dst_port=5000),
                    FakeUDPProtocol: None,
                    FakeEthernetProtocol: SimpleNamespace(src="client-mac", dst="vip-mac"),
                }.get(protocol_type)

        consumed = harness._handle_vip_packet(dp, msg, FakePacket(), 20)
        self.assertTrue(consumed)
        packetouts = [message for message in dp.sent
                      if hasattr(message, "actions") and hasattr(message, "data")]
        self.assertEqual(len(packetouts), 1)
        actions = packetouts[0].actions
        self.assertIn(("set_field", {"ipv4_dst": "10.10.20.2"}), actions)
        self.assertIn(("set_field", {"eth_dst": "backend-mac"}), actions)
        self.assertEqual(packetouts[0].data, b"original-packet")
        self.assertEqual(len(harness.vip_takeover_flows), 4)

    def test_dns_packetin_translates_vlan20_to_vlan30_and_back(self):
        harness = FlowHarness()
        dp = harness.datapaths[1]
        msg = SimpleNamespace(
            datapath=dp,
            match={"in_port": 10},
            data=b"dns-query",
        )

        class FakeDNSPacket:
            def get_protocol(self, protocol_type):
                return {
                    FakeIPv4Protocol: SimpleNamespace(
                        src="10.10.20.1",
                        dst="10.10.20.100",
                    ),
                    FakeTCPProtocol: None,
                    FakeUDPProtocol: SimpleNamespace(
                        src_port=53000,
                        dst_port=53,
                    ),
                    FakeEthernetProtocol: SimpleNamespace(
                        src="gateway-mac",
                        dst="vip-mac",
                    ),
                }.get(protocol_type)

        consumed = harness._handle_vip_packet(
            dp, msg, FakeDNSPacket(), 20
        )
        self.assertTrue(consumed)

        packetouts = [
            item for item in dp.sent
            if hasattr(item, "actions") and hasattr(item, "data")
        ]
        self.assertEqual(len(packetouts), 1)

        packet_actions = packetouts[0].actions
        self.assertIn(
            ("set_field", {"ipv4_dst": "10.10.30.2"}),
            packet_actions,
        )
        self.assertIn(
            ("set_field", {"vlan_vid": 0x1000 | 30}),
            packet_actions,
        )
        self.assertEqual(packetouts[0].data, b"dns-query")

        dp2 = harness.datapaths[2]
        dp1_flows = [
            item for item in dp.sent
            if hasattr(item, "priority") and hasattr(item, "match")
        ]
        dp2_flows = [
            item for item in dp2.sent
            if hasattr(item, "priority") and hasattr(item, "match")
        ]

        request_first = next(
            item for item in dp1_flows
            if item.match.get("in_port") == 10
            and item.match.get("ipv4_dst") == "10.10.20.100"
        )
        self.assertEqual(request_first.match["vlan_vid"], 0x1000 | 20)

        request_backend = next(
            item for item in dp2_flows
            if item.match.get("ipv4_src") == "10.10.20.1"
            and item.match.get("ipv4_dst") == "10.10.30.2"
        )
        self.assertEqual(request_backend.match["vlan_vid"], 0x1000 | 30)
        self.assertIn(
            ("pop_vlan",),
            request_backend.instructions[0][2],
        )

        response_first = next(
            item for item in dp2_flows
            if item.match.get("ipv4_src") == "10.10.30.2"
            and item.match.get("ipv4_dst") == "10.10.20.1"
        )
        response_actions = response_first.instructions[0][2]
        self.assertIn(
            ("set_field", {"ipv4_src": "10.10.20.100"}),
            response_actions,
        )
        self.assertIn(("push_vlan", 0x8100), response_actions)
        self.assertIn(
            ("set_field", {"vlan_vid": 0x1000 | 20}),
            response_actions,
        )

        response_gateway = next(
            item for item in dp1_flows
            if item.match.get("ipv4_src") == "10.10.20.100"
            and item.match.get("ipv4_dst") == "10.10.20.1"
        )
        self.assertEqual(response_gateway.match["vlan_vid"], 0x1000 | 20)
        self.assertEqual(len(harness.vip_takeover_flows), 4)

    def test_single_interface_block_and_packetout_rewrite_contract(self):
        block = next(node for node in TREE.body if isinstance(node, ast.ClassDef)
                     and node.name == "TopologyMonitor")
        block_method = next(n for n in block.body if isinstance(n, ast.FunctionDef)
                            and n.name == "block_device")
        block_source = ast.get_source_segment(TEXT, block_method)
        self.assertIn("block_macs = [mac]", block_source)
        self.assertIn("gateway-owned", block_source)
        self.assertNotIn("h38-eth1", block_source)
        handler = next(n for n in block.body if isinstance(n, ast.FunctionDef)
                       and n.name == "_handle_vip_packet")
        handler_source = ast.get_source_segment(TEXT, handler)
        self.assertIn("OFPPacketOut", handler_source)
        self.assertIn("forward[0] + reverse[0]", handler_source)
        self.assertNotIn("_send_packet_out_bytes", handler_source)
        flow_builder = next(n for n in block.body if isinstance(n, ast.FunctionDef)
                            and n.name == "_vip_direction_flows")
        self.assertIn("OFPActionSetField", ast.get_source_segment(TEXT, flow_builder))

    def test_packetin_dispatch_precedes_normal_unicast(self):
        handler = next(n for n in TREE.body if isinstance(n, ast.ClassDef)
                       and n.name == "TopologyMonitor")
        packet_in = next(n for n in handler.body if isinstance(n, ast.FunctionDef)
                         and n.name == "packet_in_handler")
        calls = [n for n in ast.walk(packet_in) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute)
                 and n.func.attr == "_handle_vip_packet"]
        self.assertEqual(len(calls), 1)
        text = ast.get_source_segment(TEXT, packet_in)
        self.assertLess(text.index("_handle_vip_packet"),
                        text.index("# Broadcast / multicast -> CLFF"))

    def test_unblock_targets_primary_service_vip_and_all_record_macs(self):
        method = next(n for cls in TREE.body if isinstance(cls, ast.ClassDef)
                      and cls.name == "TopologyMonitor" for n in cls.body
                      if isinstance(n, ast.FunctionDef) and n.name == "unblock_device")
        source = ast.get_source_segment(TEXT, method)
        self.assertIn('target_ip == "10.10.20.100"', source)
        self.assertIn('record or {}).get("macs", [mac])', source)
        self.assertNotIn('"10.10.30.100"', source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
