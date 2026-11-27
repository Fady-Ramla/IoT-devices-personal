"""Focused integration tests for Security -> LB -> VIP and switch reconnect."""
import ast
import ipaddress
import time
import unittest

from pathlib import Path
from types import MethodType, SimpleNamespace
from unittest.mock import Mock


ROOT = Path(__file__).resolve().parents[1]
TOPOLOGY_PATH = ROOT / "topology_monitor.py"
TRAFFIC_PATH = ROOT / "traffic_monitor_merged.py"

MAC = "00:00:00:00:00:27"
LB_IP = "10.10.20.100"


def find_method(path, name):
    tree = ast.parse(path.read_text(encoding="utf-8"))

    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue

        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if item.name == name:
                    module = ast.Module(body=[item], type_ignores=[])
                    namespace = {
                        "ipaddress": ipaddress,
                        "time": time,
                        "ACTION_BLOCK_DEVICE": "BLOCK_DEVICE",
                        "ACTION_UNBLOCK_DEVICE": "UNBLOCK_DEVICE",
                        "LOAD_BALANCER": {"host": "h38"},
                        "host_ip": lambda host: LB_IP if host == "h38" else None,
                        "EXPECTED_SWITCHES": 6,
                        "DEVICE_BLOCK_PRIORITY": 50000,
                    }

                    for assignment in tree.body:
                        if isinstance(assignment, ast.Assign):
                            for target in assignment.targets:
                                if (
                                    isinstance(target, ast.Name)
                                    and target.id.startswith("ACTION_")
                                ):
                                    try:
                                        namespace[target.id] = ast.literal_eval(
                                            assignment.value
                                        )
                                    except (ValueError, TypeError):
                                        pass

                    exec(
                        compile(
                            ast.fix_missing_locations(module),
                            str(path),
                            "exec",
                        ),
                        namespace,
                    )
                    return namespace[name]

    raise RuntimeError("%s not found in %s" % (name, path.name))


def module_constant(path, name, fallback):
    tree = ast.parse(path.read_text(encoding="utf-8"))

    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    try:
                        return ast.literal_eval(node.value)
                    except Exception:
                        pass

    return fallback


class FakeSecurityTopology:
    def __init__(self):
        self.block_result = {
            "success": True,
            "status": "executed",
            "action": "BLOCK_LOAD_BALANCER",
        }
        self.unblock_result = {
            "success": True,
            "status": "executed",
            "action": "UNBLOCK_LOAD_BALANCER",
        }
        self.block_load_balancer = Mock(
            side_effect=lambda **kwargs: dict(self.block_result)
        )
        self.unblock_load_balancer = Mock(
            side_effect=lambda **kwargs: dict(self.unblock_result)
        )

    def classify_security_target(self, ip=None, mac=None):
        if ip == LB_IP:
            return {
                "target_type": "load_balancer",
                "ip": LB_IP,
                "service": None,
            }
        return {
            "target_type": "device",
            "ip": ip,
            "service": None,
        }


class SecurityActionHarness:
    def __init__(self):
        self.topology = FakeSecurityTopology()
        self.logger = SimpleNamespace(
            warning=lambda *args, **kwargs: None
        )
        self.recorded_actions = []

    def _get_topology_monitor(self):
        return self.topology

    def _validate_network_decision(
        self, host_ip=None, mac=None, **kwargs
    ):
        return {
            "valid": True,
            "host_ip": host_ip,
            "mac": mac,
        }

    def _record_action(self, *args, **kwargs):
        self.recorded_actions.append((args, kwargs))


class Parser:
    def OFPMatch(self, **kwargs):
        return kwargs

    def OFPInstructionActions(self, instruction, actions):
        return ("instructions", instruction, actions)

    def OFPFlowMod(self, **kwargs):
        return SimpleNamespace(**kwargs)


class FakeSwitch:
    def __init__(self, dpid):
        self.id = dpid
        self.ofproto_parser = Parser()
        self.ofproto = SimpleNamespace(OFPIT_APPLY_ACTIONS=4)


class ReconnectHarness:
    _restore_h38_vip_on_switch = find_method(
        TOPOLOGY_PATH, "_restore_h38_vip_on_switch"
    )

    def __init__(self, confirm_mac=True):
        self.datapaths = {
            dpid: FakeSwitch(dpid) for dpid in range(1, 7)
        }
        self.blocked_devices = {
            MAC: {
                "ip": LB_IP,
                "macs": [MAC],
                "enforcement_status": "partial_failure",
                "confirmed_switches": [1, 2, 3, 4, 5],
            }
        }

        self.vip_takeover_active = True
        self.vip_takeover_dispatch = {
            dpid: [] for dpid in range(1, 6)
        }
        self.confirm_mac = confirm_mac
        self.events = []
        self.logger = SimpleNamespace(
            error=lambda *args, **kwargs: None
        )

    def _send_security_flow_batch(self, datapath, messages):
        self.events.append(("mac_block_confirmation", datapath.id))
        return {
            "success": self.confirm_mac,
            "status": "confirmed" if self.confirm_mac else "openflow_error",
        }

    def _install_vip_dispatch_on_switch(self, datapath):
        self.events.append(("vip_dispatch", datapath.id))
        self.vip_takeover_dispatch[datapath.id] = [("restored",)]
        return {"success": True, "status": "confirmed"}


class VipSecurityIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.execute_security_action = find_method(
            TRAFFIC_PATH, "execute_security_action"
        )
        cls.block_load_balancer = find_method(
            TOPOLOGY_PATH, "block_load_balancer"
        )
        cls.unblock_load_balancer = find_method(
            TOPOLOGY_PATH, "unblock_load_balancer"
        )

        cls.action_block = module_constant(
            TRAFFIC_PATH, "ACTION_BLOCK_DEVICE", "BLOCK_DEVICE"
        )
        cls.action_unblock = module_constant(
            TRAFFIC_PATH, "ACTION_UNBLOCK_DEVICE", "UNBLOCK_DEVICE"
        )

    def test_security_block_dispatches_to_load_balancer_method(self):
        harness = SecurityActionHarness()

        result = type(self).execute_security_action(
            harness,
            host_ip=LB_IP,
            mac=MAC,
            action=self.action_block,
            request_id="integration-block-1",
            reason="integration-test",
        )

        harness.topology.block_load_balancer.assert_called_once()
        call = harness.topology.block_load_balancer.call_args.kwargs

        self.assertEqual(call["ip"], LB_IP)
        self.assertEqual(call["mac"], MAC)
        self.assertTrue(result["success"])
        self.assertEqual(result["target_type"], "load_balancer")
        self.assertTrue(result["trust_state_unchanged"])
        self.assertTrue(result["trust_score_unchanged"])

    def test_security_unblock_dispatches_to_load_balancer_method(self):
        harness = SecurityActionHarness()

        result = type(self).execute_security_action(
            harness,
            host_ip=LB_IP,
            mac=MAC,
            action=self.action_unblock,
            request_id="integration-unblock-1",
            reason="integration-test",
        )

        harness.topology.unblock_load_balancer.assert_called_once()
        self.assertTrue(result["success"])
        self.assertEqual(result["target_type"], "load_balancer")
        self.assertTrue(result["trust_state_unchanged"])
        self.assertTrue(result["trust_score_unchanged"])

    def test_block_load_balancer_calls_confirmed_mac_block_path(self):
        harness = SimpleNamespace(
            ip_to_mac={LB_IP: MAC},
            blocked_endpoints={},
            block_device=Mock(return_value={
                "success": True,
                "status": "executed",
                "vip_takeover": {"success": True},
                "switches": [1, 2, 3, 4, 5, 6],
                "failed_switches": [],
            }),
            normalize_device_mac=lambda value: value.strip().lower(),
        )

        result = type(self).block_load_balancer(
            harness,
            ip=LB_IP,
            mac=MAC,
            request_id="wrapper-block-1",
            reason="integration-test",
        )

        harness.block_device.assert_called_once_with(
            mac=MAC,
            ip=LB_IP,
            request_id="wrapper-block-1",
            reason="integration-test",
        )
        self.assertTrue(result["success"])
        self.assertTrue(result["emergency_failover"])
        self.assertTrue(
            harness.blocked_endpoints["load_balancer"]["mac_only"]
        )

    def test_unblock_load_balancer_calls_vip_aware_unblock_path(self):
        harness = SimpleNamespace(
            blocked_endpoints={
                "load_balancer": {
                    "ip": LB_IP,
                    "mac": MAC,
                    "mac_only": True,
                }
            },
            blocked_lb_services={},
            unblock_device=Mock(return_value={
                "success": True,
                "status": "executed",
            }),
        )

        result = type(self).unblock_load_balancer(
            harness,
            request_id="wrapper-unblock-1",
            reason="integration-test",
        )

        harness.unblock_device.assert_called_once_with(
            mac=MAC,
            ip=LB_IP,
            request_id="wrapper-unblock-1",
            reason="integration-test",
        )
        self.assertTrue(result["success"])
        self.assertNotIn(
            "load_balancer", harness.blocked_endpoints
        )

    def test_reconnect_confirms_mac_before_restoring_vip_dispatch(self):
        harness = ReconnectHarness(confirm_mac=True)
        datapath = harness.datapaths[6]

        harness._restore_h38_vip_on_switch(datapath)

        self.assertEqual(
            harness.events,
            [
                ("mac_block_confirmation", 6),
                ("vip_dispatch", 6),
            ],
        )
        record = harness.blocked_devices[MAC]
        self.assertEqual(record["confirmed_switches"], [1, 2, 3, 4, 5, 6])
        self.assertEqual(record["enforcement_status"], "executed")

    def test_reconnect_does_not_restore_vip_if_mac_block_fails(self):
        harness = ReconnectHarness(confirm_mac=False)
        datapath = harness.datapaths[6]

        harness._restore_h38_vip_on_switch(datapath)

        self.assertEqual(
            harness.events,
            [("mac_block_confirmation", 6)],
        )
        self.assertEqual(
            harness.blocked_devices[MAC]["confirmed_switches"],
            [1, 2, 3, 4, 5],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
