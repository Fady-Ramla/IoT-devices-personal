"""Direct tests for confirmed h38 MAC unblock and rollback behavior."""

import ast
import unittest

from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "topology_monitor.py"
TREE = ast.parse(SOURCE.read_text(encoding="utf-8"))

MAC = "00:00:00:00:00:27"
LB_IP = "10.10.20.100"
EXPECTED = set(range(1, 7))

OFPFC_ADD = 0
OFPFC_DELETE_STRICT = 4
OFPIT_APPLY_ACTIONS = 4
DEVICE_BLOCK_PRIORITY = 50000


def extract_method(name):
    topology = next(
        node for node in TREE.body
        if isinstance(node, ast.ClassDef)
        and node.name == "TopologyMonitor"
    )
    method = next(
        node for node in topology.body
        if isinstance(node, ast.FunctionDef)
        and node.name == name
    )

    module = ast.Module(body=[method], type_ignores=[])
    namespace = {
        "EXPECTED_SWITCHES": 6,
        "DEVICE_BLOCK_PRIORITY": DEVICE_BLOCK_PRIORITY,
    }

    exec(
        compile(ast.fix_missing_locations(module), str(SOURCE), "exec"),
        namespace,
    )
    return namespace[name]


class FakeParser:
    def OFPMatch(self, **kwargs):
        return kwargs

    def OFPFlowMod(self, **kwargs):
        return SimpleNamespace(**kwargs)

    def OFPInstructionActions(self, instruction, actions):
        return {
            "type": instruction,
            "actions": list(actions),
        }


class FakeDatapath:
    def __init__(self, dpid):
        self.id = dpid
        self.ofproto_parser = FakeParser()
        self.ofproto = SimpleNamespace(
            OFPFC_ADD=OFPFC_ADD,
            OFPFC_DELETE_STRICT=OFPFC_DELETE_STRICT,
            OFPIT_APPLY_ACTIONS=OFPIT_APPLY_ACTIONS,
            OFPP_ANY=0xFFFFFFFC,
            OFPG_ANY=0xFFFFFFFC,
        )


class H38UnblockHarness:
    unblock_device = extract_method("unblock_device")

    def __init__(
        self,
        missing_switches=None,
        delete_fail=None,
        restore_fail=None,
        deactivate_success=True,
        activate_success=True,
        target_ip=LB_IP,
    ):
        missing_switches = set(missing_switches or [])
        self.delete_fail = set(delete_fail or [])
        self.restore_fail = set(restore_fail or [])

        self.datapaths = {
            dpid: FakeDatapath(dpid)
            for dpid in sorted(EXPECTED - missing_switches)
        }

        self.blocked_devices = {
            MAC: {
                "ip": target_ip,
                "macs": [MAC],
                "confirmed_switches": sorted(EXPECTED),
                "enforcement_status": "executed",
            }
        }

        self.deactivate_success = deactivate_success
        self.activate_success = activate_success

        self.events = []
        self.batches = []
        self.ordinary_deletes = []

        self.logger = SimpleNamespace(
            info=lambda *args, **kwargs: None,
            error=lambda *args, **kwargs: None,
            exception=lambda *args, **kwargs: None,
        )

    @staticmethod
    def normalize_device_mac(value):
        return str(value).strip().lower()

    def deactivate_vip_takeover(self):
        self.events.append(("deactivate",))
        return {
            "success": self.deactivate_success,
            "status": (
                "deactivated" if self.deactivate_success
                else "dispatch_cleanup_failed"
            ),
        }

    def _send_security_flow_batch(self, datapath, messages):
        commands = {message.command for message in messages}

        if commands == {OFPFC_DELETE_STRICT}:
            kind = "delete"
            success = datapath.id not in self.delete_fail
        elif commands == {OFPFC_ADD}:
            kind = "restore"
            success = datapath.id not in self.restore_fail
        else:
            raise AssertionError(
                "Unexpected FlowMod command set: %r" % commands
            )

        self.batches.append((kind, datapath.id, list(messages)))
        self.events.append((kind, datapath.id))

        return {
            "success": success,
            "status": "confirmed" if success else "openflow_error",
        }

    def activate_vip_takeover(self):
        record = self.blocked_devices[MAC]
        confirmed = tuple(record.get("confirmed_switches", []))
        self.events.append(("activate", confirmed))

        return {
            "success": self.activate_success,
            "status": (
                "active" if self.activate_success
                else "dispatch_install_failed"
            ),
        }

    def _delete_device_block_rule(self, datapath, mac):
        self.ordinary_deletes.append((datapath.id, mac))

    def _install_device_block_rule(self, datapath, mac):
        raise AssertionError(
            "Unexpected ordinary block restoration in this test"
        )

    def run_unblock(self, ip=LB_IP):
        return self.unblock_device(
            MAC,
            ip=ip,
            request_id="test-h38-unblock",
            reason="unit-test",
        )


class H38UnblockConfirmationTests(unittest.TestCase):

    def test_missing_switch_prevents_unblock_and_vip_deactivation(self):
        harness = H38UnblockHarness(missing_switches={6})

        result = harness.run_unblock()

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "switches_unavailable")
        self.assertEqual(result["failed_switches"], [6])
        self.assertIn(MAC, harness.blocked_devices)
        self.assertEqual(harness.batches, [])
        self.assertEqual(harness.events, [])

    def test_all_six_switches_confirm_delete_before_success(self):
        harness = H38UnblockHarness()

        result = harness.run_unblock()

        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "executed")
        self.assertEqual(result["switches"], sorted(EXPECTED))
        self.assertNotIn(MAC, harness.blocked_devices)

        delete_batches = [
            (dpid, messages)
            for kind, dpid, messages in harness.batches
            if kind == "delete"
        ]
        self.assertEqual(
            [dpid for dpid, _ in delete_batches],
            sorted(EXPECTED),
        )

        for dpid, messages in delete_batches:
            self.assertEqual(len(messages), 1)
            self.assertEqual(messages[0].command, OFPFC_DELETE_STRICT)
            self.assertEqual(
                messages[0].match,
                {"eth_src": MAC},
            )
            self.assertEqual(
                messages[0].priority,
                DEVICE_BLOCK_PRIORITY,
            )

        self.assertEqual(harness.events[0], ("deactivate",))
        self.assertFalse(
            any(event[0] == "activate" for event in harness.events)
        )

    def test_delete_failure_restores_block_on_all_switches_before_vip(self):
        harness = H38UnblockHarness(delete_fail={3})

        result = harness.run_unblock()

        self.assertFalse(result["success"])
        self.assertEqual(
            result["status"],
            "unblock_failed_block_restored",
        )
        self.assertEqual(result["delete_failed_switches"], [3])
        self.assertEqual(result["restored_switches"], sorted(EXPECTED))
        self.assertEqual(result["restore_failed_switches"], [])

        self.assertIn(MAC, harness.blocked_devices)

        record = harness.blocked_devices[MAC]
        self.assertEqual(record["confirmed_switches"], sorted(EXPECTED))
        self.assertEqual(record["enforcement_status"], "executed")

        restore_batches = [
            (dpid, messages)
            for kind, dpid, messages in harness.batches
            if kind == "restore"
        ]
        self.assertEqual(
            [dpid for dpid, _ in restore_batches],
            sorted(EXPECTED),
        )

        # The restored rule must use the same explicit empty-action
        # instruction as the production device-block installer.
        for _dpid, messages in restore_batches:
            self.assertEqual(len(messages), 1)
            message = messages[0]
            self.assertEqual(message.command, OFPFC_ADD)
            self.assertEqual(message.priority, DEVICE_BLOCK_PRIORITY)
            self.assertEqual(message.match, {"eth_src": MAC})
            self.assertEqual(
                message.instructions,
                [{
                    "type": OFPIT_APPLY_ACTIONS,
                    "actions": [],
                }],
            )

        activate_events = [
            event for event in harness.events
            if event[0] == "activate"
        ]
        self.assertEqual(len(activate_events), 1)
        self.assertEqual(activate_events[0][1], tuple(sorted(EXPECTED)))

        last_restore_index = max(
            index for index, event in enumerate(harness.events)
            if event[0] == "restore"
        )
        activate_index = next(
            index for index, event in enumerate(harness.events)
            if event[0] == "activate"
        )
        self.assertGreater(activate_index, last_restore_index)

    def test_restore_failure_does_not_reactivate_vip(self):
        harness = H38UnblockHarness(
            delete_fail={3},
            restore_fail={4},
        )

        result = harness.run_unblock()

        self.assertFalse(result["success"])
        self.assertEqual(
            result["status"],
            "unblock_failed_rollback_incomplete",
        )
        self.assertEqual(result["restore_failed_switches"], [4])

        record = harness.blocked_devices[MAC]
        self.assertEqual(
            record["confirmed_switches"],
            [1, 2, 3, 5, 6],
        )
        self.assertEqual(record["enforcement_status"], "partial_failure")

        self.assertFalse(
            any(event[0] == "activate" for event in harness.events)
        )

    def test_vip_activation_failure_keeps_mac_block_record(self):
        harness = H38UnblockHarness(
            delete_fail={2},
            activate_success=False,
        )

        result = harness.run_unblock()

        self.assertFalse(result["success"])
        self.assertEqual(
            result["status"],
            "unblock_failed_vip_restore_failed",
        )
        self.assertIn(MAC, harness.blocked_devices)
        self.assertEqual(
            harness.blocked_devices[MAC]["confirmed_switches"],
            sorted(EXPECTED),
        )

    def test_vip_deactivation_failure_prevents_mac_deletion(self):
        harness = H38UnblockHarness(deactivate_success=False)

        result = harness.run_unblock()

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "partial_failure")
        self.assertIn(MAC, harness.blocked_devices)
        self.assertEqual(harness.batches, [])
        self.assertEqual(harness.events, [("deactivate",)])

    def test_ordinary_endpoint_keeps_existing_unblock_path(self):
        harness = H38UnblockHarness(target_ip="10.10.10.27")

        result = harness.run_unblock(ip="10.10.10.27")

        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "executed")
        self.assertNotIn(MAC, harness.blocked_devices)

        self.assertEqual(
            harness.ordinary_deletes,
            [(dpid, MAC) for dpid in sorted(EXPECTED)],
        )
        self.assertEqual(harness.batches, [])
        self.assertEqual(harness.events, [])


if __name__ == "__main__":
    unittest.main()
