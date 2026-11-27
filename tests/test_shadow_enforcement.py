import ast
import ipaddress
import logging
import os
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / "traffic_monitor_merged.py").read_text(encoding="utf-8"))
traffic_class = next(node for node in TREE.body
                     if isinstance(node, ast.ClassDef)
                     and node.name == "TrafficMonitorMerged")
method = next(node for node in traffic_class.body
              if isinstance(node, ast.FunctionDef)
              and node.name == "execute_shadow_api_verdict")
namespace = {
    "os": os, "ipaddress": ipaddress,
    "ACTION_BLOCK_DEVICE": "BLOCK_DEVICE",
    "ACTION_UNBLOCK_DEVICE": "UNBLOCK_DEVICE",
}
exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])),
             str(ROOT / "traffic_monitor_merged.py"), "exec"), namespace)


class ShadowMonitorHarness:
    execute_shadow_api_verdict = namespace["execute_shadow_api_verdict"]


class ShadowEnforcementTests(unittest.TestCase):
    def setUp(self):
        self.monitor = ShadowMonitorHarness()
        self.monitor.logger = logging.getLogger("test.shadow.enforcement")
        self.monitor.shadow_seen_request_ids = set()

        self.mac = "00:00:00:00:00:05"
        self.ip = "10.10.10.5"

        self.topology = SimpleNamespace(
            ip_to_mac={self.ip: self.mac},
            host_location={self.mac: (4, 1)},
            ip_vlan={self.ip: 10},
            mac_vlan={self.mac: 10},
            vlan_map_ready=True,
            vlan_port_map={
                (4, 1): {
                    "kind": "access",
                    "role": "endpoint",
                    "vlan_id": 10,
                    "allowed_vlans": frozenset(),
                }
            },
            blocked_devices={},
            normalize_device_mac=lambda value: value.strip().lower(),
        )

        self.monitor._get_topology_monitor = Mock(return_value=self.topology)
        self.monitor.execute_security_action = Mock(return_value={
            "success": True,
            "status": "executed",
        })

        self.payload = {
            "decision": "BLOCK_DEVICE",
            "requested_src_ip": self.ip,
            "response_src_ip": self.ip,
            "request_id": "test-request-1",
            "reason": "unit test",
        }

        self.env = patch.dict(os.environ, {
            "SHADOW_ENFORCE": "1",
            "SHADOW_ENFORCEMENT_ALL_ACCESS": "0",
            "SHADOW_ENFORCEMENT_IPS": self.ip,
            "SHADOW_ENFORCEMENT_VLANS": "10",
            "SECUREIOT_PROTECTED_IPS": "",
            "SHADOW_AUTO_UNBLOCK": "0",
        }, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_legacy_allowlist_accepts_current_access_endpoint(self):
        result = self.monitor.execute_shadow_api_verdict(self.payload)
        self.assertTrue(result["success"])
        self.monitor.execute_security_action.assert_called_once()

    def test_legacy_allowlist_rejects_unlisted_ip(self):
        os.environ["SHADOW_ENFORCEMENT_IPS"] = "10.10.10.99"
        result = self.monitor.execute_shadow_api_verdict(self.payload)
        self.assertEqual(result["status"], "rejected")
        self.monitor.execute_security_action.assert_not_called()

    def test_protected_ip_is_rejected(self):
        os.environ["SECUREIOT_PROTECTED_IPS"] = self.ip
        result = self.monitor.execute_shadow_api_verdict(self.payload)
        self.assertEqual(result["status"], "rejected")
        self.monitor.execute_security_action.assert_not_called()

    def test_all_access_still_rejects_protected_ip(self):
        self.enable_all_access()
        os.environ["SECUREIOT_PROTECTED_IPS"] = self.ip

        result = self.monitor.execute_shadow_api_verdict(self.payload)

        self.assertEqual(result["status"], "rejected")
        self.assertIn("protected", result["message"])
        self.monitor.execute_security_action.assert_not_called()

    def test_source_ip_mismatch_is_rejected(self):
        self.payload["response_src_ip"] = "10.10.10.99"
        result = self.monitor.execute_shadow_api_verdict(self.payload)
        self.assertEqual(result["status"], "rejected")
        self.monitor.execute_security_action.assert_not_called()

    def test_gateway_trunk_is_not_an_access_endpoint(self):
        self.topology.vlan_port_map[(4, 1)] = {
            "kind": "trunk",
            "role": "gateway",
            "vlan_id": None,
            "allowed_vlans": frozenset({10, 20, 30, 40, 50}),
        }
        self.topology.ip_to_mac[self.ip] = self.mac
        result = self.monitor.execute_shadow_api_verdict(self.payload)
        # Legacy mode remains allowlist-based; endpoint-only validation
        # is introduced in the new ALL_ACCESS mode.
        self.assertTrue(result["success"])

    def test_vlan_scope_is_enforced(self):
        os.environ["SHADOW_ENFORCEMENT_VLANS"] = "20"
        result = self.monitor.execute_shadow_api_verdict(self.payload)
        self.assertEqual(result["status"], "rejected")
        self.monitor.execute_security_action.assert_not_called()

    def test_automatic_unblock_remains_disabled(self):
        self.payload["decision"] = "UNBLOCK_DEVICE"
        result = self.monitor.execute_shadow_api_verdict(self.payload)
        self.assertEqual(result["status"], "rejected")
        self.monitor.execute_security_action.assert_not_called()


    def enable_all_access(self):
        os.environ["SHADOW_ENFORCEMENT_ALL_ACCESS"] = "1"
        os.environ["SHADOW_ENFORCEMENT_IPS"] = "10.10.10.99"

    def test_all_access_accepts_endpoint_without_ip_allowlist(self):
        self.enable_all_access()
        result = self.monitor.execute_shadow_api_verdict(self.payload)
        self.assertTrue(result["success"])
        self.monitor.execute_security_action.assert_called_once()

    def test_all_access_rejects_gateway_trunk(self):
        self.enable_all_access()
        self.topology.vlan_port_map[(4, 1)] = {
            "kind": "trunk",
            "role": "gateway",
            "vlan_id": None,
            "allowed_vlans": frozenset({10, 20, 30, 40, 50}),
        }
        result = self.monitor.execute_shadow_api_verdict(self.payload)
        self.assertEqual(result["status"], "rejected")
        self.monitor.execute_security_action.assert_not_called()

    def test_all_access_rejects_inter_switch_trunk(self):
        self.enable_all_access()
        self.topology.vlan_port_map[(4, 1)] = {
            "kind": "trunk",
            "role": "inter-switch",
            "vlan_id": None,
            "allowed_vlans": frozenset({10, 20, 30, 40, 50}),
        }
        result = self.monitor.execute_shadow_api_verdict(self.payload)
        self.assertEqual(result["status"], "rejected")
        self.monitor.execute_security_action.assert_not_called()

    def test_all_access_rejects_mac_vlan_mismatch(self):
        self.enable_all_access()
        self.topology.mac_vlan[self.mac] = 20
        result = self.monitor.execute_shadow_api_verdict(self.payload)
        self.assertEqual(result["status"], "rejected")
        self.monitor.execute_security_action.assert_not_called()

    def test_all_access_rejects_unready_vlan_inventory(self):
        self.enable_all_access()
        self.topology.vlan_map_ready = False
        result = self.monitor.execute_shadow_api_verdict(self.payload)
        self.assertEqual(result["status"], "unavailable")
        self.monitor.execute_security_action.assert_not_called()


if __name__ == "__main__":
    unittest.main()
