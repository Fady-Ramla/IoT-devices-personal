#!/usr/bin/env python3
"""Smoke tests for the current Zero Trust contract.

The normal score path only emits ALLOW/KEEP_UNTRUSTED. Device enforcement is
explicit and MAC-based through BLOCK_DEVICE/UNBLOCK_DEVICE.
"""
import json
import unittest
from unittest.mock import patch

from zero_trust.zero_trust_decision import ZeroTrustDecision
from zero_trust.zero_trust_engine import ZeroTrustEngine
from zero_trust.zero_trust_network_bridge import ZeroTrustNetworkBridge
from zero_trust.zero_trust_policy import (
    ACTION_ALLOW, ACTION_BLOCK_DEVICE, ACTION_KEEP_UNTRUSTED,
    ACTION_UNBLOCK_DEVICE, TRUSTED, UNTRUSTED,
)


class ZeroTrustContractTests(unittest.TestCase):
    def setUp(self):
        self.validator = ZeroTrustDecision()

    def test_normal_decisions_never_become_device_blocks(self):
        engine = ZeroTrustEngine()
        trusted = engine.evaluate("10.0.0.2", 90, "benign")
        untrusted = engine.evaluate("10.0.0.3", 35, "malicious")
        self.assertEqual((trusted["trust_state"], trusted["action"]),
                         (TRUSTED, ACTION_ALLOW))
        self.assertEqual((untrusted["trust_state"], untrusted["action"]),
                         (UNTRUSTED, ACTION_KEEP_UNTRUSTED))
        self.assertNotIn(trusted["action"], {ACTION_BLOCK_DEVICE, ACTION_UNBLOCK_DEVICE})
        self.assertNotIn(untrusted["action"], {ACTION_BLOCK_DEVICE, ACTION_UNBLOCK_DEVICE})

    def test_explicit_device_action_is_mac_based(self):
        result = self.validator.validate_device_action(
            ACTION_BLOCK_DEVICE, "02:00:00:00:00:05", "10.0.0.5")
        self.assertEqual(result, {
            "action": ACTION_BLOCK_DEVICE,
            "mac": "02:00:00:00:00:05",
            "ip": "10.0.0.5",
        })
        result = self.validator.validate_device_action(
            ACTION_UNBLOCK_DEVICE, "02:00:00:00:00:05")
        self.assertEqual(result["action"], ACTION_UNBLOCK_DEVICE)
        self.assertIsNone(result["ip"])

    def test_bridge_payload_matches_network_controller(self):
        bridge = ZeroTrustNetworkBridge()
        with patch.object(bridge, "_post_payload", return_value={"success": True}) as post:
            bridge.block_device("02:00:00:00:00:05", "10.0.0.5", "SEC-001", "malicious")
        payload = post.call_args.args[0]
        self.assertEqual(payload["action"], ACTION_BLOCK_DEVICE)
        self.assertEqual(payload["mac"], "02:00:00:00:00:05")
        self.assertEqual(payload["ip"], "10.0.0.5")
        self.assertNotIn("trust_score", payload)
        self.assertNotIn("trust_state", payload)

    def test_invalid_mac_is_rejected(self):
        with self.assertRaises(ValueError):
            self.validator.validate_device_action(ACTION_BLOCK_DEVICE, "not-a-mac")


if __name__ == "__main__":
    unittest.main(verbosity=2)
