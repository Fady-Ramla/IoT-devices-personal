# ============================================================
# TrustFlow - Zero Trust Network Bridge
# ============================================================
#
# Responsibility:
#
#   Connect the Zero Trust Security layer with
#   the Network Action REST API.
#
# Architecture:
#
#   Security / AI result
#          |
#          v
#   ZeroTrustEngine
#          |
#          v
#   ZeroTrustDecision
#          |
#          v
#   Network API
#          |
#          v
#   TrafficMonitorMerged
#
# IMPORTANT:
#
#   This bridge does NOT:
#   - calculate Trust Score
#   - run AI
#   - install OpenFlow rules
#   - calculate Dijkstra
#
#   It only connects the Security decision
#   to the existing Network API.
#
# ============================================================

import json
import urllib.request
import urllib.error
import os

from zero_trust.zero_trust_engine import ZeroTrustEngine
from zero_trust.zero_trust_decision import ZeroTrustDecision
from zero_trust.zero_trust_policy import ACTION_BLOCK_DEVICE, ACTION_UNBLOCK_DEVICE


class ZeroTrustNetworkBridge:

    # ========================================================
    # INITIALIZATION
    # ========================================================

    def __init__(
        self,
        api_url="http://127.0.0.1:8080/network/action"
    ):

        self.api_url = api_url

        self.engine = ZeroTrustEngine()

        self.decision_validator = ZeroTrustDecision()

    # ========================================================
    # SEND PAYLOAD TO NETWORK API
    # ========================================================

    def _post_payload(self, payload):
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.api_url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-SecureIoT-Token": os.environ.get(
                    "SECUREIOT_CONTROL_TOKEN", "")
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                response_body = response.read()
                try:
                    parsed = json.loads(response_body.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    parsed = response_body.decode("utf-8", errors="replace")
                return {"success": True, "status_code": response.status,
                        "response": parsed}
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            return {"success": False, "status_code": exc.code,
                    "response": error_body}
        except urllib.error.URLError as exc:
            return {"success": False, "status_code": None,
                    "response": str(exc)}

    def send_to_network(self, decision, request_id):
        """Send a normal score-derived ALLOW/KEEP_UNTRUSTED decision."""
        payload = {
            "request_id": request_id,
            "host_ip": decision["device"],
            "action": decision["action"],
            "trust_score": decision["trust_score"],
            "trust_state": decision["trust_state"],
            "severity": decision["severity"],
            "reason": decision["reason"],
        }
        return self._post_payload(payload)

    def send_device_action(self, action, mac, ip=None, request_id=None, reason=None):
        """Forward an explicit Security block/unblock command.

        This API does not accept or derive an enforcement action from
        Trust Score. MAC is the stable OpenFlow match; IP is metadata.
        """
        fields = self.decision_validator.validate_device_action(action, mac, ip)
        payload = {
            "request_id": request_id,
            "action": fields["action"],
            "mac": fields["mac"],
            "ip": fields["ip"],
            "reason": reason,
        }
        return self._post_payload(payload)

    def block_device(self, mac, ip=None, request_id=None, reason=None):
        return self.send_device_action(
            ACTION_BLOCK_DEVICE, mac, ip, request_id, reason)

    def unblock_device(self, mac, ip=None, request_id=None, reason=None):
        return self.send_device_action(
            ACTION_UNBLOCK_DEVICE, mac, ip, request_id, reason)

    # ========================================================
    # PROCESS SECURITY RESULT
    # ========================================================

    def process(
        self,
        device,
        trust_score,
        prediction,
        request_id
    ):
        """
        Process an AI score result only. This method never blocks
        a device. The Security component must call block_device()
        separately when it issues an explicit enforcement decision.
        """

        # ----------------------------------------------------
        # Step 1: Zero Trust Engine
        # ----------------------------------------------------

        decision = self.engine.evaluate(
            device=device,
            trust_score=trust_score,
            prediction=prediction
        )

        # ----------------------------------------------------
        # Step 2: Final Decision Validation
        # ----------------------------------------------------

        self.decision_validator.validate_final_decision(
            decision
        )

        # ----------------------------------------------------
        # Step 3: Send to Network
        # ----------------------------------------------------

        network_result = self.send_to_network(
            decision=decision,
            request_id=request_id
        )

        return {
            "security_decision": decision,

            "network_result": network_result
        }


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("TRUSTFLOW ZERO TRUST → NETWORK TEST")
    print("=" * 70)

    bridge = ZeroTrustNetworkBridge()

    # --------------------------------------------------------
    # Simulated AI result
    #
    # IMPORTANT:
    #
    # This is NOT AI.
    #
    # We are only simulating the output that AI
    # will provide later.
    # --------------------------------------------------------

    device = "10.0.0.2"

    trust_score = 35

    prediction = "malicious"

    request_id = "ZT-BRIDGE-001"

    print("\n[1] SIMULATED AI RESULT")
    print("-" * 70)

    print(
        "Device     : {}".format(
            device
        )
    )

    print(
        "Trust Score: {}".format(
            trust_score
        )
    )

    print(
        "Prediction : {}".format(
            prediction
        )
    )

    # --------------------------------------------------------
    # Process
    # --------------------------------------------------------

    print("\n[2] ZERO TRUST PROCESSING")
    print("-" * 70)

    result = bridge.process(
        device=device,
        trust_score=trust_score,
        prediction=prediction,
        request_id=request_id
    )

    # --------------------------------------------------------
    # Security decision
    # --------------------------------------------------------

    print("\n[3] SECURITY DECISION")
    print("-" * 70)

    print(
        json.dumps(
            result["security_decision"],
            indent=4
        )
    )

    # --------------------------------------------------------
    # Network result
    # --------------------------------------------------------

    print("\n[4] NETWORK RESULT")
    print("-" * 70)

    print(
        json.dumps(
            result["network_result"],
            indent=4
        )
    )

    print("\n" + "=" * 70)
