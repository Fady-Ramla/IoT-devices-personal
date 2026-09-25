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

from zero_trust.zero_trust_engine import ZeroTrustEngine
from zero_trust.zero_trust_decision import ZeroTrustDecision


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
    # SEND DECISION TO NETWORK API
    # ========================================================

    def send_to_network(
        self,
        decision,
        request_id
    ):
        """
        Send a validated Zero Trust decision
        to the Network Action API.
        """

        payload = {
            "request_id": request_id,

            "src_ip": decision["device"],

            "action": decision["action"],

            "trust_score": decision["trust_score"],

            "trust_state": decision["trust_state"],

            "severity": decision["severity"],

            "reason": decision["reason"]
        }

        body = json.dumps(
            payload
        ).encode("utf-8")

        request = urllib.request.Request(
            self.api_url,
            data=body,
            headers={
                "Content-Type": "application/json"
            },
            method="POST"
        )

        try:

            with urllib.request.urlopen(
                request,
                timeout=5
            ) as response:

                response_body = response.read()

                return {
                    "success": True,

                    "status_code": response.status,

                    "response": json.loads(
                        response_body.decode("utf-8")
                    )
                }

        except urllib.error.HTTPError as exc:

            error_body = exc.read().decode(
                "utf-8",
                errors="replace"
            )

            return {
                "success": False,

                "status_code": exc.code,

                "response": error_body
            }

        except urllib.error.URLError as exc:

            return {
                "success": False,

                "status_code": None,

                "response": str(exc)
            }

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
        Process a Security / AI result.

        Steps:

            1. ZeroTrustEngine evaluates the result.
            2. ZeroTrustDecision validates it.
            3. Decision is sent to Network API.
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
