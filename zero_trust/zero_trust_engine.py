# ============================================================
# TrustFlow - Zero Trust Engine
# ============================================================
#
# Responsibility:
#
#   1. Receive Trust Score from AI
#   2. Validate Trust Score
#   3. Validate AI prediction
#   4. Determine Trust State
#   5. Determine Security Action
#   6. Determine Severity
#   7. Build Security Reason
#   8. Maintain current device security status
#   9. Validate the final Security Decision
#
# IMPORTANT:
#
#   AI calculates the Trust Score.
#
#   This module DOES NOT calculate or modify Trust Score.
#
# Architecture:
#
#   Network
#       |
#       | Features
#       v
#      AI
#       |
#       | Trust Score + Prediction
#       v
#   ZeroTrustEngine
#       |
#       +--> Validate Trust Score
#       +--> Trust State
#       +--> Security Action
#       +--> Severity
#       +--> Reason
#       |
#       v
#   ZeroTrustDecision
#       |
#       | Final Decision Validation
#       v
#   NetworkAction
#       |
#       v
#   Network
#       |
#       v
#   OpenFlow
#
# ============================================================


from zero_trust.zero_trust_policy import (
    MIN_SCORE,
    MAX_SCORE,

    TRUSTED,
    UNTRUSTED,
    QUARANTINED,

    TRUSTED_THRESHOLD,
    UNTRUSTED_THRESHOLD,

    ACTION_ALLOW,
    ACTION_KEEP_UNTRUSTED,
    ACTION_QUARANTINE,

    PREDICTION_BENIGN,
    PREDICTION_MALICIOUS,

    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,

    calculate_trust_state,
)


from zero_trust.zero_trust_decision import (
    ZeroTrustDecision,
)


class ZeroTrustEngine:

    # ========================================================
    # INITIALIZATION
    # ========================================================

    def __init__(self):

        # ----------------------------------------------------
        # ZeroTrustDecision is responsible for validating
        # the final Security Decision.
        #
        # It does NOT calculate the normal decision again.
        # ----------------------------------------------------

        self.decision_validator = ZeroTrustDecision()

        # ----------------------------------------------------
        # Store the latest Security status of each device.
        #
        # Example:
        #
        # {
        #     "10.0.0.5": {
        #         "trust_score": 35,
        #         "trust_state": "QUARANTINED",
        #         "prediction": "malicious",
        #         "action": "QUARANTINE",
        #         "severity": "HIGH",
        #         "events": []
        #     }
        # }
        #
        # The Trust Score stored here is always received
        # from AI.
        #
        # ZeroTrustEngine never calculates it.
        # ----------------------------------------------------

        self.devices = {}

    # ========================================================
    # VALIDATE DEVICE
    # ========================================================

    def validate_device(self, device):
        """
        Validate device identifier.
        """

        if device is None:

            raise ValueError(
                "Missing device"
            )

        if not isinstance(
            device,
            str
        ):

            raise ValueError(
                "device must be a string"
            )

        device = device.strip()

        if not device:

            raise ValueError(
                "device must be a non-empty string"
            )

        return device

    # ========================================================
    # VALIDATE TRUST SCORE
    # ========================================================

    def validate_score(self, trust_score):
        """
        Validate the Trust Score received from AI.

        Valid range:
            0 <= score <= 100

        IMPORTANT:
            This function only validates the score.
            It does NOT calculate it.
        """

        if trust_score is None:

            raise ValueError(
                "Missing trust_score"
            )

        # ----------------------------------------------------
        # bool is a subclass of int in Python.
        #
        # Therefore True / False must be rejected.
        # ----------------------------------------------------

        if isinstance(
            trust_score,
            bool
        ):

            raise ValueError(
                "trust_score must be numeric"
            )

        if not isinstance(
            trust_score,
            (int, float)
        ):

            raise ValueError(
                "trust_score must be numeric"
            )

        if not (
            MIN_SCORE
            <= trust_score
            <= MAX_SCORE
        ):

            raise ValueError(
                "trust_score must be between 0 and 100"
            )

        return trust_score

    # ========================================================
    # VALIDATE AI PREDICTION
    # ========================================================

    def validate_prediction(self, prediction):
        """
        Validate AI prediction.

        Accepted values:
            benign
            malicious
        """

        if prediction is None:

            raise ValueError(
                "Missing prediction"
            )

        if not isinstance(
            prediction,
            str
        ):

            raise ValueError(
                "prediction must be a string"
            )

        prediction = (
            prediction
            .strip()
            .lower()
        )

        if prediction not in (
            PREDICTION_BENIGN,
            PREDICTION_MALICIOUS,
        ):

            raise ValueError(
                "prediction must be "
                "'benign' or 'malicious'"
            )

        return prediction

    # ========================================================
    # DETERMINE TRUST STATE
    # ========================================================

    def calculate_trust_state(
        self,
        trust_score
    ):
        """
        Map the AI-provided Trust Score to a Trust State.

        Policy:

            80 - 100 -> TRUSTED
            50 - 79  -> UNTRUSTED
            0  - 49  -> QUARANTINED

        IMPORTANT:
            The score itself is NOT calculated here.

            The mapping is delegated to the central
            Zero Trust Policy.
        """

        trust_score = self.validate_score(
            trust_score
        )

        return calculate_trust_state(
            trust_score
        )

    # ========================================================
    # DETERMINE SECURITY ACTION
    # ========================================================

    def calculate_action(
        self,
        trust_state
    ):
        """
        Map Trust State to the normal Security Action.

        Normal mapping:

            TRUSTED
                -> ALLOW

            UNTRUSTED
                -> KEEP_UNTRUSTED

            QUARANTINED
                -> QUARANTINE

        Special actions such as RESTORE and REROUTE are
        intentionally NOT generated here.
        """

        if trust_state == TRUSTED:

            return ACTION_ALLOW

        if trust_state == UNTRUSTED:

            return ACTION_KEEP_UNTRUSTED

        if trust_state == QUARANTINED:

            return ACTION_QUARANTINE

        raise ValueError(
            "Unknown trust state: {}".format(
                trust_state
            )
        )

    # ========================================================
    # DETERMINE SEVERITY
    # ========================================================

    def calculate_severity(
        self,
        trust_score,
        prediction
    ):
        """
        Determine security severity.

        The Trust Score is the main factor.

        AI prediction provides additional context.

        IMPORTANT:
            Prediction does NOT modify Trust Score.

            Prediction does NOT directly override the
            Trust State or Security Action.
        """

        trust_score = self.validate_score(
            trust_score
        )

        prediction = self.validate_prediction(
            prediction
        )

        # ----------------------------------------------------
        # Malicious prediction
        # ----------------------------------------------------

        if prediction == PREDICTION_MALICIOUS:

            if trust_score <= 20:

                return SEVERITY_CRITICAL

            if trust_score < 50:

                return SEVERITY_HIGH

            return SEVERITY_MEDIUM

        # ----------------------------------------------------
        # Benign prediction
        # ----------------------------------------------------

        if trust_score < 50:

            return SEVERITY_HIGH

        if trust_score < 80:

            return SEVERITY_MEDIUM

        return SEVERITY_LOW

    # ========================================================
    # BUILD SECURITY REASON
    # ========================================================

    def build_reason(
        self,
        device,
        trust_score,
        prediction,
        trust_state,
        action
    ):
        """
        Build a human-readable explanation
        for the Security decision.
        """

        return (
            "Device {} received AI Trust Score {} "
            "with prediction '{}'. "
            "Trust State is {}. "
            "Security Action is {}."
        ).format(
            device,
            trust_score,
            prediction,
            trust_state,
            action
        )

    # ========================================================
    # EVALUATE AI SECURITY RESULT
    # ========================================================

    def evaluate(
        self,
        device,
        trust_score,
        prediction
    ):
        """
        Evaluate an AI security result.

        Input from AI:

            device
            trust_score
            prediction

        ZeroTrustEngine performs:

            1. Validation
            2. Trust State mapping
            3. Security Action mapping
            4. Severity calculation
            5. Reason generation

        ZeroTrustDecision performs:

            6. Final Decision validation

        IMPORTANT:

            Trust Score is NOT calculated here.

            The score received from AI is used directly.
        """

        # ----------------------------------------------------
        # Validate input
        # ----------------------------------------------------

        device = self.validate_device(
            device
        )

        trust_score = self.validate_score(
            trust_score
        )

        prediction = self.validate_prediction(
            prediction
        )

        # ----------------------------------------------------
        # Determine Trust State
        # ----------------------------------------------------

        trust_state = self.calculate_trust_state(
            trust_score
        )

        # ----------------------------------------------------
        # Determine normal Security Action
        # ----------------------------------------------------

        action = self.calculate_action(
            trust_state
        )

        # ----------------------------------------------------
        # Determine Severity
        # ----------------------------------------------------

        severity = self.calculate_severity(
            trust_score=trust_score,
            prediction=prediction
        )

        # ----------------------------------------------------
        # Build Security Reason
        # ----------------------------------------------------

        reason = self.build_reason(
            device=device,
            trust_score=trust_score,
            prediction=prediction,
            trust_state=trust_state,
            action=action
        )

        # ----------------------------------------------------
        # Build final Security Decision
        # ----------------------------------------------------

        decision = {

            "device": device,

            "trust_score": trust_score,

            "prediction": prediction,

            "trust_state": trust_state,

            "action": action,

            "severity": severity,

            "reason": reason
        }

        # ----------------------------------------------------
        # Validate final decision
        #
        # ZeroTrustDecision does NOT recalculate anything.
        # It only verifies that the decision is valid.
        # ----------------------------------------------------

        self.decision_validator.validate_final_decision(
            decision
        )

        # ----------------------------------------------------
        # Store latest device status
        # ----------------------------------------------------

        if device not in self.devices:

            self.devices[device] = {

                "trust_score": None,

                "trust_state": None,

                "prediction": None,

                "action": None,

                "severity": None,

                "events": []
            }

        # ----------------------------------------------------
        # Save latest Security decision
        #
        # The score here is the score received from AI.
        # No calculation is performed.
        # ----------------------------------------------------

        self.devices[
            device
        ][
            "trust_score"
        ] = trust_score

        self.devices[
            device
        ][
            "trust_state"
        ] = trust_state

        self.devices[
            device
        ][
            "prediction"
        ] = prediction

        self.devices[
            device
        ][
            "action"
        ] = action

        self.devices[
            device
        ][
            "severity"
        ] = severity

        # ----------------------------------------------------
        # Store Security event
        # ----------------------------------------------------

        self.devices[
            device
        ][
            "events"
        ].append({

            "trust_score": trust_score,

            "prediction": prediction,

            "trust_state": trust_state,

            "action": action,

            "severity": severity,

            "reason": reason
        })

        # ----------------------------------------------------
        # Return final Security Decision
        # ----------------------------------------------------

        return decision

    # ========================================================
    # GET DEVICE STATUS
    # ========================================================

    def get_device_status(
        self,
        device
    ):
        """
        Return the latest Security status of a device.
        """

        device = self.validate_device(
            device
        )

        if device not in self.devices:

            return {

                "device": device,

                "trust_score": None,

                "trust_state": None,

                "prediction": None,

                "action": None,

                "severity": None,

                "events": []
            }

        data = self.devices[
            device
        ]

        return {

            "device": device,

            "trust_score": data[
                "trust_score"
            ],

            "trust_state": data[
                "trust_state"
            ],

            "prediction": data[
                "prediction"
            ],

            "action": data[
                "action"
            ],

            "severity": data[
                "severity"
            ],

            "events": list(
                data[
                    "events"
                ]
            )
        }

    # ========================================================
    # GET ALL DEVICES
    # ========================================================

    def get_all_devices(self):
        """
        Return the latest Security status
        of all devices.
        """

        result = {}

        for device in self.devices:

            result[device] = (
                self.get_device_status(
                    device
                )
            )

        return result

    # ========================================================
    # GET ACTION
    # ========================================================

    def get_action(
        self,
        device
    ):
        """
        Return the latest Security Action.
        """

        device = self.validate_device(
            device
        )

        if device not in self.devices:

            return None

        return self.devices[
            device
        ][
            "action"
        ]

    # ========================================================
    # GET TRUST STATE
    # ========================================================

    def get_trust_state(
        self,
        device
    ):
        """
        Return the latest Trust State.
        """

        device = self.validate_device(
            device
        )

        if device not in self.devices:

            return None

        return self.devices[
            device
        ][
            "trust_state"
        ]

    # ========================================================
    # GET TRUST SCORE
    # ========================================================

    def get_trust_score(
        self,
        device
    ):
        """
        Return the latest AI-provided Trust Score.

        This value was received from AI.
        It is not calculated here.
        """

        device = self.validate_device(
            device
        )

        if device not in self.devices:

            return None

        return self.devices[
            device
        ][
            "trust_score"
        ]

    # ========================================================
    # GET SEVERITY
    # ========================================================

    def get_severity(
        self,
        device
    ):
        """
        Return the latest Security Severity.
        """

        device = self.validate_device(
            device
        )

        if device not in self.devices:

            return None

        return self.devices[
            device
        ][
            "severity"
        ]


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("ZERO TRUST ENGINE")
    print("=" * 70)

    engine = ZeroTrustEngine()

    device = "10.0.0.5"

    # ========================================================
    # TEST 1
    # AI sends Trust Score = 92
    # ========================================================

    print("\n[1] AI RESULT")
    print("-" * 70)

    result = engine.evaluate(
        device=device,
        trust_score=92,
        prediction=PREDICTION_BENIGN
    )

    print(result)

    # Expected:
    #
    # Trust Score = 92
    # Trust State = TRUSTED
    # Action      = ALLOW
    # Severity    = LOW

    # ========================================================
    # TEST 2
    # AI sends Trust Score = 65
    # ========================================================

    print("\n[2] AI RESULT")
    print("-" * 70)

    result = engine.evaluate(
        device=device,
        trust_score=65,
        prediction=PREDICTION_MALICIOUS
    )

    print(result)

    # Expected:
    #
    # Trust Score = 65
    # Trust State = UNTRUSTED
    # Action      = KEEP_UNTRUSTED
    # Severity    = MEDIUM

    # ========================================================
    # TEST 3
    # AI sends Trust Score = 35
    # ========================================================

    print("\n[3] AI RESULT")
    print("-" * 70)

    result = engine.evaluate(
        device=device,
        trust_score=35,
        prediction=PREDICTION_MALICIOUS
    )

    print(result)

    # Expected:
    #
    # Trust Score = 35
    # Trust State = QUARANTINED
    # Action      = QUARANTINE
    # Severity    = HIGH

    # ========================================================
    # TEST 4
    # AI sends Trust Score = 90
    # ========================================================
    #
    # IMPORTANT:
    #
    # The previous score was 35.
    #
    # We DO NOT do:
    #
    #     35 + something
    #
    # We simply accept the NEW score from AI.
    #
    # ========================================================

    print("\n[4] AI RESULT")
    print("-" * 70)

    result = engine.evaluate(
        device=device,
        trust_score=90,
        prediction=PREDICTION_BENIGN
    )

    print(result)

    # Expected:
    #
    # Trust Score = 90
    # Trust State = TRUSTED
    # Action      = ALLOW
    # Severity    = LOW

    # ========================================================
    # TEST 5
    # Current Device Status
    # ========================================================

    print("\n[5] DEVICE STATUS")
    print("-" * 70)

    print(
        engine.get_device_status(
            device
        )
    )

    # ========================================================
    # TEST 6
    # All Devices
    # ========================================================

    print("\n[6] ALL DEVICES")
    print("-" * 70)

    print(
        engine.get_all_devices()
    )
