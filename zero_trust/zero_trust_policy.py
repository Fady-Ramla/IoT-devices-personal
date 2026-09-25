# zero_trust_policy.py
# ============================================================
# TrustFlow - Zero Trust Policy
#
# Single source of truth for:
# - Trust Score thresholds
# - Trust states
# - Security actions
# - Security events
# - Predictions
# - Severity levels
# ============================================================


# ============================================================
# Trust Score
# ============================================================

MIN_SCORE = 0
MAX_SCORE = 100

INITIAL_SCORE = 100


# ============================================================
# Trust State Thresholds
# ============================================================

TRUSTED_THRESHOLD = 80
UNTRUSTED_THRESHOLD = 50


TRUSTED = "TRUSTED"
UNTRUSTED = "UNTRUSTED"
QUARANTINED = "QUARANTINED"


# ============================================================
# Security Actions
# ============================================================

ACTION_ALLOW = "ALLOW"
ACTION_KEEP_UNTRUSTED = "KEEP_UNTRUSTED"
ACTION_QUARANTINE = "QUARANTINE"

# Special actions
ACTION_RESTORE = "RESTORE"
ACTION_REROUTE = "REROUTE"


VALID_ACTIONS = {
    ACTION_ALLOW,
    ACTION_KEEP_UNTRUSTED,
    ACTION_QUARANTINE,
    ACTION_RESTORE,
    ACTION_REROUTE,
}


# ============================================================
# Security Events
# ============================================================

EVENT_NORMAL = "NORMAL"
EVENT_RECOVERY = "RECOVERY"
EVENT_SUSPICIOUS = "SUSPICIOUS"
EVENT_PORT_SCAN = "PORT_SCAN"
EVENT_MALICIOUS_POST = "MALICIOUS_POST"
EVENT_SYN_FLOOD = "SYN_FLOOD"


VALID_EVENTS = {
    EVENT_NORMAL,
    EVENT_RECOVERY,
    EVENT_SUSPICIOUS,
    EVENT_PORT_SCAN,
    EVENT_MALICIOUS_POST,
    EVENT_SYN_FLOOD,
}


# ============================================================
# Legacy / Reference Event Score Changes
# ============================================================
#
# These values are kept as policy/reference values.
#
# The current architecture does NOT modify the AI Trust Score
# using these deltas.
#
# AI is the authoritative source of the Trust Score.
# ============================================================

EVENT_DELTAS = {
    EVENT_NORMAL: +1,
    EVENT_RECOVERY: +5,
    EVENT_SUSPICIOUS: -10,
    EVENT_PORT_SCAN: -20,
    EVENT_MALICIOUS_POST: -25,
    EVENT_SYN_FLOOD: -30,
}


# ============================================================
# Predictions
# ============================================================

PREDICTION_BENIGN = "benign"
PREDICTION_MALICIOUS = "malicious"

VALID_PREDICTIONS = {
    PREDICTION_BENIGN,
    PREDICTION_MALICIOUS,
}


# ============================================================
# Severity
# ============================================================

SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

VALID_SEVERITIES = {
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
}


# ============================================================
# Helpers
# ============================================================

def clamp_score(score):
    """
    Keep Trust Score inside the valid range [0, 100].
    """

    return max(
        MIN_SCORE,
        min(MAX_SCORE, score)
    )


def calculate_trust_state(score):
    """
    Convert Trust Score into Trust State.

    80 - 100 -> TRUSTED
    50 - 79  -> UNTRUSTED
    0  - 49  -> QUARANTINED
    """

    if score >= TRUSTED_THRESHOLD:
        return TRUSTED

    if score >= UNTRUSTED_THRESHOLD:
        return UNTRUSTED

    return QUARANTINED
