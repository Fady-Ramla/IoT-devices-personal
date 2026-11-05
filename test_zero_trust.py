"""
test_zero_trust.py
------------------
Test that the Zero Trust module is fully functional
and compatible with traffic_monitor_merged.py.

READ-ONLY: does NOT modify any file.
"""

import sys


print()
print("=" * 70)
print("        ZERO TRUST MODULE TEST")
print("=" * 70)


# ============================================================
# 1. Imports
# ============================================================

print()
print("-" * 70)
print("1. IMPORTS")
print("-" * 70)

try:

    from zero_trust.zero_trust_policy import (
        TRUSTED,
        UNTRUSTED,
        QUARANTINED,

        ACTION_ALLOW,
        ACTION_KEEP_UNTRUSTED,
        ACTION_QUARANTINE,
        ACTION_RESTORE,
        ACTION_REROUTE,

        MIN_SCORE,
        MAX_SCORE
    )

    print("[PASS] zero_trust_policy imports OK")

except Exception as e:

    print("[FAIL] zero_trust_policy imports:")
    print("       ", e)
    sys.exit(1)


try:

    from zero_trust.zero_trust_decision import (
        ZeroTrustDecision
    )

    print("[PASS] zero_trust_decision imports OK")

except Exception as e:

    print("[FAIL] zero_trust_decision imports:")
    print("       ", e)
    sys.exit(1)


# ============================================================
# 2. Constants
# ============================================================

print()
print("-" * 70)
print("2. CONSTANTS")
print("-" * 70)

print(f"  TRUSTED       = {TRUSTED}")
print(f"  UNTRUSTED     = {UNTRUSTED}")
print(f"  QUARANTINED   = {QUARANTINED}")
print()
print(f"  ACTION_ALLOW            = {ACTION_ALLOW}")
print(f"  ACTION_KEEP_UNTRUSTED   = {ACTION_KEEP_UNTRUSTED}")
print(f"  ACTION_QUARANTINE       = {ACTION_QUARANTINE}")
print(f"  ACTION_RESTORE          = {ACTION_RESTORE}")
print(f"  ACTION_REROUTE          = {ACTION_REROUTE}")
print()
print(f"  MIN_SCORE = {MIN_SCORE}")
print(f"  MAX_SCORE = {MAX_SCORE}")

if MIN_SCORE == 0 and MAX_SCORE == 100:
    print("[PASS] Score range is 0-100")
else:
    print("[WARNING] Unexpected score range")


# ============================================================
# 3. ZeroTrustDecision Instance
# ============================================================

print()
print("-" * 70)
print("3. ZeroTrustDecision INSTANCE")
print("-" * 70)

try:

    d = ZeroTrustDecision()

    print("[PASS] ZeroTrustDecision() created")

except Exception as e:

    print("[FAIL] ZeroTrustDecision() failed:")
    print("       ", e)
    sys.exit(1)


methods = [
    m for m in dir(d)
    if not m.startswith("_")
]

print(f"  Methods available: {methods}")


# ============================================================
# 4. validate_score
# ============================================================

print()
print("-" * 70)
print("4. validate_score()")
print("-" * 70)

try:

    d.validate_score(50)
    print("[PASS] validate_score(50) OK")

    d.validate_score(0)
    print("[PASS] validate_score(0) OK")

    d.validate_score(100)
    print("[PASS] validate_score(100) OK")

except Exception as e:

    print("[FAIL]", e)


# Invalid cases
try:

    d.validate_score(150)
    print("[FAIL] validate_score(150) should raise ValueError")

except ValueError:
    print("[PASS] validate_score(150) raises ValueError")

except Exception as e:
    print("[FAIL] unexpected error:", e)


# ============================================================
# 5. validate_trust_state
# ============================================================

print()
print("-" * 70)
print("5. validate_trust_state()")
print("-" * 70)

for state in [TRUSTED, UNTRUSTED, QUARANTINED]:

    try:
        d.validate_trust_state(state)
        print(f"[PASS] validate_trust_state({state}) OK")

    except Exception as e:
        print(f"[FAIL] validate_trust_state({state}):", e)


try:
    d.validate_trust_state("INVALID")
    print("[FAIL] validate_trust_state('INVALID') should raise")

except ValueError:
    print("[PASS] validate_trust_state('INVALID') raises ValueError")


# ============================================================
# 6. validate_action
# ============================================================

print()
print("-" * 70)
print("6. validate_action()")
print("-" * 70)

for action in [
    ACTION_ALLOW,
    ACTION_KEEP_UNTRUSTED,
    ACTION_QUARANTINE,
    ACTION_RESTORE,
    ACTION_REROUTE
]:

    try:
        d.validate_action(action)
        print(f"[PASS] validate_action({action}) OK")

    except Exception as e:
        print(f"[FAIL] validate_action({action}):", e)


# ============================================================
# 7. validate_decision - IMPORTANT
# ============================================================

print()
print("-" * 70)
print("7. validate_decision()")
print("-" * 70)

# TRUSTED + ALLOW

try:

    d.validate_decision(
        trust_score=100,
        trust_state=TRUSTED,
        action=ACTION_ALLOW
    )

    print("[PASS] (TRUSTED, ALLOW) accepted")

except Exception as e:
    print("[FAIL] (TRUSTED, ALLOW):", e)


# UNTRUSTED + KEEP_UNTRUSTED

try:

    d.validate_decision(
        trust_score=50,
        trust_state=UNTRUSTED,
        action=ACTION_KEEP_UNTRUSTED
    )

    print("[PASS] (UNTRUSTED, KEEP_UNTRUSTED) accepted")

except Exception as e:
    print("[FAIL] (UNTRUSTED, KEEP_UNTRUSTED):", e)


# QUARANTINED + QUARANTINE

try:

    d.validate_decision(
        trust_score=20,
        trust_state=QUARANTINED,
        action=ACTION_QUARANTINE
    )

    print("[PASS] (QUARANTINED, QUARANTINE) accepted")

except Exception as e:
    print("[FAIL] (QUARANTINED, QUARANTINE):", e)


# INVALID: TRUSTED + QUARANTINE (should raise)

try:

    d.validate_decision(
        trust_score=100,
        trust_state=TRUSTED,
        action=ACTION_QUARANTINE
    )

    print("[FAIL] (TRUSTED, QUARANTINE) should raise")

except ValueError:

    print("[PASS] (TRUSTED, QUARANTINE) raises ValueError")


# ============================================================
# 8. traffic_monitor_merged.py USAGE
# ============================================================

print()
print("-" * 70)
print("8. traffic_monitor_merged.py USAGE")
print("-" * 70)

try:

    from traffic_monitor_merged import TrafficMonitorMerged

    print("[PASS] TrafficMonitorMerged imports OK")

except Exception as e:

    print("[FAIL] TrafficMonitorMerged import:")
    print("       ", e)
    sys.exit(1)


# Verify the class has _validate_network_decision

if hasattr(TrafficMonitorMerged, "_validate_network_decision"):

    print("[PASS] _validate_network_decision exists")

else:

    print("[FAIL] _validate_network_decision missing")


# Verify the class has execute_security_action

if hasattr(TrafficMonitorMerged, "execute_security_action"):

    print("[PASS] execute_security_action exists")

else:

    print("[FAIL] execute_security_action missing")


# ============================================================
# SUMMARY
# ============================================================

print()
print("=" * 70)
print("        ZERO TRUST MODULE TEST COMPLETE")
print("=" * 70)
print()
