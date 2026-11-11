"""Safe adapter from Shadow Verdict API results to the SecureIoT Ryu action API.

This module is intentionally not wired into the live collector. Integrate it
only after the Ryu app supplies a current, unambiguous IP->MAC mapping. Dry-run
is the default; live blocking requires SHADOW_ENFORCE=1. Unblocking additionally
requires SHADOW_ALLOW_UNBLOCK=1.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Mapping, Optional

DEFAULT_ACTION_URL = "http://127.0.0.1:8080/network/action"
MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
ALLOWED_DECISIONS = {"BLOCK_DEVICE", "UNBLOCK_DEVICE"}


def _normalize_ip(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("IP address must be a string")
    return str(ipaddress.ip_address(value.strip()))


def _normalize_mac(value: object) -> str:
    if not isinstance(value, str) or not MAC_RE.fullmatch(value.strip()):
        raise ValueError("MAC must be a colon-separated six-byte address")
    return value.strip().lower()


def _protected_ips() -> set[str]:
    raw = os.getenv("SECUREIOT_PROTECTED_IPS", "")
    result: set[str] = set()
    for item in raw.split(","):
        item = item.strip()
        if item:
            result.add(_normalize_ip(item))
    return result


def process_verdict(
    verdict: Mapping[str, object],
    request_flow: Mapping[str, object],
    ip_to_mac: Mapping[str, str],
    *,
    dry_run: Optional[bool] = None,
    action_url: Optional[str] = None,
    control_token: Optional[str] = None,
    timeout_sec: float = 2.0,
) -> dict:
    """Validate a verdict and optionally request an explicit Ryu action.

    `request_flow` is the exact request sent to the Shadow API. `ip_to_mac`
    must be a current controller-learned mapping, not a guessed or stale map.
    No action is attempted if identity cannot be confirmed.
    """
    if not isinstance(verdict, Mapping) or not isinstance(request_flow, Mapping):
        raise ValueError("verdict and request_flow must be mappings")

    decision = str(verdict.get("decision", "")).strip().upper()
    if decision not in ALLOWED_DECISIONS:
        return {"status": "ignored", "reason": "no_valid_verdict"}

    requested_src = _normalize_ip(request_flow.get("src_ip"))
    returned_src = _normalize_ip(verdict.get("src_ip"))
    if requested_src != returned_src:
        return {"status": "rejected", "reason": "src_ip_mismatch"}

    if requested_src in _protected_ips():
        return {"status": "rejected", "reason": "protected_ip"}

    # Do not silently accept an ambiguous/stale mapping. Require the caller to
    # provide a current, exact key for the observed source address.
    candidate = ip_to_mac.get(requested_src)
    if candidate is None:
        return {"status": "rejected", "reason": "unknown_source_ip"}
    mac = _normalize_mac(candidate)

    if decision == "UNBLOCK_DEVICE" and os.getenv("SHADOW_ALLOW_UNBLOCK") != "1":
        return {"status": "rejected", "reason": "unblock_not_enabled"}

    if dry_run is None:
        dry_run = os.getenv("SHADOW_ENFORCE") != "1"

    payload = {
        "action": decision,
        "mac": mac,
        "ip": requested_src,
        "request_id": "shadow-%s-%s" % (int(time.time() * 1000), requested_src),
        "reason": str(verdict.get("reason") or "Shadow Verdict API verdict")[:300],
    }
    if dry_run:
        return {"status": "dry_run", "payload": payload}

    token = control_token or os.getenv("SECUREIOT_CONTROL_TOKEN", "").strip()
    if not token:
        return {"status": "rejected", "reason": "missing_control_token"}

    url = action_url or os.getenv("SECUREIOT_NETWORK_ACTION_URL", DEFAULT_ACTION_URL)
    if not url.startswith("http://127.0.0.1:") and not url.startswith("http://localhost:") and not url.startswith("https://"):
        return {"status": "rejected", "reason": "unsafe_action_url"}

    req = urllib.request.Request(
        url,
        data=json.dumps(payload, allow_nan=False).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-SecureIoT-Token": token,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as response:
            body = response.read(8192).decode("utf-8", errors="replace")
            try:
                parsed = json.loads(body)
            except ValueError:
                parsed = {"raw_response": body}
            return {"status": "submitted", "http_status": response.status,
                    "payload": payload, "network_result": parsed}
    except urllib.error.HTTPError as exc:
        return {"status": "network_api_error", "http_status": exc.code}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"status": "network_api_unreachable", "error": type(exc).__name__}
