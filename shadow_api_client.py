#!/usr/bin/env python3
"""Asynchronous Shadow API client for TrustFlow.

Continuous Shadow API client:
- Sends the exact 16-field API request.
- Keeps run_id and observation_id local.
- Stores submission, request, verdict, and enforcement audit events under:
  New_Datasets/raw/shadow_api/<session_uuid>.jsonl
- Only requests local enforcement when SHADOW_ENFORCE=1; Ryu applies strict
  allowlist, VLAN, identity, and block-origin checks before changing switches.
"""

import ipaddress
import json
import logging
import math
import os
import queue
import threading
import time
import uuid

from datetime import datetime, timezone
from pathlib import Path
import urllib.error
import urllib.request


LOG = logging.getLogger("ShadowAPI")

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

API_URL = os.environ.get("SHADOW_API_URL", "").strip()

TIMEOUT = 2.0
WORKER_COUNT = 4
MAX_QUEUE_SIZE = 256

# Minimum interval between request starts.
# This is a shared limit across all workers.
MIN_REQUEST_INTERVAL = 0.2

PROJECT_ROOT = Path(__file__).resolve().parent
SHADOW_API_DATA_DIR = (
    PROJECT_ROOT / "New_Datasets" / "raw" / "shadow_api"
)

FLOW_QUEUE = queue.Queue(maxsize=MAX_QUEUE_SIZE)

_WORKERS_STARTED = False
_WORKER_LOCK = threading.Lock()
_RATE_LOCK = threading.Lock()
_RESULT_LOCK = threading.Lock()
_JSONL_LOCK = threading.Lock()

_LAST_REQUEST_AT = 0.0

# Latest response diagnostics.
# These are global diagnostics, not per-flow results.
LAST_HTTP_STATUS = None
LAST_VERDICT = None
LAST_RESPONSE_ERROR = None


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _utc_now():
    """Return the current UTC timestamp in ISO-8601 format."""
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _get_api_url():
    """Read the API URL from the environment."""
    return os.environ.get("SHADOW_API_URL", API_URL).strip()


def _valid_run_id(run_id):
    """Accept only canonical UUIDs for run-specific file names."""
    try:
        parsed = uuid.UUID(str(run_id))
        return str(parsed) == str(run_id).lower()
    except (ValueError, TypeError, AttributeError):
        return False


def _json_safe_number(value):
    """Return True for finite numeric values."""
    try:
        return math.isfinite(float(value))
    except (TypeError, ValueError, OverflowError):
        return False


def _set_response_state(status=None, verdict=None, error=None):
    """Update the latest response diagnostics safely."""

    global LAST_HTTP_STATUS
    global LAST_VERDICT
    global LAST_RESPONSE_ERROR

    with _RESULT_LOCK:
        LAST_HTTP_STATUS = status
        LAST_VERDICT = verdict
        LAST_RESPONSE_ERROR = error


def _write_jsonl_result(metadata, result):
    """Append one per-flow result to its run-specific JSONL file."""

    run_id = metadata.get("run_id", "")
    observation_id = metadata.get("observation_id", "")

    if not _valid_run_id(run_id):
        LOG.warning(
            "SHADOW_API_LIVE cannot save result: invalid run_id"
        )
        return False

    if not observation_id:
        LOG.warning(
            "SHADOW_API_LIVE cannot save result: missing observation_id"
        )
        return False

    result_path = SHADOW_API_DATA_DIR / (run_id + ".jsonl")

    record = {
        "run_id": run_id,
        "observation_id": observation_id,
        "recorded_at": _utc_now(),
    }
    record.update(result)

    try:
        SHADOW_API_DATA_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        encoded = json.dumps(
            record,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )

        with _JSONL_LOCK:
            with result_path.open(
                "a",
                encoding="utf-8"
            ) as handle:
                handle.write(encoded + "\n")
                handle.flush()
                os.fsync(handle.fileno())

        return True

    except Exception as exc:
        LOG.exception(
            "SHADOW_API_LIVE JSONL write failed: %s",
            type(exc).__name__
        )
        return False



def _append_audit_event(metadata, event, details=None):
    """Append one immutable audit event to the run-specific JSONL file."""
    run_id = metadata.get("run_id", "")
    observation_id = metadata.get("observation_id", "")

    if not _valid_run_id(run_id) or not observation_id:
        return False

    record = {
        "run_id": run_id,
        "observation_id": observation_id,
        "recorded_at": _utc_now(),
        "event": event,
    }
    if details:
        record.update(details)

    try:
        SHADOW_API_DATA_DIR.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(
            record, ensure_ascii=False, allow_nan=False,
            separators=(",", ":"),
        )
        result_path = SHADOW_API_DATA_DIR / (run_id + ".jsonl")

        with _JSONL_LOCK:
            with result_path.open("a", encoding="utf-8") as handle:
                handle.write(encoded + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        return True

    except Exception as exc:
        LOG.exception("SHADOW_API_LIVE audit write failed: %s",
                      type(exc).__name__)
        return False


def _build_result(
    status=None,
    verdict=None,
    error=None,
    reason=None,
    confidence=None,
    response_src_ip=None,
    response_timestamp=None,
    response_body=None,
    latency_ms=None,
):
    """Build a JSON-serializable result record."""

    return {
        "http_status": status,
        "decision": verdict,
        "error": error,
        "reason": reason,
        "confidence": confidence,
        "response_src_ip": response_src_ip,
        "response_timestamp": response_timestamp,
        "response_body": response_body,
        "latency_ms": latency_ms,
    }


# ---------------------------------------------------------------------
# Worker startup
# ---------------------------------------------------------------------

def _start_workers():
    """Start the background workers once."""

    global _WORKERS_STARTED

    with _WORKER_LOCK:
        if _WORKERS_STARTED:
            return

        for index in range(WORKER_COUNT):
            worker = threading.Thread(
                target=_worker_loop,
                name="shadow-api-worker-%s" % (index + 1),
                daemon=True,
            )
            worker.start()

        _WORKERS_STARTED = True

        LOG.info(
            "SHADOW_API_LIVE workers_started=%s queue_capacity=%s",
            WORKER_COUNT,
            MAX_QUEUE_SIZE,
        )


# ---------------------------------------------------------------------
# API request
# ---------------------------------------------------------------------

def _send_payload(payload, api_key):
    """Send one flow and return its result.

    This request function only returns a validated verdict; the worker may
    separately forward it to the authenticated local Ryu guard if enabled.
    """

    url = _get_api_url()

    if not url.startswith("https://"):
        error = "invalid_or_non_https_api_url"
        _set_response_state(error=error)

        LOG.warning(
            "SHADOW_API_LIVE invalid HTTPS API URL; fail-open"
        )

        return _build_result(error=error)

    request = urllib.request.Request(
        url,
        data=json.dumps(
            payload,
            allow_nan=False,
        ).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
        },
        method="POST",
    )

    started_at = time.monotonic()

    try:
        with urllib.request.urlopen(
            request,
            timeout=TIMEOUT,
        ) as response:

            body = response.read(8192).decode(
                "utf-8",
                errors="replace",
            )

            status = response.status
            latency_ms = round(
                (time.monotonic() - started_at) * 1000,
                3,
            )

            if status != 200:
                error = "unexpected_http_status"
                _set_response_state(
                    status=status,
                    error=error,
                )

                LOG.warning(
                    "SHADOW_API_LIVE HTTP status=%s; fail-open",
                    status,
                )

                return _build_result(
                    status=status,
                    error=error,
                    response_body=body,
                    latency_ms=latency_ms,
                )

            try:
                result = json.loads(body)

            except (TypeError, ValueError):
                error = "invalid_json"
                _set_response_state(
                    status=status,
                    error=error,
                )

                LOG.warning(
                    "SHADOW_API_LIVE invalid JSON response; fail-open"
                )

                return _build_result(
                    status=status,
                    error=error,
                    response_body=body,
                    latency_ms=latency_ms,
                )

            if not isinstance(result, dict):
                error = "unexpected_response_type"
                _set_response_state(
                    status=status,
                    error=error,
                )

                return _build_result(
                    status=status,
                    error=error,
                    response_body=body,
                    latency_ms=latency_ms,
                )

            decision = str(
                result.get("decision", "")
            ).strip().upper()

            if decision not in (
                "BLOCK_DEVICE",
                "UNBLOCK_DEVICE",
            ):
                error = "invalid_verdict"
                _set_response_state(
                    status=status,
                    error=error,
                )

                LOG.warning(
                    "SHADOW_API_LIVE invalid verdict; fail-open"
                )

                return _build_result(
                    status=status,
                    error=error,
                    response_body=body,
                    latency_ms=latency_ms,
                )

            reason = result.get("reason")
            confidence = result.get("confidence")
            response_src_ip = result.get("src_ip")
            response_timestamp = result.get("timestamp")

            _set_response_state(
                status=status,
                verdict=decision,
                error=None,
            )

            LOG.info(
                "SHADOW_API_LIVE status=%s verdict=%s "
                "reason=%s confidence=%s src_ip=%s dst_ip=%s "
                "latency_ms=%s",
                status,
                decision,
                str(reason or "")[:300],
                confidence,
                payload["src_ip"],
                payload["dst_ip"],
                latency_ms,
            )

            # Enforcement is deliberately performed by a separate local guard,
            # never in this API response parser.

            return _build_result(
                status=status,
                verdict=decision,
                reason=reason,
                confidence=confidence,
                response_src_ip=response_src_ip,
                response_timestamp=response_timestamp,
                response_body=body,
                latency_ms=latency_ms,
            )

    except urllib.error.HTTPError as exc:
        latency_ms = round(
            (time.monotonic() - started_at) * 1000,
            3,
        )

        try:
            error_body = exc.read(8192).decode(
                "utf-8",
                errors="replace",
            )
        except Exception:
            error_body = None

        error = "http_error"

        _set_response_state(
            status=exc.code,
            error=error,
        )

        LOG.warning(
            "SHADOW_API_LIVE HTTP %s; fail-open",
            exc.code,
        )

        return _build_result(
            status=exc.code,
            error=error,
            response_body=error_body,
            latency_ms=latency_ms,
        )

    except urllib.error.URLError as exc:
        latency_ms = round(
            (time.monotonic() - started_at) * 1000,
            3,
        )

        error = "connection_error"
        _set_response_state(error=error)

        LOG.warning(
            "SHADOW_API_LIVE connection_error=%s; fail-open",
            type(exc.reason).__name__
            if exc.reason else "unknown",
        )

        return _build_result(
            error=error,
            latency_ms=latency_ms,
        )

    except Exception as exc:
        latency_ms = round(
            (time.monotonic() - started_at) * 1000,
            3,
        )

        error = type(exc).__name__
        _set_response_state(error=error)

        LOG.warning(
            "SHADOW_API_LIVE request_failed=%s; fail-open",
            error,
        )

        return _build_result(
            error=error,
            latency_ms=latency_ms,
        )


# ---------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------

def _apply_shadow_verdict(request_payload, result, metadata):
    """Send a valid API verdict to the local Ryu guard; never fail closed."""
    if os.environ.get("SHADOW_ENFORCE") != "1":
        return {"status": "disabled"}
    if result.get("http_status") != 200 or result.get("decision") not in (
        "BLOCK_DEVICE", "UNBLOCK_DEVICE"
    ):
        return {"status": "skipped", "reason": "no_valid_http_200_verdict"}

    token = os.environ.get("SECUREIOT_CONTROL_TOKEN", "").strip()
    if not token:
        return {"status": "rejected", "reason": "missing_control_token"}

    url = os.environ.get(
        "SHADOW_ENFORCEMENT_URL",
        "http://127.0.0.1:8080/shadow/verdict",
    ).strip()
    if not (url.startswith("http://127.0.0.1:") or url.startswith("http://localhost:")):
        return {"status": "rejected", "reason": "enforcement_url_must_be_loopback"}

    body = {
        "decision": result.get("decision"),
        "requested_src_ip": request_payload.get("src_ip"),
        "response_src_ip": result.get("response_src_ip"),
        "reason": result.get("reason"),
        "confidence": result.get("confidence"),
        "request_id": metadata.get("observation_id"),
        "observation_id": metadata.get("observation_id"),
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(body, allow_nan=False).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-SecureIoT-Token": token,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            text = response.read(8192).decode("utf-8", errors="replace")
            try:
                response_body = json.loads(text)
            except ValueError:
                response_body = {"raw_response": text}
            return {
                "status": "submitted" if response.status == 200 else "rejected",
                "http_status": response.status,
                "network_result": response_body,
            }
    except urllib.error.HTTPError as exc:
        return {"status": "network_api_error", "http_status": exc.code}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"status": "network_api_unreachable", "error": type(exc).__name__}


def _worker_loop():
    """Consume queued flows, send them asynchronously, and audit enforcement."""
    global _LAST_REQUEST_AT

    while True:
        item = FLOW_QUEUE.get()
        try:
            payload, api_key, metadata, ready_event, send_gate = item

            # Wait until the queued audit event has been persisted.
            ready_event.wait()
            if not send_gate.get("allow_send", False):
                continue

            with _RATE_LOCK:
                now = time.monotonic()
                wait = MIN_REQUEST_INTERVAL - (now - _LAST_REQUEST_AT)
                if wait > 0:
                    time.sleep(wait)
                _LAST_REQUEST_AT = time.monotonic()

            result = _send_payload(payload, api_key)

            if not _append_audit_event(
                metadata,
                "api_result",
                {
                    "request_payload": payload,
                    "api_result": result,
                },
            ):
                LOG.error("SHADOW_API_LIVE result audit failed")

            enforcement_result = _apply_shadow_verdict(payload, result, metadata)
            if not _append_audit_event(
                metadata,
                "enforcement_result",
                {"enforcement_result": enforcement_result},
            ):
                LOG.error("SHADOW_API_LIVE enforcement audit failed")

        except Exception as exc:
            LOG.warning(
                "SHADOW_API_LIVE worker_error=%s; fail-open",
                type(exc).__name__,
            )
            try:
                if isinstance(item, tuple) and len(item) == 5:
                    payload, _, metadata, _, _ = item
                    _append_audit_event(
                        metadata,
                        "worker_error",
                        {
                            "request_payload": payload,
                            "error": type(exc).__name__,
                        },
                    )
            except Exception:
                LOG.exception("SHADOW_API_LIVE worker audit failed")

        finally:
            FLOW_QUEUE.task_done()


# ---------------------------------------------------------------------
# Public submission function
# ---------------------------------------------------------------------

def submit_flow_live(flow):
    """Validate and queue one TCP/UDP flow for Shadow API analysis.

    Required local metadata:
        run_id
        observation_id

    Returns:
        True: flow accepted into the local queue.
        False: disabled, invalid, or queue full.

    True does NOT mean the external API has processed the flow.
    """

    if os.environ.get("SHADOW_API_LIVE") != "1":
        return False

    api_url = _get_api_url()

    if not api_url.startswith("https://"):
        LOG.warning(
            "SHADOW_API_LIVE HTTPS API URL missing or invalid; fail-open"
        )
        return False

    api_key = os.environ.get(
        "SHADOW_API_KEY",
        "",
    ).strip()

    if not api_key:
        LOG.warning(
            "SHADOW_API_LIVE API key missing; fail-open"
        )
        return False

    if not isinstance(flow, dict):
        return False

    try:
        src_ip = str(flow["src_ip"]).strip()
        dst_ip = str(flow["dst_ip"]).strip()

        # These two identifiers are local metadata only.
        run_id = str(flow["run_id"]).strip()
        observation_id = str(
            flow["observation_id"]
        ).strip()

        proto = int(flow["ip_proto"])
        dst_port = int(flow["dst_port"])

        packets = int(flow["packet_count"])
        byte_count = int(flow["byte_count"])

        duration = float(flow["duration_sec"])
        packet_rate = float(flow["packet_rate"])
        byte_rate = float(flow["byte_rate"])

        dpid = int(flow["switch_dpid"])
        priority = int(flow.get("priority", 0))

    except (
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
    ):
        LOG.warning(
            "SHADOW_API_LIVE invalid flow fields; flow rejected"
        )
        return False

    # Validate run identity before using it in a file path.
    if not _valid_run_id(run_id) or not observation_id:
        LOG.warning(
            "SHADOW_API_LIVE missing or invalid run metadata; flow rejected"
        )
        return False

    # Validate IP addresses.
    try:
        ipaddress.ip_address(src_ip)
        ipaddress.ip_address(dst_ip)
    except ValueError:
        LOG.warning(
            "SHADOW_API_LIVE invalid IP address; flow rejected"
        )
        return False

    if proto not in (6, 17):
        return False

    if not 1 <= dst_port <= 65535:
        return False

    if packets <= 0 or byte_count < 0:
        return False

    if not _json_safe_number(duration):
        return False

    if not _json_safe_number(packet_rate):
        return False

    if not _json_safe_number(byte_rate):
        return False

    if duration <= 0:
        return False

    if packet_rate < 0 or byte_rate < 0:
        return False

    if dpid < 0 or priority < 0:
        return False

    # Exact API request contract: 16 fields.
    # run_id and observation_id are deliberately NOT included.
    payload = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": {
            6: "TCP",
            17: "UDP",
        }[proto],
        "packet_count": packets,
        "byte_count": byte_count,
        "packet_rate": packet_rate,
        "byte_rate": byte_rate,
        "duration_sec": duration,
        "switch_dpid": dpid,
        "priority": priority,
        "timestamp": _utc_now(),
        "ip_proto": proto,
        "flow_duration": duration,
        "total_pkts": packets,
        "avg_packet_size": byte_count / max(packets, 1),
    }

    # Local metadata travels with the queued item, not the API body.
    metadata = {
        "run_id": run_id,
        "observation_id": observation_id,
    }

    # Save the exact request locally before it can reach the API.
    if not _append_audit_event(
        metadata,
        "submission_attempt",
        {"request_payload": payload},
    ):
        LOG.error("SHADOW_API_LIVE local audit unavailable; not queued")
        return False

    _start_workers()

    ready_event = threading.Event()
    send_gate = {"allow_send": False}

    try:
        FLOW_QUEUE.put_nowait(
            (payload, api_key, metadata, ready_event, send_gate)
        )
    except queue.Full:
        _append_audit_event(metadata, "queue_full")
        LOG.warning(
            "SHADOW_API_LIVE queue_full run_id=%s observation_id=%s",
            run_id, observation_id,
        )
        return False

    # Worker cannot send until this event is durably recorded.
    queued_saved = _append_audit_event(metadata, "queued")
    send_gate["allow_send"] = bool(queued_saved)
    ready_event.set()

    if not queued_saved:
        LOG.error("SHADOW_API_LIVE queued audit failed; flow not sent")
        return False

    LOG.info(
        "SHADOW_API_LIVE queued run_id=%s observation_id=%s "
        "queue_size=%s",
        run_id, observation_id, FLOW_QUEUE.qsize(),
    )
    return True
