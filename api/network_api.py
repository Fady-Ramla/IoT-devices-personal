"""Compatibility REST controller for Zero Trust -> network actions.

WARNING: traffic_monitor_merged.py already registers POST /network/action. Do
NOT load both in the same Ryu/WSGI app (duplicate route). Use this module only
when the controller is NOT running traffic_monitor_merged.py.

The active Ryu app currently registers the equivalent route in
traffic_monitor_merged.py. This module intentionally implements the same
payload contract so that it can be used independently without drifting from
that route:
  * POST /network/action
  * X-SecureIoT-Token header
  * host_ip (or ip) for score/state/reroute actions
  * mac plus optional ip/host_ip for explicit block/unblock actions
"""

import hmac
import json

from ryu.app.wsgi import ControllerBase, route
from webob import Response


class NetworkActionController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.traffic_monitor = data.get("traffic_monitor")

    @route("network_action", "/network/action", methods=["POST"])
    def network_action(self, req, **kwargs):
        monitor = self.traffic_monitor
        if monitor is None:
            return self._response(503, {
                "success": False,
                "status": "unavailable",
                "message": "TrafficMonitorMerged is not available",
            })

        expected_token = getattr(monitor, "control_token", "")
        supplied_token = req.headers.get("X-SecureIoT-Token", "")
        if not expected_token:
            return self._response(503, {
                "success": False,
                "status": "unavailable",
                "message": "Zero Trust control token is not configured",
            })
        if not supplied_token or not hmac.compare_digest(supplied_token, expected_token):
            return self._response(401, {
                "success": False,
                "status": "unauthorized",
                "message": "Valid Zero Trust control token required",
            })

        try:
            data = json.loads(req.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, AttributeError) as exc:
            return self._response(400, {
                "success": False, "status": "error",
                "message": "Invalid JSON body", "details": str(exc),
            })
        if not isinstance(data, dict):
            return self._response(400, {
                "success": False, "status": "error",
                "message": "JSON body must be an object",
            })

        action = str(data.get("action") or "").strip().upper()
        if not action:
            return self._response(400, {
                "success": False, "status": "error", "message": "action is required",
            })

        host_ip = data.get("ip") or data.get("host_ip") or data.get("src_ip")
        mac = data.get("mac")
        request_id = data.get("request_id")
        if action in ("BLOCK_DEVICE", "UNBLOCK_DEVICE"):
            if not mac:
                return self._response(400, {
                    "success": False, "status": "error",
                    "message": "mac is required for device block actions",
                })
        elif not host_ip:
            return self._response(400, {
                "success": False, "status": "error",
                "message": "ip (or host_ip) is required for this action",
            })

        try:
            result = monitor.execute_security_action(
                host_ip=host_ip,
                mac=mac,
                action=action,
                request_id=request_id,
                trust_state=data.get("trust_state"),
                trust_score=data.get("trust_score"),
                reason=data.get("reason"),
            )
        except ValueError as exc:
            return self._response(400, {
                "success": False, "status": "error", "message": str(exc),
            })
        except Exception:
            monitor.logger.exception("REST network action failed")
            return self._response(500, {
                "success": False, "status": "error",
                "message": "Internal network error",
            })

        return self._response(200 if result.get("success") else 400, result)

    @staticmethod
    def _response(status, payload):
        return Response(
            status=status,
            content_type="application/json",
            charset="utf-8",
            body=json.dumps(payload).encode("utf-8"),
        )
