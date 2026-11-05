# api/network_api.py
# =============================================================
# TrustFlow - Network Action REST API
#
# Responsibilities:
#   - Receive Security decisions through REST
#   - Validate the request
#   - Resolve src_ip -> host_ip
#   - Delegate the final action to TrafficMonitorMerged
#
# IMPORTANT:
#   This API does NOT:
#   - calculate Trust Score
#   - run AI
#   - calculate Dijkstra
#   - discover topology
#   - install OpenFlow routing rules directly
#
# TrafficMonitorMerged is responsible for executing the
# network action, while TopologyMonitor owns topology/rerouting.
# =============================================================

import json

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import route
from webob import Response


class NetworkActionController(ControllerBase):
    """
    REST controller for Security -> Network actions.

    Endpoint:
        POST /network/action
    """

    def __init__(self, req, link, data, **config):
        super(NetworkActionController, self).__init__(
            req,
            link,
            data,
            **config
        )

        self.traffic_monitor = data.get(
            "traffic_monitor"
        )

    # =========================================================
    # POST /network/action
    # =========================================================

    @route(
        "network_action",
        "/network/action",
        methods=["POST"]
    )
    def network_action(self, req, **kwargs):

        # -----------------------------------------------------
        # Make sure TrafficMonitor is available
        # -----------------------------------------------------

        if self.traffic_monitor is None:
            return Response(
                status=500,
                content_type="application/json",
                body=json.dumps({
                    "status": "error",
                    "message": "TrafficMonitorMerged is not available"
                }).encode("utf-8")
            )

        # -----------------------------------------------------
        # Parse JSON body
        # -----------------------------------------------------

        try:
            if not req.body:
                raise ValueError("Request body is empty")

            data = json.loads(
                req.body.decode("utf-8")
            )

        except Exception as exc:
            return Response(
                status=400,
                content_type="application/json",
                body=json.dumps({
                    "status": "error",
                    "message": "Invalid JSON body",
                    "details": str(exc)
                }).encode("utf-8")
            )

        # -----------------------------------------------------
        # Basic validation
        # -----------------------------------------------------

        if not isinstance(data, dict):
            return Response(
                status=400,
                content_type="application/json",
                body=json.dumps({
                    "status": "error",
                    "message": "JSON body must be an object"
                }).encode("utf-8")
            )

        # -----------------------------------------------------
        # Required fields
        # -----------------------------------------------------

        action = data.get(
            "action"
        )

        src_ip = data.get(
            "src_ip"
        )

        request_id = data.get(
            "request_id"
        )

        if not action:
            return Response(
                status=400,
                content_type="application/json",
                body=json.dumps({
                    "status": "error",
                    "message": "action is required"
                }).encode("utf-8")
            )

        if not src_ip:
            return Response(
                status=400,
                content_type="application/json",
                body=json.dumps({
                    "status": "error",
                    "message": "src_ip is required"
                }).encode("utf-8")
            )

        # -----------------------------------------------------
        # Network identity
        #
        # Security sends src_ip.
        # TrafficMonitor execution uses host_ip.
        # -----------------------------------------------------

        host_ip = src_ip

        # -----------------------------------------------------
        # Optional Security information
        # -----------------------------------------------------

        trust_score = data.get(
            "trust_score"
        )

        trust_state = data.get(
            "trust_state"
        )

        severity = data.get(
            "severity"
        )

        reason = data.get(
            "reason"
        )

        # -----------------------------------------------------
        # Execute Security decision
        #
        # NOTE:
        # severity is intentionally NOT passed here because
        # TrafficMonitorMerged.execute_security_action()
        # currently does not accept a severity argument.
        # -----------------------------------------------------

        try:

            status = (
                self.traffic_monitor
                .execute_security_action(
                    request_id=request_id,
                    host_ip=host_ip,
                    action=action,
                    trust_score=trust_score,
                    trust_state=trust_state,
                    reason=reason
                )
            )

        except ValueError as exc:

            return Response(
                status=400,
                content_type="application/json",
                body=json.dumps({
                    "status": "error",
                    "message": str(exc)
                }).encode("utf-8")
            )

        except Exception as exc:

            self.traffic_monitor.logger.exception(
                "Network action execution failed"
            )

            return Response(
                status=500,
                content_type="application/json",
                body=json.dumps({
                    "status": "failed",
                    "request_id": request_id,
                    "error": "Internal network error",
                    "details": str(exc)
                }).encode("utf-8")
            )

        # -----------------------------------------------------
        # Successful execution
        # -----------------------------------------------------

        return Response(
            status=200,
            content_type="application/json",
            body=json.dumps({
                "status": "success",
                "request_id": request_id,
                "action": str(action).upper(),
                "src_ip": src_ip,
                "host_ip": host_ip,
                "result": status
            }).encode("utf-8")
        )

