#!/usr/bin/env python3
"""Topology-change consumer for resilience and self-healing."""

from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls

from topology_monitor import EventTopologyChanged
import time


class ResilienceEngine(app_manager.RyuApp):
    """Orchestrate recovery after physical topology changes."""

    _CONTEXTS = {}

    def __init__(self, *args, **kwargs):
        super(ResilienceEngine, self).__init__(*args, **kwargs)
        self.event_history = []
        self.last_event = None
        self.recovery_history = []
        self.last_recovery = None
        self.logger.info("ResilienceEngine initialized")

    @set_ev_cls(EventTopologyChanged)
    def topology_changed_handler(self, ev):
        record = {
            "old_signature": ev.old_signature,
            "new_signature": ev.new_signature,
            "added": sorted(ev.added),
            "removed": sorted(ev.removed),
            "topology_ready": ev.topology_ready,
            "timestamp": time.time(),
        }
        self.last_event = record
        self.event_history.append(record)
        self.event_history = self.event_history[-100:]
        self.logger.warning(
            "RESILIENCE EVENT RECEIVED: added=%s removed=%s ready=%s",
            record["added"], record["removed"], record["topology_ready"],
        )

        if not ev.topology_ready or not ev.removed:
            return

        topology_monitor = app_manager.lookup_service_brick("TopologyMonitor")
        if topology_monitor is None:
            self.logger.error("SELF-HEALING: TopologyMonitor unavailable")
            return

        try:
            result = topology_monitor.reroute_active_flows(
                failed_links=ev.removed
            )
        except Exception:
            self.logger.exception("SELF-HEALING: Recovery execution failed")
            return

        recovery = {
            "timestamp": time.time(),
            "failed_links": sorted(ev.removed),
            "success": bool(result.get("success")),
            "rerouted": result.get("rerouted", 0),
            "failed": result.get("failed", 0),
        }
        self.last_recovery = recovery
        self.recovery_history.append(recovery)
        self.recovery_history = self.recovery_history[-100:]

        if result.get("success"):
            self.logger.warning(
                "SELF-HEALING: SUCCESS rerouted=%d failed=%d",
                result.get("rerouted", 0), result.get("failed", 0),
            )
        else:
            self.logger.error(
                "SELF-HEALING: PARTIAL/FAILED rerouted=%d failed=%d",
                result.get("rerouted", 0), result.get("failed", 0),
            )

    def get_status(self):
        return {
            "event_count": len(self.event_history),
            "recovery_count": len(self.recovery_history),
            "last_event": self.last_event,
            "last_event_at": self.last_event.get("timestamp") if self.last_event else None,
            "last_recovery": self.last_recovery,
        }
