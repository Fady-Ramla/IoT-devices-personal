#!/usr/bin/env python3
"""Topology-change consumer for resilience and self-healing."""

from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls

from topology_monitor import EventTopologyChanged


class ResilienceEngine(app_manager.RyuApp):
    """
    Orchestrate network recovery after physical topology changes.

    Responsibilities:
      - Receive topology-change events
      - Detect failed links
      - Trigger recovery in TopologyMonitor

    Does NOT:
      - calculate paths
      - install OpenFlow rules
      - make security decisions
      - modify Zero Trust state

    Path selection: PathEngine
    Forwarding / OpenFlow: TopologyMonitor
    Recovery orchestration: ResilienceEngine
    """

    _CONTEXTS = {}

    def __init__(self, *args, **kwargs):
        super(ResilienceEngine, self).__init__(*args, **kwargs)

        # RyuApp reserves ``events`` for its internal event queue.
        self.event_history = []
        self.last_event = None

        self.logger.info("ResilienceEngine initialized")

    @set_ev_cls(EventTopologyChanged)
    def topology_changed_handler(self, ev):
        """Handle physical topology changes and trigger recovery."""
        record = {
            "old_signature": ev.old_signature,
            "new_signature": ev.new_signature,
            "added": sorted(ev.added),
            "removed": sorted(ev.removed),
            "topology_ready": ev.topology_ready,
        }

        self.last_event = record
        self.event_history.append(record)
        self.event_history = self.event_history[-100:]

        self.logger.warning(
            "RESILIENCE EVENT RECEIVED: added=%s removed=%s ready=%s",
            record["added"],
            record["removed"],
            record["topology_ready"],
        )

        if not ev.topology_ready:
            self.logger.warning(
                "SELF-HEALING: Topology is not ready; recovery skipped"
            )
            return

        # A recovery action is needed only when links were removed.
        if not ev.removed:
            self.logger.info(
                "SELF-HEALING: No failed links; recovery not required"
            )
            return

        topology_monitor = app_manager.lookup_service_brick(
            "TopologyMonitor"
        )

        if topology_monitor is None:
            self.logger.error(
                "SELF-HEALING: TopologyMonitor service not available"
            )
            return

        self.logger.warning(
            "SELF-HEALING: Starting recovery for failed links=%s",
            sorted(ev.removed),
        )

        try:
            result = topology_monitor.reroute_active_flows(
                failed_links=ev.removed
            )
        except Exception:
            self.logger.exception(
                "SELF-HEALING: Recovery execution failed"
            )
            return

        if result.get("success"):
            self.logger.warning(
                "SELF-HEALING: SUCCESS rerouted=%d failed=%d",
                result.get("rerouted", 0),
                result.get("failed", 0),
            )
        else:
            self.logger.error(
                "SELF-HEALING: PARTIAL/FAILED rerouted=%d failed=%d",
                result.get("rerouted", 0),
                result.get("failed", 0),
            )

    def get_status(self):
        """Return the latest resilience state."""
        return {
            "event_count": len(self.event_history),
            "last_event": self.last_event,
        }
