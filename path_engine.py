#!/usr/bin/env python3
"""Routing and Traffic Engineering engine for the TrustFlow project.

This module intentionally has no Ryu or Mininet dependency. It consumes an
operational NetworkX graph and returns path decisions; OpenFlow installation
belongs to another component.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Hashable, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

import networkx as nx

Node = Hashable
Edge = Tuple[Node, Node]


@dataclass(frozen=True)
class PathWeights:
    """Weights used by the initial explainable path-cost function."""

    hop: float = 1.0
    utilization: float = 3.0
    congestion: float = 2.0
    failure: float = 1000.0


@dataclass(frozen=True)
class PathEvaluation:
    path: Tuple[Node, ...]
    cost: float
    hop_cost: float
    utilization_cost: float
    congestion_cost: float
    failure_cost: float
    max_utilization: float
    shared_edges: Tuple[Edge, ...] = field(default_factory=tuple)
    reason: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "path": list(self.path),
            "cost": self.cost,
            "hop_cost": self.hop_cost,
            "utilization_cost": self.utilization_cost,
            "congestion_cost": self.congestion_cost,
            "failure_cost": self.failure_cost,
            "max_utilization": self.max_utilization,
            "shared_edges": [list(edge) for edge in self.shared_edges],
            "reason": self.reason,
        }


class PathEngine:
    """Select valid primary and backup paths from an operational graph.

    The engine does not discover topology, classify security events, install
    OpenFlow rules, or verify connectivity. It only computes path decisions.
    """

    def __init__(
        self,
        weights: Optional[Union[PathWeights, nx.Graph]] = None,
        max_candidates: int = 20,
        reroute_threshold: float = 0.05,
        congestion_threshold: float = 0.80,
    ) -> None:
        if max_candidates < 1:
            raise ValueError("max_candidates must be positive")
        if reroute_threshold < 0:
            raise ValueError("reroute_threshold cannot be negative")
        if congestion_threshold < 0:
            raise ValueError("congestion_threshold cannot be negative")
        initial_graph = weights if isinstance(weights, nx.Graph) else None
        self.weights = (
            weights if isinstance(weights, PathWeights) else PathWeights()
        )
        self.max_candidates = max_candidates
        self.reroute_threshold = reroute_threshold
        self.congestion_threshold = congestion_threshold
        self.graph = nx.Graph()
        self.network_state: Dict[Edge, Dict[str, float]] = {}
        if initial_graph is not None:
            self.set_graph(initial_graph)

    # --------------------------------------------------------------
    # Compatibility API for the stateful TopologyMonitor callers.
    # The structured get_best_path/get_backup_path APIs remain the
    # canonical Routing/TE interface.
    # --------------------------------------------------------------

    def set_graph(self, graph: nx.Graph) -> None:
        if not isinstance(graph, nx.Graph):
            raise TypeError("graph must be a NetworkX graph")
        self.graph = graph.copy()
        self._apply_compatibility_metrics()

    def update_link_metric(
        self,
        src_dpid: Node,
        dst_dpid: Node,
        utilization: Optional[float] = None,
        rate_bps: Optional[float] = None,
        capacity_bps: Optional[float] = None,
    ) -> None:
        edge = self._edge_key(src_dpid, dst_dpid)
        metric = self.network_state.setdefault(edge, {})
        if utilization is not None:
            metric["utilization"] = self._normalize_utilization(utilization)
        if rate_bps is not None:
            metric["rate_bps"] = max(0.0, float(rate_bps))
        if capacity_bps is not None and float(capacity_bps) > 0:
            metric["capacity_bps"] = float(capacity_bps)
        self._apply_compatibility_metrics()

    def update_link_metrics(self, metrics: Iterable[Mapping[str, Any]]) -> None:
        for item in metrics:
            self.update_link_metric(
                item["src_dpid"],
                item["dst_dpid"],
                utilization=item.get("utilization"),
                rate_bps=item.get("rate_bps"),
                capacity_bps=item.get("capacity_bps"),
            )

    def _apply_compatibility_metrics(self) -> None:
        for src, dst in self.graph.edges():
            metric = self.network_state.get(self._edge_key(src, dst), {})
            utilization = self._normalize_utilization(
                metric.get("utilization", 0.0)
            )
            if "utilization" not in metric:
                rate = metric.get("rate_bps")
                capacity = metric.get("capacity_bps")
                if rate is not None and capacity:
                    utilization = self._normalize_utilization(
                        float(rate) / float(capacity)
                    )
            weight = 1.0 + (4.0 * utilization)
            if utilization >= 0.95:
                weight += 20.0
            self.graph[src][dst]["weight"] = weight

    def find_path(self, src_dpid: Node, dst_dpid: Node) -> Optional[List[Node]]:
        if src_dpid not in self.graph or dst_dpid not in self.graph:
            return None
        try:
            return list(nx.shortest_path(
                self.graph,
                source=src_dpid,
                target=dst_dpid,
                weight="weight",
            ))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def candidate_paths(
        self,
        src_dpid: Node,
        dst_dpid: Node,
        limit: int = 3,
    ) -> List[List[Node]]:
        if src_dpid not in self.graph or dst_dpid not in self.graph:
            return []
        try:
            paths = nx.shortest_simple_paths(
                self.graph,
                src_dpid,
                dst_dpid,
                weight="weight",
            )
            return [list(path) for _, path in zip(
                range(max(1, int(limit))), paths
            )]
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def status(self) -> Dict[str, Any]:
        return {
            "nodes": self.graph.number_of_nodes(),
            "links": self.graph.number_of_edges(),
            "metrics": {
                "%s-%s" % edge: dict(metric)
                for edge, metric in sorted(
                    self.network_state.items(), key=lambda item: repr(item[0])
                )
            },
            "congestion_threshold": self.congestion_threshold,
            "reroute_threshold": self.reroute_threshold,
        }

    @staticmethod
    def _edge_key(u: Node, v: Node) -> Edge:
        """Return a stable undirected edge key for a NetworkX graph."""
        return (u, v) if repr(u) <= repr(v) else (v, u)

    @classmethod
    def _path_edges(cls, path: Sequence[Node]) -> set[Edge]:
        return {
            cls._edge_key(path[index], path[index + 1])
            for index in range(len(path) - 1)
        }

    @staticmethod
    def _normalize_utilization(value: Any) -> float:
        """Normalize utilization supplied as 0..1 or 0..100 percentage."""
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return 0.0
        if numeric > 1.0:
            numeric /= 100.0
        return min(1.0, max(0.0, numeric))

    def _edge_utilization(
        self,
        network_state: Optional[Mapping[Any, Any]],
        u: Node,
        v: Node,
    ) -> float:
        if not network_state:
            return 0.0

        candidates = (
            (u, v),
            (v, u),
            self._edge_key(u, v),
            f"{u}-{v}",
            f"{v}-{u}",
        )
        for key in candidates:
            if key not in network_state:
                continue
            value = network_state[key]
            if isinstance(value, Mapping):
                value = value.get("utilization", value.get("utilisation", 0.0))
            return self._normalize_utilization(value)
        return 0.0

    def _build_operational_graph(
        self,
        graph: nx.Graph,
        unavailable_links: Optional[Iterable[Edge]] = None,
        unavailable_nodes: Optional[Iterable[Node]] = None,
    ) -> nx.Graph:
        if graph is None:
            raise ValueError("graph is required")
        if not isinstance(graph, nx.Graph):
            raise TypeError("graph must be a NetworkX graph")

        operational = graph.copy()
        blocked_edges = {
            self._edge_key(u, v) for u, v in (unavailable_links or ())
        }
        operational.remove_edges_from(
            (u, v)
            for u, v in operational.edges()
            if self._edge_key(u, v) in blocked_edges
        )
        blocked_nodes = set(unavailable_nodes or ())
        if blocked_nodes:
            operational.remove_nodes_from(blocked_nodes)
        return operational

    def get_candidate_paths(
        self,
        src: Node,
        dst: Node,
        graph: nx.Graph,
        *,
        unavailable_links: Optional[Iterable[Edge]] = None,
        unavailable_nodes: Optional[Iterable[Node]] = None,
        max_candidates: Optional[int] = None,
    ) -> List[List[Node]]:
        """Return simple candidate paths ordered by hop count."""
        operational = self._build_operational_graph(
            graph, unavailable_links, unavailable_nodes
        )
        if src not in operational or dst not in operational:
            return []
        if src == dst:
            return [[src]]

        limit = self.max_candidates if max_candidates is None else max_candidates
        if limit < 1:
            raise ValueError("max_candidates must be positive")
        try:
            paths = nx.shortest_simple_paths(operational, src, dst)
            candidates = []
            for path in paths:
                path_list = list(path)
                if self.is_path_valid(path_list, graph=operational):
                    candidates.append(path_list)
                if len(candidates) >= limit:
                    break
            return candidates
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def evaluate_path(
        self,
        path: Sequence[Node],
        *,
        network_state: Optional[Mapping[Any, Any]] = None,
        unavailable_links: Optional[Iterable[Edge]] = None,
        reference_path: Optional[Sequence[Node]] = None,
    ) -> PathEvaluation:
        if not path:
            raise ValueError("path cannot be empty")

        blocked = {
            self._edge_key(u, v) for u, v in (unavailable_links or ())
        }
        edges = self._path_edges(path)
        utilizations = [
            self._edge_utilization(network_state, u, v)
            for u, v in zip(path, path[1:])
        ]
        max_utilization = max(utilizations, default=0.0)
        utilization_cost = sum(utilizations)
        congestion_cost = sum(
            max(0.0, utilization - self.congestion_threshold)
            for utilization in utilizations
        )
        failure_cost = self.weights.failure if edges & blocked else 0.0
        shared_edges = tuple(
            sorted(edges & self._path_edges(reference_path or ()), key=repr)
        )
        cost = (
            self.weights.hop * max(0, len(path) - 1)
            + self.weights.utilization * utilization_cost
            + self.weights.congestion * congestion_cost
            + failure_cost
        )
        reason = "shortest valid path"
        if max_utilization > self.congestion_threshold:
            reason = "path has congestion penalty"
        if failure_cost:
            reason = "path contains unavailable link"
        return PathEvaluation(
            path=tuple(path),
            cost=cost,
            hop_cost=max(0, len(path) - 1),
            utilization_cost=utilization_cost,
            congestion_cost=congestion_cost,
            failure_cost=failure_cost,
            max_utilization=max_utilization,
            shared_edges=shared_edges,
            reason=reason,
        )

    def is_path_valid(
        self,
        path: Sequence[Node],
        *,
        graph: Optional[nx.Graph] = None,
        unavailable_links: Optional[Iterable[Edge]] = None,
        unavailable_nodes: Optional[Iterable[Node]] = None,
    ) -> bool:
        """Return whether a path is usable under the current constraints."""
        if not path:
            return False
        if len(path) != len(set(path)):
            return False
        blocked_nodes = set(unavailable_nodes or ())
        if blocked_nodes and any(node in blocked_nodes for node in path):
            return False
        blocked = {
            self._edge_key(u, v) for u, v in (unavailable_links or ())
        }
        if self._path_edges(path) & blocked:
            return False
        if graph is None:
            return True

        if any(node not in graph for node in path):
            return False

        return all(graph.has_edge(u, v) for u, v in zip(path, path[1:]))

    def select_primary_backup(
        self,
        candidates: Sequence[Sequence[Node]],
        *,
        network_state: Optional[Mapping[Any, Any]] = None,
        unavailable_links: Optional[Iterable[Edge]] = None,
    ) -> Tuple[Optional[PathEvaluation], Optional[PathEvaluation], List[PathEvaluation]]:
        valid_candidates = [
            path
            for path in candidates
            if self.is_path_valid(
                path,
                unavailable_links=unavailable_links,
            )
        ]
        evaluations = [
            self.evaluate_path(
                path,
                network_state=network_state,
                unavailable_links=unavailable_links,
            )
            for path in valid_candidates
        ]
        evaluations.sort(key=lambda evaluation: (evaluation.cost, len(evaluation.path)))
        if not evaluations:
            return None, None, []

        primary = evaluations[0]
        primary_edges = self._path_edges(primary.path)
        edge_disjoint_backups = [
            evaluation
            for evaluation in evaluations[1:]
            if not (self._path_edges(evaluation.path) & primary_edges)
        ]
        backup_candidates = sorted(
            edge_disjoint_backups or evaluations[1:],
            key=lambda evaluation: (
                len(self._path_edges(evaluation.path) & primary_edges),
                evaluation.cost,
                len(evaluation.path),
            ),
        )
        backup = backup_candidates[0] if backup_candidates else None
        return primary, backup, evaluations

    def get_best_path(
        self,
        src: Node,
        dst: Node,
        graph: nx.Graph,
        *,
        flow_context: Optional[Mapping[str, Any]] = None,
        network_state: Optional[Mapping[Any, Any]] = None,
        unavailable_links: Optional[Iterable[Edge]] = None,
        unavailable_nodes: Optional[Iterable[Node]] = None,
    ) -> Dict[str, Any]:
        """Return a structured, explainable path decision."""
        candidates = self.get_candidate_paths(
            src,
            dst,
            graph,
            unavailable_links=unavailable_links,
            unavailable_nodes=unavailable_nodes,
        )
        valid_candidates = [
            path
            for path in candidates
            if self.is_path_valid(
                path,
                unavailable_links=unavailable_links,
            )
        ]
        evaluations = [
            self.evaluate_path(
                path,
                network_state=network_state,
                unavailable_links=unavailable_links,
            )
            for path in valid_candidates
        ]
        evaluations.sort(
            key=lambda evaluation: (evaluation.cost, len(evaluation.path))
        )
        if not evaluations:
            return {
                "success": False,
                "path": None,
                "backup_path": None,
                "candidates": [],
                "message": f"No valid path from {src} to {dst}",
                "flow_context": dict(flow_context or {}),
            }

        primary = evaluations[0]

        return {
            "success": True,
            "path": list(primary.path),
            "backup_path": None,
            "cost": primary.cost,
            "reason": primary.reason,
            "primary": primary.as_dict(),
            "backup": None,
            "candidates": [evaluation.as_dict() for evaluation in evaluations],
            "flow_context": dict(flow_context or {}),
        }

    def get_backup_path(
        self,
        current_path: Sequence[Node],
        src: Node,
        dst: Node,
        graph: nx.Graph,
        *,
        flow_context: Optional[Mapping[str, Any]] = None,
        network_state: Optional[Mapping[Any, Any]] = None,
        unavailable_links: Optional[Iterable[Edge]] = None,
        unavailable_nodes: Optional[Iterable[Node]] = None,
    ) -> Dict[str, Any]:
        """Select a replacement path after the current path becomes invalid.

        This API is intentionally separate from normal path selection. It
        never installs rules and it does not pre-activate the backup path.
        The caller must establish that a failure occurred and then pass the
        returned path to the enforcement/installation layer.
        """
        candidates = self.get_candidate_paths(
            src,
            dst,
            graph,
            unavailable_links=unavailable_links,
            unavailable_nodes=unavailable_nodes,
        )
        alternatives = [
            path for path in candidates if list(path) != list(current_path)
        ]
        primary, backup, evaluations = self.select_primary_backup(
            alternatives,
            network_state=network_state,
            unavailable_links=unavailable_links,
        )
        if primary is None:
            return {
                "success": False,
                "path": None,
                "backup_path": None,
                "current_path": list(current_path),
                "message": f"No backup path from {src} to {dst}",
                "reason": "no valid backup after primary failure",
                "flow_context": dict(flow_context or {}),
            }

        return {
            "success": True,
            "path": list(primary.path),
            "backup_path": list(backup.path) if backup else None,
            "current_path": list(current_path),
            "cost": primary.cost,
            "reason": "backup activated after primary failure",
            "primary": primary.as_dict(),
            "backup": backup.as_dict() if backup else None,
            "candidates": [evaluation.as_dict() for evaluation in evaluations],
            "flow_context": dict(flow_context or {}),
        }

    def should_reroute(
        self,
        current_path: Sequence[Node],
        proposed_path: Sequence[Node],
        *,
        network_state: Optional[Mapping[Any, Any]] = None,
        unavailable_links: Optional[Iterable[Edge]] = None,
        graph: Optional[nx.Graph] = None,
        unavailable_nodes: Optional[Iterable[Node]] = None,
    ) -> bool:
        """Apply a simple improvement threshold to reduce route flapping."""
        if list(current_path) == list(proposed_path):
            return False
        current_valid = self.is_path_valid(
            current_path,
            graph=graph,
            unavailable_links=unavailable_links,
            unavailable_nodes=unavailable_nodes,
        )
        proposed_valid = self.is_path_valid(
            proposed_path,
            graph=graph,
            unavailable_links=unavailable_links,
            unavailable_nodes=unavailable_nodes,
        )
        if not proposed_valid:
            return False
        if not current_valid:
            return True
        current = self.evaluate_path(
            current_path,
            network_state=network_state,
            unavailable_links=unavailable_links,
        )
        proposed = self.evaluate_path(
            proposed_path,
            network_state=network_state,
            unavailable_links=unavailable_links,
        )
        if current.failure_cost > 0:
            return True
        if current.cost == 0:
            return proposed.cost < current.cost
        improvement = (current.cost - proposed.cost) / current.cost
        return improvement >= self.reroute_threshold


__all__ = ["PathEngine", "PathEvaluation", "PathWeights"]
