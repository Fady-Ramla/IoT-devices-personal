import networkx as nx

from path_engine import PathEngine


def partial_mesh():
    graph = nx.Graph()
    graph.add_edges_from(
        [
            (1, 2),
            (2, 3),
            (3, 4),
            (4, 5),
            (1, 3),
            (2, 4),
            (3, 5),
        ]
    )
    return graph


def test_candidates_include_distinct_routes():
    engine = PathEngine(max_candidates=10)
    candidates = engine.get_candidate_paths(1, 5, partial_mesh())
    assert [1, 3, 5] in candidates
    assert [1, 2, 4, 5] in candidates


def test_failed_link_is_excluded():
    engine = PathEngine(max_candidates=10)
    result = engine.get_best_path(
        1,
        5,
        partial_mesh(),
        unavailable_links=[(3, 5)],
    )
    assert result["success"] is True
    assert result["path"] == [1, 2, 4, 5]
    primary_edges = list(zip(result["path"], result["path"][1:]))
    assert (3, 5) not in primary_edges
    assert (5, 3) not in primary_edges


def test_failed_node_is_excluded():
    result = PathEngine(max_candidates=10).get_best_path(
        1,
        5,
        partial_mesh(),
        unavailable_nodes=[3],
    )
    assert result["success"] is True
    assert 3 not in result["path"]


def test_utilization_can_beat_shortest_path():
    engine = PathEngine(max_candidates=10)
    utilization = {
        (1, 3): 0.90,
        (3, 5): 0.85,
        (1, 2): 0.20,
        (2, 4): 0.30,
        (4, 5): 0.15,
    }
    result = engine.get_best_path(
        1,
        5,
        partial_mesh(),
        network_state=utilization,
    )
    assert result["success"] is True
    assert result["path"] == [1, 2, 4, 5]


def test_backup_prefers_fewer_shared_edges():
    engine = PathEngine(max_candidates=10)
    candidates = engine.get_candidate_paths(1, 5, partial_mesh())
    primary, backup, _ = engine.select_primary_backup(candidates)
    assert primary is not None
    assert backup is not None
    primary_edges = {
        frozenset(edge)
        for edge in zip(primary.path, primary.path[1:])
    }
    backup_edges = {
        frozenset(edge)
        for edge in zip(backup.path, backup.path[1:])
    }
    assert len(primary_edges & backup_edges) == 0


def test_no_path_returns_structured_failure():
    graph = nx.Graph()
    graph.add_edge(1, 2)
    graph.add_edge(3, 4)
    result = PathEngine().get_best_path(1, 4, graph)
    assert result["success"] is False
    assert result["path"] is None


def test_path_validation_rejects_unknown_node():
    engine = PathEngine()
    assert engine.is_path_valid([1, 2, 99], graph=partial_mesh()) is False


def test_reroute_threshold_prevents_small_flap():
    engine = PathEngine(reroute_threshold=0.10)
    assert engine.should_reroute(
        [1, 2, 4, 5],
        [1, 3, 4, 5],
        network_state={
            (1, 2): 0.50,
            (2, 4): 0.50,
            (4, 5): 0.50,
            (1, 3): 0.48,
            (3, 4): 0.48,
        },
    ) is False


def test_significant_improvement_triggers_reroute():
    engine = PathEngine(reroute_threshold=0.10)
    assert engine.should_reroute(
        [1, 3, 5],
        [1, 2, 4, 5],
        network_state={
            (1, 3): 0.90,
            (3, 5): 0.90,
            (1, 2): 0.10,
            (2, 4): 0.10,
            (4, 5): 0.10,
        },
        graph=partial_mesh(),
    ) is True


def test_failed_current_path_triggers_reroute():
    assert PathEngine().should_reroute(
        [1, 3, 5],
        [1, 2, 4, 5],
        graph=partial_mesh(),
        unavailable_links=[(3, 5)],
    ) is True


def test_reroute_rejects_invalid_proposed_path():
    engine = PathEngine()
    assert engine.should_reroute(
        [1, 3, 5],
        [1, 2, 4, 5],
        graph=partial_mesh(),
        unavailable_links=[(2, 4)],
    ) is False


def test_same_path_does_not_reroute():
    assert PathEngine().should_reroute(
        [1, 2, 4, 5],
        [1, 2, 4, 5],
        graph=partial_mesh(),
    ) is False


def test_normal_selection_returns_primary_without_activation_reason():
    result = PathEngine().get_best_path(1, 5, partial_mesh())
    assert result["success"] is True
    assert result["reason"] != "backup activated after primary failure"
    assert result["path"] == [1, 3, 5]
    assert result["backup_path"] is None
    assert result["backup"] is None


def test_backup_selection_requires_current_path_failure_context():
    result = PathEngine().get_backup_path(
        current_path=[1, 3, 5],
        src=1,
        dst=5,
        graph=partial_mesh(),
        unavailable_links=[(3, 5)],
    )
    assert result["success"] is True
    assert result["reason"] == "backup activated after primary failure"
    assert result["path"] == [1, 2, 4, 5]
    assert result["path"] != [1, 3, 5]
