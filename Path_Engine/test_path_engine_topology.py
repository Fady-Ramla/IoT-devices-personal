import networkx as nx

from path_engine import PathEngine


def project_mesh():
    """Five-switch, seven-link topology used by the current project tests."""
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


def path_edges(path):
    return {frozenset(edge) for edge in zip(path, path[1:])}


def test_normal_routing_selects_a_valid_path():
    result = PathEngine().get_best_path(1, 5, project_mesh())
    assert result["success"] is True
    assert result["path"][0] == 1
    assert result["path"][-1] == 5


def test_link_1_3_failure_reroutes():
    result = PathEngine().get_best_path(
        1, 5, project_mesh(), unavailable_links=[(1, 3)]
    )
    assert result["success"] is True
    assert frozenset((1, 3)) not in path_edges(result["path"])


def test_link_3_5_failure_reroutes():
    result = PathEngine().get_best_path(
        1, 5, project_mesh(), unavailable_links=[(3, 5)]
    )
    assert result["success"] is True
    assert frozenset((3, 5)) not in path_edges(result["path"])


def test_link_2_4_failure_reroutes():
    result = PathEngine().get_best_path(
        1, 5, project_mesh(), unavailable_links=[(2, 4)]
    )
    assert result["success"] is True
    assert frozenset((2, 4)) not in path_edges(result["path"])


def test_multiple_failures_still_use_valid_path():
    failed = [(1, 3), (2, 4)]
    result = PathEngine().get_best_path(
        1, 5, project_mesh(), unavailable_links=failed
    )
    assert result["success"] is True
    assert all(frozenset(link) not in path_edges(result["path"]) for link in failed)


def test_no_path_after_cut_returns_failure():
    failed = [(1, 2), (1, 3)]
    result = PathEngine().get_best_path(
        1, 5, project_mesh(), unavailable_links=failed
    )
    assert result["success"] is False
    assert result["path"] is None


def test_congestion_can_select_longer_path():
    utilization = {
        (1, 3): 0.95,
        (3, 5): 0.95,
        (1, 2): 0.10,
        (2, 4): 0.10,
        (4, 5): 0.10,
    }
    result = PathEngine().get_best_path(
        1, 5, project_mesh(), network_state=utilization
    )
    assert result["success"] is True
    assert result["path"] == [1, 2, 4, 5]


def test_primary_and_backup_are_edge_disjoint_when_possible():
    engine = PathEngine()
    result = engine.get_best_path(1, 5, project_mesh())
    assert result["success"] is True
    candidates = engine.get_candidate_paths(1, 5, project_mesh())
    primary, backup, _ = engine.select_primary_backup(candidates)
    assert primary is not None
    assert backup is not None
    assert not (
        path_edges(primary.path) & path_edges(backup.path)
    )


def test_link_restoration_makes_link_usable_again():
    failed_result = PathEngine().get_best_path(
        1, 5, project_mesh(), unavailable_links=[(3, 5)]
    )
    restored_result = PathEngine().get_best_path(1, 5, project_mesh())
    assert failed_result["success"] is True
    assert restored_result["success"] is True
    assert frozenset((3, 5)) not in path_edges(failed_result["path"])
    assert frozenset((3, 5)) in {
        frozenset(edge)
        for path in restored_result["candidates"]
        for edge in zip(path["path"], path["path"][1:])
    }


def test_small_change_does_not_flap():
    engine = PathEngine(reroute_threshold=0.10)
    assert engine.should_reroute(
        [1, 2, 4, 5],
        [1, 3, 4, 5],
        graph=project_mesh(),
        network_state={
            (1, 2): 0.50,
            (2, 4): 0.50,
            (4, 5): 0.50,
            (1, 3): 0.48,
            (3, 4): 0.48,
        },
    ) is False
