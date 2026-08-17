# tests/test_layer2.py
"""
Tests for Layer 2 — RGCN Anomaly Detection.

Coverage:
  - networkx_to_pyg: node features, edge index, edge type tensor shapes
  - SentinelRGCN: forward pass shapes, anomaly_scores wrapper, determinism
  - GNNInferenceEngine: score_graph outputs, get_anomalous_nodes threshold filtering
  - Edge cases: empty graph, no-edge graph, unknown node/edge types

Run with:
    cd backend
    pytest ../tests/test_layer2.py -v
"""
import pytest
import torch
import networkx as nx

from layer2_gnn.rgcn_model import (
    SentinelRGCN,
    EDGE_TYPE_MAP,
    NODE_TYPE_MAP,
    NODE_FEATURE_DIM,
    NUM_RELATIONS,
)
from layer2_gnn.graph_converter import networkx_to_pyg
from layer2_gnn.inference import GNNInferenceEngine


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

def _make_simple_graph() -> tuple[nx.MultiDiGraph, dict]:
    """
    Build a minimal three-node provenance graph:
        proc_100 -[SPAWN]-> proc_200 -[CONNECT]-> sock_8888

    Returns (graph, node_meta).
    """
    g = nx.MultiDiGraph()
    node_meta = {
        "proc_100": {"node_type": "process", "host": "workstation-1"},
        "proc_200": {"node_type": "process", "host": "workstation-1"},
        "sock_8888": {"node_type": "socket",  "host": "workstation-1"},
    }
    g.add_node("proc_100")
    g.add_node("proc_200")
    g.add_node("sock_8888")
    g.add_edge("proc_100", "proc_200", edge_type="SPAWN")
    g.add_edge("proc_200", "sock_8888", edge_type="CONNECT")
    return g, node_meta


def _make_apt_graph() -> tuple[nx.MultiDiGraph, dict]:
    """
    Simulate a phishing APT subgraph:
        winword -[SPAWN]-> cmd -[WRITE]-> payload.ps1 -[READ]-> powershell
        powershell -[CONNECT]-> c2_socket
    """
    g = nx.MultiDiGraph()
    node_meta = {
        "winword":     {"node_type": "process",  "host": "workstation-1"},
        "cmd":         {"node_type": "process",  "host": "workstation-1"},
        "payload_ps1": {"node_type": "file",     "host": "workstation-1"},
        "powershell":  {"node_type": "process",  "host": "workstation-1"},
        "c2_socket":   {"node_type": "socket",   "host": "workstation-1"},
    }
    for nid in node_meta:
        g.add_node(nid)

    g.add_edge("winword",     "cmd",         edge_type="SPAWN")
    g.add_edge("cmd",         "payload_ps1", edge_type="WRITE")
    g.add_edge("payload_ps1", "powershell",  edge_type="READ")
    g.add_edge("powershell",  "c2_socket",   edge_type="CONNECT")
    return g, node_meta


def _make_empty_graph() -> tuple[nx.MultiDiGraph, dict]:
    return nx.MultiDiGraph(), {}


def _make_no_edge_graph() -> tuple[nx.MultiDiGraph, dict]:
    g = nx.MultiDiGraph()
    node_meta = {
        "isolated_proc": {"node_type": "process", "host": "h1"},
    }
    g.add_node("isolated_proc")
    return g, node_meta


# ─────────────────────────────────────────────────────────────────────────────
# graph_converter tests
# ─────────────────────────────────────────────────────────────────────────────

class TestGraphConverter:

    def test_basic_node_count(self):
        g, meta = _make_simple_graph()
        data, node_ids = networkx_to_pyg(g, meta)
        assert data.x.shape[0] == 3, "Should have 3 node feature rows"
        assert len(node_ids) == 3

    def test_feature_dim(self):
        g, meta = _make_simple_graph()
        data, _ = networkx_to_pyg(g, meta)
        assert data.x.shape[1] == NODE_FEATURE_DIM, (
            f"Feature dim should be {NODE_FEATURE_DIM}, got {data.x.shape[1]}"
        )

    def test_node_type_one_hot_process(self):
        g, meta = _make_simple_graph()
        data, node_ids = networkx_to_pyg(g, meta)
        proc_idx = node_ids.index("proc_100")
        feat = data.x[proc_idx]
        assert feat[NODE_TYPE_MAP["process"]].item() == 1.0
        # All other positions should be 0
        assert feat.sum().item() == 1.0

    def test_node_type_one_hot_socket(self):
        g, meta = _make_simple_graph()
        data, node_ids = networkx_to_pyg(g, meta)
        sock_idx = node_ids.index("sock_8888")
        feat = data.x[sock_idx]
        assert feat[NODE_TYPE_MAP["socket"]].item() == 1.0
        assert feat.sum().item() == 1.0

    def test_edge_index_shape(self):
        g, meta = _make_simple_graph()
        data, _ = networkx_to_pyg(g, meta)
        assert data.edge_index.shape[0] == 2, "edge_index must have 2 rows (src, dst)"
        assert data.edge_index.shape[1] == 2, "Should have 2 edges"

    def test_edge_type_shape(self):
        g, meta = _make_simple_graph()
        data, _ = networkx_to_pyg(g, meta)
        assert data.edge_type.shape[0] == 2, "Should have 2 edge type entries"

    def test_edge_type_values_valid(self):
        g, meta = _make_apt_graph()
        data, _ = networkx_to_pyg(g, meta)
        max_type = data.edge_type.max().item()
        assert max_type < NUM_RELATIONS, (
            f"Edge type {max_type} exceeds NUM_RELATIONS={NUM_RELATIONS}"
        )

    def test_spawn_edge_type_encoded(self):
        g, meta = _make_simple_graph()
        data, node_ids = networkx_to_pyg(g, meta)
        src_idx = node_ids.index("proc_100")
        dst_idx = node_ids.index("proc_200")
        # Find the edge in edge_index
        edge_positions = (
            (data.edge_index[0] == src_idx) & (data.edge_index[1] == dst_idx)
        ).nonzero(as_tuple=True)[0]
        assert len(edge_positions) == 1
        et = data.edge_type[edge_positions[0]].item()
        assert et == EDGE_TYPE_MAP["SPAWN"]

    def test_unknown_edge_type_defaults(self):
        """Unknown edge types should not crash — they default to READ (1)."""
        g = nx.MultiDiGraph()
        node_meta = {
            "p1": {"node_type": "process"},
            "p2": {"node_type": "process"},
        }
        g.add_node("p1"); g.add_node("p2")
        g.add_edge("p1", "p2", edge_type="TOTALLY_UNKNOWN_TYPE")
        data, _ = networkx_to_pyg(g, node_meta)
        assert data.edge_type.shape[0] == 1
        # Should not raise; default is EDGE_TYPE_MAP.get(..., 1) = READ
        assert data.edge_type[0].item() == 1

    def test_unknown_node_type_defaults(self):
        """Unknown node types should default to process (index 0)."""
        g = nx.MultiDiGraph()
        node_meta = {"mystery": {"node_type": "hypervisor"}}
        g.add_node("mystery")
        data, _ = networkx_to_pyg(g, node_meta)
        assert data.x[0, 0].item() == 1.0  # defaults to index 0 = process

    def test_empty_graph(self):
        g, meta = _make_empty_graph()
        data, node_ids = networkx_to_pyg(g, meta)
        assert data.x.shape[0] == 0
        assert len(node_ids) == 0
        assert data.edge_index.shape == (2, 0)

    def test_no_edge_graph(self):
        g, meta = _make_no_edge_graph()
        data, node_ids = networkx_to_pyg(g, meta)
        assert data.x.shape[0] == 1
        assert data.edge_index.shape[1] == 0
        assert data.edge_type.shape[0] == 0

    def test_apt_graph_full(self):
        g, meta = _make_apt_graph()
        data, node_ids = networkx_to_pyg(g, meta)
        assert data.x.shape[0] == 5
        assert data.edge_index.shape[1] == 4
        assert data.edge_type.shape[0] == 4


# ─────────────────────────────────────────────────────────────────────────────
# SentinelRGCN model tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSentinelRGCN:

    def test_instantiation(self):
        model = SentinelRGCN()
        assert model is not None

    def test_forward_output_shape(self):
        g, meta = _make_simple_graph()
        data, _ = networkx_to_pyg(g, meta)
        model = SentinelRGCN()
        model.eval()
        with torch.no_grad():
            logits = model(data.x, data.edge_index, data.edge_type)
        # Expect [N, 1]
        assert logits.shape == (3, 1), f"Expected (3, 1), got {logits.shape}"

    def test_forward_apt_graph(self):
        g, meta = _make_apt_graph()
        data, _ = networkx_to_pyg(g, meta)
        model = SentinelRGCN()
        model.eval()
        with torch.no_grad():
            logits = model(data.x, data.edge_index, data.edge_type)
        assert logits.shape == (5, 1)

    def test_anomaly_scores_range(self):
        """Scores must be in [0, 1] because we apply sigmoid."""
        g, meta = _make_apt_graph()
        data, _ = networkx_to_pyg(g, meta)
        model = SentinelRGCN()
        model.eval()
        scores = model.anomaly_scores(data.x, data.edge_index, data.edge_type)
        assert scores.shape == (5,), "anomaly_scores should squeeze to [N]"
        assert scores.min().item() >= 0.0
        assert scores.max().item() <= 1.0

    def test_anomaly_scores_deterministic(self):
        """Same model, same input → same scores (no stochastic dropout in eval mode)."""
        g, meta = _make_apt_graph()
        data, _ = networkx_to_pyg(g, meta)
        model = SentinelRGCN()
        model.eval()
        scores_a = model.anomaly_scores(data.x, data.edge_index, data.edge_type)
        scores_b = model.anomaly_scores(data.x, data.edge_index, data.edge_type)
        assert torch.allclose(scores_a, scores_b), "Scores should be deterministic in eval mode"

    def test_model_has_expected_layers(self):
        model = SentinelRGCN()
        assert hasattr(model, "conv1"), "Missing conv1 (RGCNConv layer 1)"
        assert hasattr(model, "conv2"), "Missing conv2 (RGCNConv layer 2)"
        assert hasattr(model, "head"),  "Missing linear classification head"

    def test_custom_dims(self):
        """Model should accept non-default dimensions without error."""
        model = SentinelRGCN(in_channels=5, hidden_dim=16, out_dim=8, num_relations=4)
        g = nx.MultiDiGraph()
        g.add_node("a"); g.add_node("b")
        g.add_edge("a", "b", edge_type="SPAWN")
        meta = {"a": {"node_type": "process"}, "b": {"node_type": "file"}}
        data, _ = networkx_to_pyg(g, meta)
        model.eval()
        with torch.no_grad():
            logits = model(data.x, data.edge_index, data.edge_type)
        assert logits.shape[0] == 2

    def test_no_edge_graph_forward(self):
        """Model should handle graphs with no edges without crashing."""
        g, meta = _make_no_edge_graph()
        data, node_ids = networkx_to_pyg(g, meta)
        # edge_index is empty — PyG RGCNConv with no edges should still run
        # (returns node features aggregated from self-loops only)
        model = SentinelRGCN()
        model.eval()
        with torch.no_grad():
            logits = model(data.x, data.edge_index, data.edge_type)
        assert logits.shape[0] == 1


# ─────────────────────────────────────────────────────────────────────────────
# GNNInferenceEngine tests
# ─────────────────────────────────────────────────────────────────────────────

class TestGNNInferenceEngine:
    """
    These tests use random (untrained) weights because the CI environment
    will not have pre-trained weights at layer2_gnn/weights/rgcn_sentinel.pt.
    They validate behaviour and output contracts, not numeric accuracy.
    """

    @pytest.fixture(scope="class")
    def engine(self):
        """Single engine instance per test class (model load is expensive)."""
        return GNNInferenceEngine()

    def test_score_graph_returns_dict(self, engine):
        g, meta = _make_simple_graph()
        scores = engine.score_graph(g, meta)
        assert isinstance(scores, dict)

    def test_score_graph_keys_match_nodes(self, engine):
        g, meta = _make_simple_graph()
        scores = engine.score_graph(g, meta)
        assert set(scores.keys()) == set(g.nodes())

    def test_score_graph_values_in_range(self, engine):
        g, meta = _make_apt_graph()
        scores = engine.score_graph(g, meta)
        for nid, s in scores.items():
            assert 0.0 <= s <= 1.0, f"Node {nid} score {s} out of [0,1]"

    def test_score_graph_empty(self, engine):
        g, meta = _make_empty_graph()
        scores = engine.score_graph(g, meta)
        assert scores == {}, "Empty graph should return empty dict"

    def test_score_graph_no_edges(self, engine):
        """No-edge graph should return neutral scores, not crash."""
        g, meta = _make_no_edge_graph()
        scores = engine.score_graph(g, meta)
        assert "isolated_proc" in scores
        # Neutral score for edgeless nodes
        assert scores["isolated_proc"] == pytest.approx(0.1, abs=1e-6)

    def test_get_anomalous_nodes_returns_list(self, engine):
        g, meta = _make_apt_graph()
        flagged = engine.get_anomalous_nodes(g, meta)
        assert isinstance(flagged, list)

    def test_get_anomalous_nodes_sorted_descending(self, engine):
        g, meta = _make_apt_graph()
        flagged = engine.get_anomalous_nodes(g, meta)
        if len(flagged) > 1:
            scores_only = [s for _, s in flagged]
            assert scores_only == sorted(scores_only, reverse=True), (
                "get_anomalous_nodes should return nodes sorted by score descending"
            )

    def test_get_anomalous_nodes_respects_threshold(self, engine):
        """All returned nodes must have score >= engine.threshold."""
        g, meta = _make_apt_graph()
        flagged = engine.get_anomalous_nodes(g, meta)
        for nid, score in flagged:
            assert score >= engine.threshold, (
                f"Node {nid} with score {score:.3f} is below threshold {engine.threshold}"
            )

    def test_get_anomalous_nodes_tuple_format(self, engine):
        """Each element must be a (str, float) tuple."""
        g, meta = _make_apt_graph()
        flagged = engine.get_anomalous_nodes(g, meta)
        for item in flagged:
            assert len(item) == 2
            nid, score = item
            assert isinstance(nid, str)
            assert isinstance(score, float)

    def test_score_graph_deterministic(self, engine):
        """Inference must be deterministic (model in eval mode)."""
        g, meta = _make_apt_graph()
        scores_a = engine.score_graph(g, meta)
        scores_b = engine.score_graph(g, meta)
        for nid in scores_a:
            assert abs(scores_a[nid] - scores_b[nid]) < 1e-6, (
                f"Non-deterministic score for node {nid}"
            )

    def test_engine_threshold_attribute(self, engine):
        """Engine must expose threshold from config."""
        assert hasattr(engine, "threshold")
        assert 0.0 < engine.threshold < 1.0

    def test_engine_model_in_eval_mode(self, engine):
        """Model must be in eval mode after loading (no dropout during inference)."""
        assert not engine.model.training, "Model should be in eval() mode after loading"