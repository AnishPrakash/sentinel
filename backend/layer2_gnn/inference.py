# backend/layer2_gnn/inference.py
"""
Live inference engine for the RGCN model.
Loads pre-trained weights once at startup; then accepts graph snapshots
and returns per-node anomaly scores.
"""
import os
import torch
from typing import Dict, List, Tuple
import networkx as nx

from layer2_gnn.rgcn_model import SentinelRGCN
from layer2_gnn.graph_converter import networkx_to_pyg
from config import GNN_ANOMALY_THRESHOLD, MODEL_WEIGHTS_PATH


class GNNInferenceEngine:
    def __init__(self):
        self.model     = SentinelRGCN()
        self.threshold = GNN_ANOMALY_THRESHOLD
        self._loaded   = False
        self._load_model()

    def _load_model(self):
        if os.path.exists(MODEL_WEIGHTS_PATH):
            state = torch.load(MODEL_WEIGHTS_PATH, map_location="cpu")
            self.model.load_state_dict(state)
            self.model.eval()
            self._loaded = True
            print(f"[GNN] Weights loaded from {MODEL_WEIGHTS_PATH}")
        else:
            print(f"[GNN] WARNING: No weights at {MODEL_WEIGHTS_PATH}. "
                  "Using random weights (run train.py first for real results).")
            self.model.eval()

    def score_graph(
        self,
        graph: nx.MultiDiGraph,
        node_meta: dict,
    ) -> Dict[str, float]:
        """
        Score all nodes in the graph.
        Returns {node_id: anomaly_score ∈ [0, 1]}.
        """
        if graph.number_of_nodes() == 0:
            return {}

        pyg_data, node_ids = networkx_to_pyg(graph, node_meta)

        if pyg_data.edge_index.shape[1] == 0:
            # No edges — assign neutral score
            return {nid: 0.1 for nid in node_ids}

        with torch.no_grad():
            scores = self.model.anomaly_scores(
                pyg_data.x,
                pyg_data.edge_index,
                pyg_data.edge_type,
            )

        return {node_ids[i]: float(scores[i]) for i in range(len(node_ids))}

    def get_anomalous_nodes(
        self,
        graph: nx.MultiDiGraph,
        node_meta: dict,
    ) -> List[Tuple[str, float]]:
        """
        Returns list of (node_id, score) for nodes above threshold,
        sorted descending by score.
        """
        scores = self.score_graph(graph, node_meta)
        flagged = [
            (nid, s) for nid, s in scores.items()
            if s >= self.threshold
        ]
        return sorted(flagged, key=lambda x: x[1], reverse=True)


# ── Global singleton ──────────────────────────────────────────────────────────
gnn_engine = GNNInferenceEngine()
