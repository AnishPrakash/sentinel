# backend/layer2_gnn/graph_converter.py
"""
Converts a NetworkX MultiDiGraph (provenance graph) into a
PyTorch Geometric Data object suitable for RGCN inference.
"""
import torch
import networkx as nx
from torch_geometric.data import Data
from layer2_gnn.rgcn_model import NODE_TYPE_MAP, EDGE_TYPE_MAP, NODE_FEATURE_DIM


def networkx_to_pyg(
    graph: nx.MultiDiGraph,
    node_meta: dict,
) -> tuple[Data, list[str]]:
    """
    Args:
        graph:     NetworkX MultiDiGraph from ProvenanceGraph
        node_meta: Dict mapping node_id → {"node_type": str, ...}

    Returns:
        (pyg_data, ordered_node_ids)
        pyg_data.x          : [N, NODE_FEATURE_DIM]
        pyg_data.edge_index : [2, E]
        pyg_data.edge_type  : [E]
    """
    node_ids   = list(graph.nodes())
    node_index = {nid: i for i, nid in enumerate(node_ids)}

    # ── Node features: one-hot of node_type ──────────────────────────────────
    x = torch.zeros(len(node_ids), NODE_FEATURE_DIM)
    for nid, idx in node_index.items():
        nt = node_meta.get(nid, {}).get("node_type", "process")
        type_idx = NODE_TYPE_MAP.get(nt, 0)
        x[idx, type_idx] = 1.0

    # ── Edges ─────────────────────────────────────────────────────────────────
    src_list, tgt_list, etype_list = [], [], []
    for u, v, data in graph.edges(data=True):
        if u in node_index and v in node_index:
            src_list.append(node_index[u])
            tgt_list.append(node_index[v])
            etype = EDGE_TYPE_MAP.get(data.get("edge_type", "READ"), 1)
            etype_list.append(etype)

    if not src_list:
        # Empty graph edge case
        edge_index = torch.zeros((2, 0), dtype=torch.long)
        edge_type  = torch.zeros(0, dtype=torch.long)
    else:
        edge_index = torch.tensor([src_list, tgt_list], dtype=torch.long)
        edge_type  = torch.tensor(etype_list, dtype=torch.long)

    data = Data(x=x, edge_index=edge_index, edge_type=edge_type)
    return data, node_ids
