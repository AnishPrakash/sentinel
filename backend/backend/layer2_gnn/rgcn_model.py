# backend/layer2_gnn/rgcn_model.py
"""
Relational Graph Convolutional Network (RGCN) for anomaly detection.
Treats each edge type (SPAWN, READ, WRITE, CONNECT, DELETE, MODIFY_REG)
as a separate relation, updating node embeddings by aggregating across
type-specific neighbourhoods.

Architecture:
  Input: Node features (one-hot node type, 5 dims)
  RGCN Layer 1: hidden_dim=64
  RGCN Layer 2: hidden_dim=32
  Output: Anomaly score per node ∈ [0, 1] via sigmoid
"""
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import RGCNConv


# Edge type → integer index (must match graph_converter.py)
EDGE_TYPE_MAP = {
    "SPAWN":      0,
    "READ":       1,
    "WRITE":      2,
    "CONNECT":    3,
    "DELETE":     4,
    "MODIFY_REG": 5,
}
NUM_RELATIONS = len(EDGE_TYPE_MAP)

# Node type → integer index (one-hot feature)
NODE_TYPE_MAP = {
    "process":  0,
    "file":     1,
    "socket":   2,
    "registry": 3,
    "user":     4,
}
NODE_FEATURE_DIM = len(NODE_TYPE_MAP)


class SentinelRGCN(nn.Module):
    """
    Two-layer RGCN with a binary classification head.
    Forward pass returns a per-node anomaly logit.
    Use sigmoid(logit) to get anomaly probability.
    """

    def __init__(
        self,
        in_channels:  int = NODE_FEATURE_DIM,
        hidden_dim:   int = 64,
        out_dim:      int = 32,
        num_relations: int = NUM_RELATIONS,
    ):
        super().__init__()
        self.conv1 = RGCNConv(in_channels,  hidden_dim, num_relations)
        self.conv2 = RGCNConv(hidden_dim,   out_dim,    num_relations)
        self.head  = nn.Linear(out_dim, 1)
        self.dropout = nn.Dropout(p=0.3)

    def forward(self, x, edge_index, edge_type):
        """
        x:          [N, NODE_FEATURE_DIM]  — node feature matrix
        edge_index: [2, E]                 — COO edge index
        edge_type:  [E]                    — integer relation type per edge
        Returns:
            logits: [N, 1]
        """
        h = F.relu(self.conv1(x, edge_index, edge_type))
        h = self.dropout(h)
        h = F.relu(self.conv2(h, edge_index, edge_type))
        logits = self.head(h)
        return logits

    def anomaly_scores(self, x, edge_index, edge_type) -> torch.Tensor:
        """Convenience wrapper returning probabilities."""
        with torch.no_grad():
            logits = self.forward(x, edge_index, edge_type)
            return torch.sigmoid(logits).squeeze(-1)
