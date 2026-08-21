# backend/layer2_gnn/train.py
"""
OFFLINE TRAINING SCRIPT — Run this BEFORE the hackathon day.
Trains RGCN on BETH dataset and saves weights to disk.

Usage:
    python -m layer2_gnn.train --epochs 50 --lr 0.001 --save weights/rgcn_sentinel.pt

The BETH dataset has a `sus` column (0=benign, 1=suspicious).
We treat suspicious subgraphs as positive examples.
"""
import os
import argparse
import torch
import torch.nn.functional as F
from torch_geometric.loader import DataLoader
from sklearn.metrics import roc_auc_score, classification_report
import numpy as np

from layer2_gnn.rgcn_model import SentinelRGCN, NODE_FEATURE_DIM
from layer1_ingestion.beth_loader import stream_beth
from layer1_ingestion.log_parser import parse_beth_row
from layer2_gnn.graph_converter import networkx_to_pyg
import networkx as nx


def build_beth_graphs(limit: int = 50_000):
    """
    Builds a list of (pyg_data, label) tuples from BETH dataset.
    We chunk events by host+session into mini-graphs.
    """
    from layer1_ingestion.graph_builder import ProvenanceGraph
    from models.schemas import LogEvent

    graphs_and_labels = []
    session_events = {}   # session_key → (events, max_sus)

    for row in stream_beth(limit=limit):
        event = parse_beth_row(row)
        if event is None:
            continue

        key = f"{row.get('hostName','h1')}_{row.get('processId','0')}"
        sus = int(row.get("sus", 0))
        if key not in session_events:
            session_events[key] = ([], 0)
        evts, cur_sus = session_events[key]
        evts.append(event)
        session_events[key] = (evts, max(cur_sus, sus))

    for key, (evts, label) in session_events.items():
        if len(evts) < 3:
            continue
        pg = ProvenanceGraph()
        for e in evts:
            pg.add_event(e)
        nx_graph = pg.get_networkx()
        if nx_graph.number_of_nodes() < 2:
            continue
        pyg_data, _ = networkx_to_pyg(nx_graph, pg._node_meta)
        pyg_data.y = torch.tensor([float(label)], dtype=torch.float)
        graphs_and_labels.append(pyg_data)

    return graphs_and_labels


def train(args):
    os.makedirs(os.path.dirname(args.save), exist_ok=True)

    print("[Train] Building BETH graph dataset...")
    dataset = build_beth_graphs(limit=args.limit)
    print(f"[Train] {len(dataset)} graphs. "
          f"Positives: {sum(1 for d in dataset if d.y.item() > 0)}")

    split = int(0.8 * len(dataset))
    train_data = dataset[:split]
    test_data  = dataset[split:]

    model     = SentinelRGCN()
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-4)
    pos_weight = torch.tensor(
        [len(train_data) / max(1, sum(1 for d in train_data if d.y.item() > 0))]
    )
    criterion = torch.nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    model.train()
    for epoch in range(1, args.epochs + 1):
        total_loss = 0.0
        for data in train_data:
            if data.edge_index.shape[1] == 0:
                continue
            optimizer.zero_grad()
            logits = model(data.x, data.edge_index, data.edge_type)
            # Use mean logit across nodes as graph-level prediction
            graph_logit = logits.mean()
            loss = criterion(graph_logit.unsqueeze(0), data.y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        if epoch % 10 == 0:
            print(f"  Epoch {epoch:3d} | Loss: {total_loss / len(train_data):.4f}")

    # ── Evaluation ─────────────────────────────────────────────────────────
    model.eval()
    y_true, y_pred = [], []
    with torch.no_grad():
        for data in test_data:
            if data.edge_index.shape[1] == 0:
                continue
            logits = model(data.x, data.edge_index, data.edge_type)
            prob = torch.sigmoid(logits.mean()).item()
            y_true.append(int(data.y.item()))
            y_pred.append(prob)

    auc = roc_auc_score(y_true, y_pred) if len(set(y_true)) > 1 else 0.0
    preds_bin = [1 if p >= 0.5 else 0 for p in y_pred]
    print(f"\n[Eval] AUC-ROC: {auc:.4f}")
    print(classification_report(y_true, preds_bin, target_names=["Benign", "Attack"]))

    torch.save(model.state_dict(), args.save)
    print(f"[Train] Weights saved → {args.save}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--epochs", type=int,   default=50)
    parser.add_argument("--lr",     type=float, default=0.001)
    parser.add_argument("--limit",  type=int,   default=50_000)
    parser.add_argument("--save",   type=str,   default="layer2_gnn/weights/rgcn_sentinel.pt")
    train(parser.parse_args())
