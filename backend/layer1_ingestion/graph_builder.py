# backend/layer1_ingestion/graph_builder.py
"""
Maintains a live in-memory provenance graph using NetworkX.
Nodes = OS objects (processes, files, sockets, registry keys).
Edges = system call interactions with typed labels.
"""
import networkx as nx
import threading
from typing import Dict, List, Tuple, Optional
from models.schemas import LogEvent, GraphNode, GraphEdge, GraphSnapshot, EdgeType


class ProvenanceGraph:
    """
    Thread-safe directed multigraph representing system call provenance.
    Each call to add_event() inserts/updates nodes and a typed edge.
    """

    def __init__(self):
        self._graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self._lock  = threading.Lock()
        self._node_meta: Dict[str, dict] = {}

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _proc_id(self, host: str, pid: int, name: str) -> str:
        return f"{host}::proc::{pid}::{name}"

    def _file_id(self, host: str, path: str) -> str:
        return f"{host}::file::{path}"

    def _socket_id(self, target: str) -> str:
        return f"socket::{target}"

    def _reg_id(self, host: str, key: str) -> str:
        return f"{host}::reg::{key}"

    def _ensure_node(self, node_id: str, label: str, node_type: str, host: str) -> None:
        if node_id not in self._graph:
            self._graph.add_node(node_id)
            self._node_meta[node_id] = {
                "label":        label,
                "node_type":    node_type,
                "host":         host,
                "anomaly_score": 0.0,
            }

    # ── Public API ────────────────────────────────────────────────────────────

    def add_event(self, event: LogEvent) -> Tuple[str, str]:
        """
        Ingest one LogEvent into the graph.
        Returns (source_node_id, target_node_id).
        """
        with self._lock:
            # Source is always the process
            src_id = self._proc_id(event.host, event.pid, event.process)
            self._ensure_node(src_id, event.process, "process", event.host)

            # Target depends on event type
            if event.event_type == EdgeType.SPAWN:
                tgt_id = self._proc_id(event.host, event.ppid, event.parent)
                self._ensure_node(tgt_id, event.parent, "process", event.host)
            elif event.event_type in (EdgeType.READ, EdgeType.WRITE, EdgeType.DELETE):
                tgt_id = self._file_id(event.host, event.target)
                self._ensure_node(tgt_id, event.target.split("/")[-1][:32], "file", event.host)
            elif event.event_type == EdgeType.CONNECT:
                tgt_id = self._socket_id(event.target)
                self._ensure_node(tgt_id, event.target, "socket", "network")
            elif event.event_type == EdgeType.MODIFY_REG:
                tgt_id = self._reg_id(event.host, event.target)
                self._ensure_node(tgt_id, event.target.split("\\")[-1][:32], "registry", event.host)
            else:
                tgt_id = self._file_id(event.host, event.target)
                self._ensure_node(tgt_id, event.target[:32], "file", event.host)

            self._graph.add_edge(
                src_id, tgt_id,
                edge_type  = event.event_type.value,
                timestamp  = event.timestamp,
                user       = event.user,
            )

            return src_id, tgt_id

    def set_anomaly_score(self, node_id: str, score: float) -> None:
        with self._lock:
            if node_id in self._node_meta:
                self._node_meta[node_id]["anomaly_score"] = score

    def get_snapshot(self) -> GraphSnapshot:
        """Return a serialisable snapshot of the current graph state."""
        with self._lock:
            nodes = [
                GraphNode(
                    id            = nid,
                    label         = meta["label"],
                    node_type     = meta["node_type"],
                    host          = meta["host"],
                    anomaly_score = meta["anomaly_score"],
                )
                for nid, meta in self._node_meta.items()
            ]

            edges = []
            for u, v, data in self._graph.edges(data=True):
                edges.append(GraphEdge(
                    source    = u,
                    target    = v,
                    edge_type = EdgeType(data["edge_type"]),
                    timestamp = data.get("timestamp", ""),
                ))

            return GraphSnapshot(nodes=nodes, edges=edges)

    def get_networkx(self) -> nx.MultiDiGraph:
        """Return raw NetworkX graph for GNN processing."""
        return self._graph

    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    def subgraph_around(self, node_id: str, depth: int = 2) -> nx.MultiDiGraph:
        """Extract ego subgraph for a suspicious node (fed to LLM)."""
        with self._lock:
            nodes = nx.single_source_shortest_path_length(
                self._graph, node_id, cutoff=depth
            ).keys()
            return self._graph.subgraph(nodes).copy()


# ── Global singleton ──────────────────────────────────────────────────────────
provenance_graph = ProvenanceGraph()
