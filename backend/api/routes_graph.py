# backend/api/routes_graph.py
from fastapi import APIRouter
from layer1_ingestion.graph_builder import provenance_graph
from models.schemas import GraphSnapshot

router = APIRouter()


@router.get("/snapshot", response_model=GraphSnapshot)
async def graph_snapshot():
    """
    Returns the current provenance graph (nodes + edges) for frontend visualisation.
    Anomaly scores are included on each node so the UI can colour them.
    """
    return provenance_graph.get_snapshot()


@router.get("/stats")
async def graph_stats():
    return {
        "nodes": provenance_graph.node_count(),
        "edges": provenance_graph.edge_count(),
    }
