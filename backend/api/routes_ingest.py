# backend/api/routes_ingest.py
"""
POST /ingest/logs
Accepts raw log events → runs full 5-layer pipeline → stores alerts.
"""
import json
from datetime import datetime
from fastapi import APIRouter, HTTPException
from models.schemas import IngestRequest, Alert, AlertSeverity, MitreMatch, ValidationResult
from models.alert_store import alert_store

from layer1_ingestion.log_parser  import parse_beth_row
from layer1_ingestion.graph_builder import provenance_graph
from layer2_gnn.inference         import gnn_engine
from layer3_llm.rag_pipeline      import rag_engine
from layer4_symbolic.symbolic_validator import symbolic_validator
from layer5_risk.risk_scorer      import risk_scorer
from layer5_risk.playbook_engine  import playbook_engine
from config import GNN_ANOMALY_THRESHOLD, DEMO_MODE, DEMO_CACHE_DIR

router = APIRouter()


def _load_demo_cache(scenario_key: str) -> dict:
    import os
    path = os.path.join(DEMO_CACHE_DIR, f"{scenario_key}.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}


@router.post("/logs")
async def ingest_logs(request: IngestRequest):
    """
    Main ingestion endpoint. Runs all 5 pipeline layers for each event batch.
    Returns graph statistics and any newly triggered alerts.
    """
    alerts_triggered = 0
    new_alert_ids    = []

    # ── Layer 1: Add events to provenance graph ───────────────────────────────
    for log_event in request.logs:
        src_id, tgt_id = provenance_graph.add_event(log_event)

    # ── Layer 2: Run GNN inference on current graph ───────────────────────────
    nx_graph  = provenance_graph.get_networkx()
    node_meta = provenance_graph._node_meta

    anomalous_nodes = gnn_engine.get_anomalous_nodes(nx_graph, node_meta)

    for node_id, anomaly_score in anomalous_nodes:
        # Update node colour data in graph
        provenance_graph.set_anomaly_score(node_id, anomaly_score)

        host = node_meta.get(node_id, {}).get("host", "unknown")

        # ── Layer 3: Generate LLM narrative ──────────────────────────────────
        subgraph  = provenance_graph.subgraph_around(node_id, depth=2)
        topo_ctx  = symbolic_validator.get_topology_context()

        if DEMO_MODE:
            # Use cached narrative for speed
            narrative_json = _load_demo_cache("scenario_apt")
            if not narrative_json:
                narrative_json = rag_engine.generate_narrative(
                    subgraph, node_meta, host, anomaly_score, topo_ctx
                )
        else:
            narrative_json = rag_engine.generate_narrative(
                subgraph, node_meta, host, anomaly_score, topo_ctx
            )

        # ── Layer 4: Symbolic validation ─────────────────────────────────────
        user        = node_meta.get(node_id, {}).get("user", "SYSTEM")
        validation  = symbolic_validator.validate(narrative_json, user=user)

        if validation.status in ("PARTIAL", "INVALID") and not DEMO_MODE:
            # Re-prompt LLM with constraint
            narrative_json = rag_engine.generate_narrative(
                subgraph, node_meta, host, anomaly_score, topo_ctx,
                validation_issues=validation.issues
            )
            validation.reprompted = True
            # Re-validate after reprompt
            validation = symbolic_validator.validate(narrative_json, user=user)

        # ── Layer 5: Risk scoring ─────────────────────────────────────────────
        with open("data/topology.json") as f:
            topology = json.load(f)

        technique_ids = [
            t.get("technique_id", "")
            for t in narrative_json.get("matched_techniques", [])
        ]
        playbook_actions = playbook_engine.get_actions(technique_ids, 0.5)
        primary_action   = playbook_actions[0]["id"] if playbook_actions else "WATCHLIST"

        confidence  = narrative_json.get("confidence", anomaly_score)
        risk_score  = risk_scorer.compute(confidence, host, topology, primary_action)
        severity    = risk_scorer.severity_label(risk_score)

        # ── Build and store alert ─────────────────────────────────────────────
        alert = Alert(
            host             = host,
            risk_score       = risk_score,
            severity         = AlertSeverity(severity),
            anomaly_score    = anomaly_score,
            narrative        = narrative_json.get("narrative", ""),
            mitre_matches    = [
                MitreMatch(**t) for t in narrative_json.get("matched_techniques", [])
                if all(k in t for k in ("technique_id", "technique_name", "tactic", "confidence"))
            ],
            predicted_next   = narrative_json.get("predicted_next_stage", ""),
            validation       = validation,
            playbook_actions = [a["label"] for a in playbook_actions],
        )

        alert_store.add(alert)
        new_alert_ids.append(alert.alert_id)
        alerts_triggered += 1

    return {
        "status":           "ingested",
        "events_processed": len(request.logs),
        "graph_nodes":      provenance_graph.node_count(),
        "graph_edges":      provenance_graph.edge_count(),
        "alerts_triggered": alerts_triggered,
        "new_alert_ids":    new_alert_ids,
    }
