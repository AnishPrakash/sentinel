# scripts/generate_demo_cache.py
"""
Run ONCE before hackathon. Pre-generates LLM narratives for each scenario
and caches them to disk. During demo, DEMO_MODE=true loads these instantly.
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from simulator.attack_scenarios import ALL_SCENARIOS
from layer1_ingestion.graph_builder import ProvenanceGraph
from layer1_ingestion.log_parser import parse_beth_row
from layer2_gnn.inference import GNNInferenceEngine
from layer3_llm.rag_pipeline import RAGNarrativeEngine
from layer4_symbolic.symbolic_validator import SymbolicValidator
from models.schemas import LogEvent
from config import DEMO_CACHE_DIR

os.makedirs(DEMO_CACHE_DIR, exist_ok=True)

rag    = RAGNarrativeEngine()
gnn    = GNNInferenceEngine()
sv     = SymbolicValidator()

for name, events in ALL_SCENARIOS.items():
    print(f"\n[Cache] Generating narrative for scenario: {name}")
    pg = ProvenanceGraph()
    for ev_dict in events:
        pg.add_event(LogEvent(**ev_dict))

    nx_graph  = pg.get_networkx()
    node_meta = pg._node_meta
    scores    = gnn.score_graph(nx_graph, node_meta)

    if not scores:
        continue

    top_node = max(scores, key=scores.get)
    top_score = scores[top_node]
    host = node_meta.get(top_node, {}).get("host", "unknown")
    subgraph = pg.subgraph_around(top_node)
    topo_ctx = sv.get_topology_context()

    narrative = rag.generate_narrative(subgraph, node_meta, host, top_score, topo_ctx)

    cache_path = os.path.join(DEMO_CACHE_DIR, f"scenario_{name}.json")
    with open(cache_path, "w") as f:
        json.dump(narrative, f, indent=2)
    print(f"[Cache] Saved → {cache_path}")

print("\n[Cache] All demo narratives cached. Set DEMO_MODE=true in .env before demo day.")
