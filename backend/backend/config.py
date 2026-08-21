# backend/config.py
import os
from dotenv import load_dotenv

load_dotenv()

# ─── Risk Score Weights ───────────────────────────────────────────────────────
ALPHA = float(os.getenv("ALPHA", 0.4))   # Confidence score weight
BETA  = float(os.getenv("BETA",  0.3))   # Asset criticality weight
GAMMA = float(os.getenv("GAMMA", 0.2))   # Blast radius weight
DELTA = float(os.getenv("DELTA", 0.1))   # Disruption cost weight

# ─── GNN Settings ─────────────────────────────────────────────────────────────
GNN_ANOMALY_THRESHOLD = float(os.getenv("GNN_THRESHOLD", 0.65))
MODEL_WEIGHTS_PATH    = os.getenv("MODEL_WEIGHTS", "layer2_gnn/weights/rgcn_sentinel.pt")

# ─── LLM Settings ─────────────────────────────────────────────────────────────
OLLAMA_BASE_URL  = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL     = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
CHROMA_DB_PATH   = os.getenv("CHROMA_PATH", "./chroma_db")
MITRE_JSON_PATH  = os.getenv("MITRE_JSON", "./data/enterprise-attack.json")
TOP_K_RETRIEVAL  = int(os.getenv("TOP_K", 5))

# ─── Demo Mode ────────────────────────────────────────────────────────────────
DEMO_MODE        = os.getenv("DEMO_MODE", "true").lower() == "true"
DEMO_CACHE_DIR   = os.getenv("DEMO_CACHE", "./data/demo_cache")

# ─── Network Topology ─────────────────────────────────────────────────────────
TOPOLOGY_JSON    = os.getenv("TOPOLOGY_JSON", "./data/topology.json")
ASSET_JSON       = os.getenv("ASSET_JSON",    "./data/asset_criticality.json")
PLAYBOOK_DIR     = os.getenv("PLAYBOOK_DIR",  "./data/playbooks")
