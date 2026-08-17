# backend/layer3_llm/rag_pipeline.py
"""
RAG pipeline:
  1. Convert anomalous subgraph into a structured text query
  2. Retrieve top-k MITRE ATT&CK techniques from ChromaDB
  3. Generate narrative via Ollama (local LLM)
  4. Parse and return structured JSON
"""
import json
import re
import requests
import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
import networkx as nx
from typing import List, Dict, Any, Optional

from config import (
    CHROMA_DB_PATH, OLLAMA_BASE_URL, OLLAMA_MODEL,
    TOP_K_RETRIEVAL, DEMO_MODE, DEMO_CACHE_DIR
)
from layer3_llm.prompt_templates import (
    NARRATIVE_SYSTEM_PROMPT,
    NARRATIVE_USER_TEMPLATE,
    REPROMPT_CONSTRAINT_TEMPLATE,
)


class RAGNarrativeEngine:

    def __init__(self):
        self.ef         = SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
        self.client     = chromadb.PersistentClient(path=CHROMA_DB_PATH)
        self.collection = self.client.get_or_create_collection("mitre_attack", embedding_function=self.ef)
        print(f"[RAG] ChromaDB loaded. Techniques in store: {self.collection.count()}")

    # ── Retrieval ─────────────────────────────────────────────────────────────

    def retrieve_techniques(self, query: str, k: int = TOP_K_RETRIEVAL) -> List[Dict]:
        results = self.collection.query(
            query_texts=[query],
            n_results=min(k, self.collection.count()),
        )
        techniques = []
        for i in range(len(results["ids"][0])):
            techniques.append({
                "technique_id":   results["metadatas"][0][i]["technique_id"],
                "technique_name": results["metadatas"][0][i]["name"],
                "tactic":         results["metadatas"][0][i]["tactic"],
                "document":       results["documents"][0][i],
                "distance":       results["distances"][0][i] if results.get("distances") else 0.5,
            })
        return techniques

    # ── Subgraph summarisation ────────────────────────────────────────────────

    def summarise_subgraph(
        self,
        subgraph: nx.MultiDiGraph,
        node_meta: dict,
        host: str,
        anomaly_score: float,
    ) -> dict:
        """
        Convert a NetworkX subgraph into a structured dict for prompt injection.
        """
        processes, files, sockets, reg_keys, users = [], [], [], [], []
        edges_desc = []

        for nid, meta in node_meta.items():
            if nid not in subgraph:
                continue
            nt = meta.get("node_type", "")
            label = meta.get("label", nid)
            if nt == "process":  processes.append(label)
            elif nt == "file":   files.append(label)
            elif nt == "socket": sockets.append(label)
            elif nt == "registry": reg_keys.append(label)

            user = meta.get("user", "")
            if user and user not in users:
                users.append(user)

        for u, v, data in subgraph.edges(data=True):
            u_label = node_meta.get(u, {}).get("label", u[:20])
            v_label = node_meta.get(v, {}).get("label", v[:20])
            etype   = data.get("edge_type", "?")
            edges_desc.append(f"{u_label} –[{etype}]→ {v_label}")

        external_ips = [s for s in sockets if not s.startswith("192.168.") and
                        not s.startswith("10.") and not s.startswith("172.")]

        return {
            "host":          host,
            "process":       processes[0] if processes else "unknown",
            "pid":           0,
            "parent":        processes[1] if len(processes) > 1 else "unknown",
            "edge_sequence": "; ".join(edges_desc[:10]),
            "targets":       ", ".join(files[:5] + reg_keys[:3]),
            "external_ips":  ", ".join(external_ips[:5]) or "none",
            "users":         ", ".join(users[:3]) or "SYSTEM",
            "anomaly_score": anomaly_score,
        }

    # ── LLM call ──────────────────────────────────────────────────────────────

    def _call_ollama(self, messages: List[Dict]) -> str:
        payload = {
            "model": OLLAMA_MODEL,
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0.2, "num_predict": 512},
        }
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json=payload,
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]

    # ── Main pipeline ─────────────────────────────────────────────────────────

    def generate_narrative(
        self,
        subgraph: nx.MultiDiGraph,
        node_meta: dict,
        host: str,
        anomaly_score: float,
        topology_context: str = "No topology constraints loaded.",
        validation_issues: Optional[List[str]] = None,
    ) -> dict:
        """
        Full RAG generation pipeline.
        Returns parsed dict with narrative, techniques, confidence, etc.
        """
        summary    = self.summarise_subgraph(subgraph, node_meta, host, anomaly_score)
        query      = f"{summary['process']} {summary['edge_sequence']} {summary['external_ips']}"
        techniques = self.retrieve_techniques(query)

        mitre_ctx = "\n\n".join(
            f"[{t['technique_id']}] {t['technique_name']} ({t['tactic']})\n{t['document'][:300]}"
            for t in techniques
        )

        user_msg = NARRATIVE_USER_TEMPLATE.format(
            host            = summary["host"],
            process         = summary["process"],
            pid             = summary["pid"],
            parent          = summary["parent"],
            edge_sequence   = summary["edge_sequence"],
            targets         = summary["targets"],
            external_ips    = summary["external_ips"],
            users           = summary["users"],
            anomaly_score   = summary["anomaly_score"],
            k               = TOP_K_RETRIEVAL,
            mitre_context   = mitre_ctx,
            topology_context= topology_context,
        )

        messages = [
            {"role": "system", "content": NARRATIVE_SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ]

        # Re-prompt with constraint if validator found issues
        if validation_issues:
            constraint_msg = REPROMPT_CONSTRAINT_TEMPLATE.format(
                issues="\n".join(f"- {i}" for i in validation_issues)
            )
            messages.append({"role": "user", "content": constraint_msg})

        raw_output = self._call_ollama(messages)

        # ── Parse JSON from LLM output ─────────────────────────────────────
        try:
            # Strip any markdown code fences
            clean = re.sub(r"```(?:json)?|```", "", raw_output).strip()
            result = json.loads(clean)
        except json.JSONDecodeError:
            result = {
                "narrative":          raw_output[:500],
                "matched_techniques": [],
                "confidence":         0.5,
                "predicted_next_stage": "Unknown",
                "severity":           "MEDIUM",
            }

        # Attach retrieved techniques if LLM didn't fill them
        if not result.get("matched_techniques"):
            result["matched_techniques"] = [
                {
                    "technique_id":   t["technique_id"],
                    "technique_name": t["technique_name"],
                    "tactic":         t["tactic"],
                    "confidence":     round(1.0 - t.get("distance", 0.5), 2),
                }
                for t in techniques[:3]
            ]

        return result


# ── Global singleton ──────────────────────────────────────────────────────────
rag_engine = RAGNarrativeEngine()
