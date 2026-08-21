# tests/test_layer3.py
"""
Unit tests for Layer 3 — RAG + LLM Narrative Engine
(backend/layer3_llm/{prompt_templates,mitre_loader,rag_pipeline}.py).

layer3_llm.rag_pipeline instantiates a module-level singleton
(`rag_engine = RAGNarrativeEngine()`) the moment it is imported, and that
constructor talks to ChromaDB and downloads a sentence-transformer
embedding model. To keep this suite fast, deterministic and runnable
without a live Ollama server / network access, we register lightweight
fakes for `chromadb` (and its embedding_functions submodule) in
sys.modules *before* layer3_llm is imported anywhere below. Only the
Ollama HTTP call itself is monkeypatched per-test, since that's the one
piece that must vary between test cases.
"""
import json
import sys
import types

import networkx as nx
import pytest


# ── Fakes for chromadb, installed before layer3_llm is ever imported ───────

class _FakeCollection:
    _CATALOGUE = [
        {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        {"technique_id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
        {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    ]

    def __init__(self):
        self.added_batches = []

    def count(self):
        return len(self._CATALOGUE)

    def query(self, query_texts, n_results):
        docs = self._CATALOGUE[:n_results]
        return {
            "ids": [[d["technique_id"] for d in docs]],
            "metadatas": [docs],
            "documents": [
                [f"Technique: {d['technique_id']} — {d['name']}\nTactic: {d['tactic']}\nDescription: ..."
                 for d in docs]
            ],
            "distances": [[round(0.1 * (i + 1), 2) for i in range(len(docs))]],
        }

    def add(self, ids, documents, metadatas):
        self.added_batches.append({"ids": ids, "documents": documents, "metadatas": metadatas})


class _FakeChromaClient:
    """Records every instance so tests can inspect what a call wrote."""
    instances = []

    def __init__(self, path=None):
        self._collection = _FakeCollection()
        _FakeChromaClient.instances.append(self)

    def get_or_create_collection(self, name, embedding_function=None):
        return self._collection

    def create_collection(self, name, embedding_function=None):
        return self._collection

    def delete_collection(self, name):
        pass


class _FakeEmbeddingFunction:
    def __init__(self, model_name=None):
        self.model_name = model_name

    def __call__(self, input):
        return [[0.0] * 8 for _ in input]


def _install_fake_chromadb():
    fake_ef_module = types.ModuleType("chromadb.utils.embedding_functions")
    fake_ef_module.SentenceTransformerEmbeddingFunction = _FakeEmbeddingFunction

    fake_utils_module = types.ModuleType("chromadb.utils")
    fake_utils_module.embedding_functions = fake_ef_module

    fake_chromadb_module = types.ModuleType("chromadb")
    fake_chromadb_module.PersistentClient = _FakeChromaClient
    fake_chromadb_module.utils = fake_utils_module

    sys.modules["chromadb"] = fake_chromadb_module
    sys.modules["chromadb.utils"] = fake_utils_module
    sys.modules["chromadb.utils.embedding_functions"] = fake_ef_module


_install_fake_chromadb()

from layer3_llm.prompt_templates import NARRATIVE_USER_TEMPLATE          # noqa: E402
from layer3_llm.rag_pipeline import RAGNarrativeEngine                    # noqa: E402
from layer3_llm.mitre_loader import load_mitre_to_chroma                  # noqa: E402


# ── Fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture
def engine():
    return RAGNarrativeEngine()


def _sample_subgraph():
    """A minimal winword -> cmd -> (payload.ps1, external C2 IP) chain."""
    g = nx.MultiDiGraph()
    node_meta = {
        "p1": {"node_type": "process", "label": "winword.exe", "user": "alice"},
        "p2": {"node_type": "process", "label": "cmd.exe", "user": "alice"},
        "f1": {"node_type": "file", "label": "payload.ps1", "user": "alice"},
        "s1": {"node_type": "socket", "label": "185.220.101.47", "user": "alice"},
    }
    for nid in node_meta:
        g.add_node(nid)
    g.add_edge("p1", "p2", edge_type="SPAWN")
    g.add_edge("p2", "f1", edge_type="WRITE")
    g.add_edge("p2", "s1", edge_type="CONNECT")
    return g, node_meta


# ── summarise_subgraph ──────────────────────────────────────────────────

def test_summarise_subgraph_extracts_processes_and_ips(engine):
    subgraph, node_meta = _sample_subgraph()
    summary = engine.summarise_subgraph(subgraph, node_meta, host="workstation-1", anomaly_score=0.87)

    assert summary["host"] == "workstation-1"
    assert summary["process"] == "winword.exe"
    assert summary["parent"] == "cmd.exe"
    assert "185.220.101.47" in summary["external_ips"]
    assert "payload.ps1" in summary["targets"]
    assert summary["anomaly_score"] == 0.87


def test_summarise_subgraph_excludes_private_ips(engine):
    subgraph, node_meta = _sample_subgraph()
    node_meta["s1"]["label"] = "192.168.1.50"   # private range
    summary = engine.summarise_subgraph(subgraph, node_meta, host="workstation-1", anomaly_score=0.5)
    assert summary["external_ips"] == "none"


# ── retrieval ────────────────────────────────────────────────────────────

def test_retrieve_techniques(engine):
    techniques = engine.retrieve_techniques("suspicious powershell exfiltration", k=3)
    assert len(techniques) == 3
    assert techniques[0]["technique_id"] == "T1059"
    assert techniques[0]["tactic"] == "Execution"
    assert "distance" in techniques[0]


# ── prompt formatting ───────────────────────────────────────────────────

def test_narrative_user_template_formats_cleanly():
    prompt = NARRATIVE_USER_TEMPLATE.format(
        host="workstation-1", process="winword.exe", pid=1234, parent="explorer.exe",
        edge_sequence="winword.exe -[SPAWN]-> cmd.exe", targets="payload.ps1",
        external_ips="185.220.101.47", users="alice", anomaly_score=0.87,
        k=5, mitre_context="[T1059] Command and Scripting Interpreter (Execution)",
        topology_context="workstation-1 -> [auth-server]",
    )
    assert "workstation-1" in prompt
    assert "T1059" in prompt
    assert "0.870" in prompt   # {anomaly_score:.3f}


# ── generate_narrative (Ollama call is faked; retrieval uses the fake store) ─

def test_generate_narrative_parses_valid_json(monkeypatch, engine):
    subgraph, node_meta = _sample_subgraph()
    canned = json.dumps({
        "narrative": "Word spawned cmd.exe which contacted a known C2 IP.",
        "matched_techniques": [
            {"technique_id": "T1566", "technique_name": "Phishing", "tactic": "Initial Access", "confidence": 0.9}
        ],
        "confidence": 0.9,
        "predicted_next_stage": "Lateral movement to auth-server.",
        "severity": "CRITICAL",
    })
    monkeypatch.setattr(engine, "_call_ollama", lambda messages: canned)

    result = engine.generate_narrative(subgraph, node_meta, host="workstation-1", anomaly_score=0.87)

    assert result["severity"] == "CRITICAL"
    assert result["matched_techniques"][0]["technique_id"] == "T1566"
    assert 0.0 <= result["confidence"] <= 1.0


def test_generate_narrative_falls_back_on_malformed_json(monkeypatch, engine):
    subgraph, node_meta = _sample_subgraph()
    monkeypatch.setattr(engine, "_call_ollama", lambda messages: "the model rambled instead of returning JSON")

    result = engine.generate_narrative(subgraph, node_meta, host="workstation-1", anomaly_score=0.5)

    assert result["severity"] == "MEDIUM"
    assert result["confidence"] == 0.5
    # Falls back to the top retrieved techniques when the LLM gives none.
    assert len(result["matched_techniques"]) > 0
    assert result["matched_techniques"][0]["technique_id"] == "T1059"


def test_generate_narrative_strips_markdown_fences(monkeypatch, engine):
    subgraph, node_meta = _sample_subgraph()
    fenced = "```json\n" + json.dumps({
        "narrative": "test", "matched_techniques": [], "confidence": 0.6,
        "predicted_next_stage": "unknown", "severity": "LOW",
    }) + "\n```"
    monkeypatch.setattr(engine, "_call_ollama", lambda messages: fenced)

    result = engine.generate_narrative(subgraph, node_meta, host="workstation-1", anomaly_score=0.2)
    assert result["severity"] == "LOW"


def test_generate_narrative_reprompt_included_on_validation_issues(monkeypatch, engine):
    subgraph, node_meta = _sample_subgraph()
    captured = {}

    def fake_call(messages):
        captured["messages"] = messages
        return json.dumps({
            "narrative": "corrected", "matched_techniques": [], "confidence": 0.7,
            "predicted_next_stage": "n/a", "severity": "HIGH",
        })

    monkeypatch.setattr(engine, "_call_ollama", fake_call)

    engine.generate_narrative(
        subgraph, node_meta, host="workstation-1", anomaly_score=0.9,
        validation_issues=["Topology violation: workstation-1 cannot reach db-server on port 1433."],
    )

    roles = [m["role"] for m in captured["messages"]]
    assert roles.count("user") >= 2   # original prompt + constraint re-prompt
    assert "Topology violation" in captured["messages"][-1]["content"]


# ── mitre_loader ─────────────────────────────────────────────────────────

def test_mitre_loader_filters_revoked_and_deprecated(tmp_path):
    raw = {
        "objects": [
            {
                "type": "attack-pattern",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
                "kill_chain_phases": [{"phase_name": "execution"}],
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command interpreters.",
            },
            {
                "type": "attack-pattern",
                "revoked": True,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1000"}],
                "name": "Revoked Technique",
            },
            {
                "type": "attack-pattern",
                "x_mitre_deprecated": True,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1001"}],
                "name": "Deprecated Technique",
            },
            {"type": "intrusion-set", "name": "Not a technique at all"},
        ]
    }
    json_path = tmp_path / "enterprise-attack.json"
    json_path.write_text(json.dumps(raw))

    load_mitre_to_chroma(json_path=str(json_path), db_path=str(tmp_path / "chroma"))

    client = _FakeChromaClient.instances[-1]
    added_ids = [i for batch in client._collection.added_batches for i in batch["ids"]]
    assert added_ids == ["T1059"]