# backend/layer3_llm/mitre_loader.py
"""
Loads the MITRE ATT&CK Enterprise JSON into ChromaDB for semantic retrieval.
Run once: python -m layer3_llm.mitre_loader

Download ATT&CK JSON from:
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
"""
import json
import os
import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
from config import CHROMA_DB_PATH, MITRE_JSON_PATH


def load_mitre_to_chroma(json_path: str = MITRE_JSON_PATH, db_path: str = CHROMA_DB_PATH):
    """
    Parse ATT&CK JSON, extract technique objects, embed and store in ChromaDB.
    """
    print(f"[MITRE] Loading ATT&CK JSON from {json_path}...")
    with open(json_path) as f:
        raw = json.load(f)

    techniques = []
    for obj in raw.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        # Extract technique ID (e.g., T1059)
        ext_refs = obj.get("external_references", [])
        tech_id  = next(
            (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"), None
        )
        if not tech_id:
            continue

        # Extract tactic
        kill_chain = obj.get("kill_chain_phases", [])
        tactic = kill_chain[0]["phase_name"].replace("-", " ").title() if kill_chain else "Unknown"

        desc    = obj.get("description", "")[:1000]   # truncate for embedding
        name    = obj.get("name", "Unknown")
        full_text = f"Technique: {tech_id} — {name}\nTactic: {tactic}\nDescription: {desc}"

        techniques.append({
            "id":       tech_id,
            "document": full_text,
            "metadata": {
                "technique_id": tech_id,
                "name":         name,
                "tactic":       tactic,
            }
        })

    print(f"[MITRE] Parsed {len(techniques)} active techniques.")

    ef = SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
    client = chromadb.PersistentClient(path=db_path)

    try:
        client.delete_collection("mitre_attack")
    except Exception:
        pass

    collection = client.create_collection("mitre_attack", embedding_function=ef)

    # ChromaDB batch upsert (max 5000 per call)
    batch_size = 500
    for i in range(0, len(techniques), batch_size):
        batch = techniques[i : i + batch_size]
        collection.add(
            ids       = [t["id"] for t in batch],
            documents = [t["document"] for t in batch],
            metadatas = [t["metadata"] for t in batch],
        )
        print(f"[MITRE] Stored batch {i//batch_size + 1} / {len(techniques)//batch_size + 1}")

    print(f"[MITRE] ChromaDB populated at {db_path}")


if __name__ == "__main__":
    load_mitre_to_chroma()
