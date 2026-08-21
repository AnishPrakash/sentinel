# backend/scripts/seed_chromadb.py
import json
import os
import chromadb
from sentence_transformers import SentenceTransformer

CHROMA_PATH = os.getenv("CHROMA_PATH", "./chroma_db")
MITRE_JSON  = os.getenv("MITRE_JSON",  "./data/enterprise-attack.json")

def seed():
    print("[Seed] Loading MITRE ATT&CK JSON...")
    with open(MITRE_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)

    techniques = [
        obj for obj in data.get("objects", [])
        if obj.get("type") == "attack-pattern" and not obj.get("revoked", False)
    ]
    print(f"[Seed] Found {len(techniques)} techniques.")

    client = chromadb.HttpClient(host="chromadb", port=8000) \
        if CHROMA_PATH.startswith("http") \
        else chromadb.PersistentClient(path=CHROMA_PATH)

    collection = client.get_or_create_collection("mitre_attack")

    model = SentenceTransformer("all-MiniLM-L6-v2")

    ids, docs, embeddings, metadatas = [], [], [], []

    for t in techniques:
        tid  = t.get("external_references", [{}])[0].get("external_id", t["id"])
        name = t.get("name", "")
        desc = t.get("description", "")
        text = f"{name}: {desc}"

        ids.append(tid)
        docs.append(text)
        embeddings.append(model.encode(text).tolist())
        metadatas.append({"name": name, "technique_id": tid})

    # Upsert in batches of 100
    batch = 100
    for i in range(0, len(ids), batch):
        collection.upsert(
            ids=ids[i:i+batch],
            documents=docs[i:i+batch],
            embeddings=embeddings[i:i+batch],
            metadatas=metadatas[i:i+batch],
        )
        print(f"[Seed] Upserted {min(i+batch, len(ids))}/{len(ids)}")

    print("[Seed] ChromaDB seeding complete.")

if __name__ == "__main__":
    seed()