# scripts/seed_chromadb.py
"""
One-time setup script. Run before hackathon day.
  python scripts/seed_chromadb.py
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from layer3_llm.mitre_loader import load_mitre_to_chroma
load_mitre_to_chroma()
