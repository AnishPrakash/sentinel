# SENTINEL — AI-Powered Cyber Threat Intelligence

**PS28 | VITISH 2026 | Smart India Hackathon**

SENTINEL is a 5-layer AI middleware that sits between raw security logs
and a SOC analyst's response workflow, providing automated threat
correlation, LLM-generated attack narratives, and topology-validated
remediation playbooks.

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 20+ (frontend)
- 16 GB RAM (for Ollama LLM)

### Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

# One-time setup (run before demo day):
bash ../scripts/setup_ollama.sh
bash ../scripts/download_beth.sh
python ../scripts/seed_chromadb.py
python -m layer2_gnn.train --epochs 50
python ../scripts/generate_demo_cache.py

# Start API server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
