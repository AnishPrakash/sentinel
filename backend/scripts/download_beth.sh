#!/bin/bash
# scripts/download_beth.sh
# Downloads BETH dataset from HuggingFace or Kaggle
set -e

DEST="backend/data/beth_dataset.csv"
mkdir -p backend/data

echo "[Setup] Downloading BETH dataset..."
# Option A: HuggingFace datasets CLI
pip install datasets --quiet
python3 -c "
from datasets import load_dataset
ds = load_dataset('markusbayer/BETH', split='train')
ds.to_csv('$DEST')
print(f'BETH saved to $DEST ({len(ds)} rows)')
"

echo "[Setup] BETH dataset ready at $DEST"
