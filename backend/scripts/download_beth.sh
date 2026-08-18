#!/bin/bash
# scripts/download_beth.sh
# Processes local BETH dataset using HuggingFace datasets
set -e

DEST="data/beth_dataset.csv"
mkdir -p data

echo "[Setup] Processing BETH dataset..."

pip install datasets --quiet
python3 -c "
from datasets import load_dataset
import os

# Pointing to the specific file you identified
local_file = 'data/beth_dataset/labelled_training_data.csv'

if not os.path.exists(local_file):
    print(f'Error: Could not find {local_file}.')
    print('Please ensure you extracted the Kaggle files into backend/data/beth_dataset/')
    exit(1)

# Load the local CSV instead of the Hugging Face Hub
ds = load_dataset('csv', data_files={'train': local_file}, split='train')
ds.to_csv('$DEST')
print(f'BETH saved to $DEST ({len(ds)} rows)')
"

echo "[Setup] BETH dataset ready at $DEST"