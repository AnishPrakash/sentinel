#!/bin/bash
# scripts/setup_ollama.sh
# Downloads and sets up Ollama with Llama 3.1 8B
set -e

echo "[Setup] Installing Ollama..."
curl -fsSL https://ollama.com/install.sh | sh

echo "[Setup] Pulling Llama 3.1 8B (may take 10-20 mins on first run)..."
ollama pull llama3.1:8b

echo "[Setup] Starting Ollama server..."
ollama serve &

echo "[Setup] Ollama ready at http://localhost:11434"
