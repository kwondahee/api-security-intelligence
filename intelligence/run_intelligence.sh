#!/bin/bash
# run_intelligence.sh — handles venv, dependencies, and launches orchestrator

set -e  # exit on any error

cd "$(dirname "$0")"  # go to intelligence directory

# --- [1] Create venv if not exists ---
if [ ! -d "venv" ]; then
  echo "[INIT] Creating virtual environment..."
  python3 -m venv venv
fi

# --- [2] Activate venv ---
source venv/bin/activate

# --- [3] Ensure dependencies are installed ---
echo "[INIT] Installing/updating dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# --- [4] Initialize Milvus KB if needed ---
if [ ! -f "kb_initialized.flag" ]; then
  echo "[INIT] Initializing knowledge base..."
  python3 initialize_kb.py
  touch kb_initialized.flag
fi

# --- [5] Start the orchestrator ---
echo "[RUN] Starting Aether Intelligence Orchestrator..."
exec python3 orchestrator.py
