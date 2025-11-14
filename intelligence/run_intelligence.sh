#!/bin/bash
# run_intelligence.sh — handles venv, dependencies, KB init, and orchestrator

set -e  # stop script if any command fails

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "====================================================="
echo "[INTELLIGENCE] Starting Intelligence Boot Script"
echo "Directory: $SCRIPT_DIR"
echo "====================================================="

# --- [1] Create venv if missing ---
if [ ! -d "venv" ]; then
  echo "[INIT] Creating virtual environment..."
  python3 -m venv venv || { echo "[ERROR] Failed to create venv"; exit 1; }
else
  echo "[INIT] Virtual environment already exists ✔"
fi

# --- [2] Activate venv ---
echo "[INIT] Activating venv..."
source venv/bin/activate || { echo "[ERROR] Failed to activate venv"; exit 1; }

# --- [3] Install dependencies ---
if [ -f "requirements.txt" ]; then
  echo "[INIT] Installing dependencies..."
  pip install --upgrade pip
  pip install -r requirements.txt || { echo "[ERROR] Requirements installation failed"; exit 1; }
else
  echo "[WARN] requirements.txt not found — skipping install."
fi

# --- [4] Initialize Milvus KB once ---
if [ ! -f "kb_initialized.flag" ]; then
  echo "[INIT] Running knowledge base initialization..."
  python3 initialize_kb.py && touch kb_initialized.flag
  echo "[INIT] KB initialized successfully ✔"
else
  echo "[INIT] KB already initialized — skipping ✔"
fi

# # --- [5] Start orchestrator ---
# echo "[RUN] Launching Aether Intelligence Orchestrator..."
# exec python3 orchestrator.py
