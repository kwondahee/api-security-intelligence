#!/bin/bash
# run_intelligence.sh — venv, dependencies, KB init (Qdrant), orchestrator

set -e  # exit on error

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "====================================================="
echo "[INTELLIGENCE] Starting Intelligence Boot Script"
echo "Directory: $SCRIPT_DIR"
echo "====================================================="

# ---------------------------------------------------------
# [1] Create venv if missing
# ---------------------------------------------------------
if [ ! -d "venv" ]; then
  echo "[INIT] Creating virtual environment..."
  python3 -m venv venv || { echo "[ERROR] Failed to create venv"; exit 1; }
else
  echo "[INIT] Virtual environment already exists ✔"
fi

# ---------------------------------------------------------
# [2] Activate venv
# ---------------------------------------------------------
echo "[INIT] Activating venv..."
source venv/bin/activate || { echo "[ERROR] Failed to activate venv"; exit 1; }

# # ---------------------------------------------------------
# # [3] Install dependencies
# # ---------------------------------------------------------
# if [ -f "requirements.txt" ]; then
#   echo "[INIT] Installing Python dependencies..."
#   pip install --upgrade pip
#   pip install -r requirements.txt || {
#     echo "[ERROR] Failed to install dependencies"; exit 1;
#   }
# else
#   echo "[WARN] requirements.txt not found — skipping install."
# fi

# ---------------------------------------------------------
# [4] Ensure Qdrant is running
# ---------------------------------------------------------
echo "[CHECK] Checking if Qdrant is reachable at http://localhost:6333 ..."
if curl -s http://localhost:6333/health | grep -q '"status":"ok"'; then
  echo "[CHECK] Qdrant is running ✔"
else
  echo "[ERROR] Qdrant is NOT running!"
  echo "Start it manually:"
  echo "    docker run -p 6333:6333 -p 6334:6334 qdrant/qdrant"
  exit 1
fi

# ---------------------------------------------------------
# [5] Initialize Knowledge Base (only once)
# ---------------------------------------------------------
if [ ! -f "kb_initialized.flag" ]; then
  echo "[INIT] First-time KB setup — initializing..."
  python3 initialize_kb.py && touch kb_initialized.flag
  echo "[INIT] KB initialized successfully ✔"
else
  echo "[INIT] KB already initialized — skipping ✔"
fi

# ---------------------------------------------------------
# [6] Start Intelligence Orchestrator
# ---------------------------------------------------------
echo "[RUN] Launching Intelligence Orchestrator..."
exec python3 orchestrator.py
