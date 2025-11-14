#!/bin/bash
# run_qdrant.sh — starts Qdrant (no AVX required)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "====================================================="
echo "[QDRANT] Starting Qdrant Vector DB"
echo "Directory: $SCRIPT_DIR"
echo "====================================================="

# --- Ensure Docker is running ---
if ! systemctl is-active --quiet docker; then
  echo "[QDRANT] Docker not running — starting..."
  systemctl start docker
fi

echo "[QDRANT] Docker is running ✔"

# --- Start Qdrant ---
docker compose up -d

echo "[QDRANT] Waiting for Qdrant to be healthy..."

for i in {1..20}; do
  if curl -s http://localhost:6333/healthz | grep -q "OK"; then
    echo "[QDRANT] Qdrant is healthy ✔"
    exit 0
  fi
  echo "[QDRANT] Not ready ($i/20), retrying..."
  sleep 2
done

echo "[ERROR] Qdrant did not become healthy in time."
exit 1
